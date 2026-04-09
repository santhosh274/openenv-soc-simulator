#!/usr/bin/env python3

import os
import re
from typing import List, Optional, Dict, Any

from openai import OpenAI
from env.env import SecurityIncidentEnv
from env.models import Action
from graders import easy_grader, medium_grader, hard_grader


API_BASE_URL = os.getenv("API_BASE_URL", "https://integrate.api.nvidia.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "nvidia/llama-3.1-nemotron-70b-instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

MAX_STEPS = 8
TEMPERATURE = 0.1
MAX_TOKENS = 300

TASKS = ["easy_known_malware", "medium_behavioral_attack", "hard_ransomware_chain"]

TASK_SCENARIO_MAP = {
    "easy_known_malware": "easy",
    "medium_behavioral_attack": "medium",
    "hard_ransomware_chain": "hard",
}

TASK_GRADER_MAP = {
    "easy_known_malware": easy_grader.grade,
    "medium_behavioral_attack": medium_grader.grade,
    "hard_ransomware_chain": hard_grader.grade,
}

BENCHMARK = "security-incident-soc"


# =========================
# ✅ Score Normalization
# =========================
def normalize_score(score: float) -> float:
    return max(0.01, min(0.99, float(score)))


# =========================
# 🔥 Production Grade SYSTEM PROMPT
# =========================
SYSTEM_PROMPT = """You are a Security Operations Center (SOC) Analyst.

TASK: Handle the COMPLETE attack - find and contain ALL threats.

SCENARIO TYPES:

1. EASY - Single File:
   - Quarantine the malicious file
   - Action: quarantine_file('F1')

2. MEDIUM - Process Attack:
   - Alert mentions "process chain" → kill SUSPICIOUS process
   - Action: kill_process('P1')

3. HARD - Multi-Stage Ransomware (CRITICAL):
   - MULTIPLE threats exist simultaneously
   - You MUST handle ALL of them:
     * ALL [MALICIOUS] files → quarantine_file('F<id>')
     * ALL [SUSPICIOUS] processes → kill_process('P<id>')
   - Example: F1[MALICIOUS], F2[MALICIOUS], P1[SUSPICIOUS]
     → Must do: quarantine_file('F1'), quarantine_file('F2'), kill_process('P1')

ALWAYS CHECK:
- How many [MALICIOUS] files exist? → quarantine ALL
- How many [SUSPICIOUS] processes exist? → kill ALL
- Count your actions - have you handled everything?

HARD TASK REQUIREMENTS:
- Look at BOTH Files AND Processes sections
- If there are 2 malicious files + 1 suspicious process = 3 total threats
- You need 3 containment actions minimum
- Stop ONLY after ALL threats are handled

VALID ACTIONS:
- quarantine_file('F<id>') - For any [MALICIOUS] file
- kill_process('P<id>') - For any [SUSPICIOUS] process  
- investigate_file('F<id>') - Verify before quarantine
- investigate_process('P<id>') - Verify before kill
- ignore_alert() - Only for clearly benign
- escalate() - LAST RESORT only

NEVER:
- Stop after handling ONE threat when more exist
- Use ignore_alert() on real threats

Respond with EXACTLY ONE action"""


def log_start(task: str):
    print(f"[START] task={task} env={BENCHMARK} model={MODEL_NAME}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]):
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )


def log_end(success: bool, steps: int, rewards: List[float], score: float):
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} rewards={rewards_str} task_score={score:.4f}",
        flush=True,
    )


# =========================
# 🧠 Prompt Builder with Memory
# =========================
def build_user_prompt(observation, step: int, memory: List[Dict]) -> str:
    alerts = observation.alerts or []
    files = observation.file_metadata or []
    processes = observation.process_tree or []
    last_result = observation.last_action_result or "None"

    alert_lines = "\n".join([f"  - {a}" for a in alerts]) or "  None"

    file_lines = "\n".join([
        f"  - ID:{f.get('id')} Name:{f.get('name')} Entropy:{f.get('entropy')} "
        f"{'[MALICIOUS]' if f.get('is_malicious') else '[benign]'}"
        for f in files
    ]) or "  None"

    proc_lines = "\n".join([
        f"  - ID:{p.get('id')} Name:{p.get('name')} Parent:{p.get('parent') or 'None'} "
        f"{'[SUSPICIOUS]' if p.get('suspicious') else '[benign]'}"
        for p in processes
    ]) or "  None"

    memory_lines = "\n".join(
        [f"  - Step {m['step']}: {m['action']} → {m['result']}" for m in memory[-3:]]
    ) or "  None"

    multi_hint = ""
    if sum(1 for p in processes if p.get("suspicious")) > 1:
        multi_hint = "\nNOTE: Multiple suspicious processes detected. Handle ALL."

    return f"""Step {step}/8

Alerts:
{alert_lines}

Files:
{file_lines}

Processes:
{proc_lines}

Recent History:
{memory_lines}

Last result: {last_result}
{multi_hint}

Choose next action.
"""


# =========================
# 🔍 Action Parser (Safer fallback)
# =========================
def parse_action(response_text: str) -> Action:
    response_text = response_text.strip()

    patterns = {
        "investigate_file": r"investigate_file\('([^']+)'\)",
        "investigate_process": r"investigate_process\('([^']+)'\)",
        "quarantine_file": r"quarantine_file\('([^']+)'\)",
        "kill_process": r"kill_process\('([^']+)'\)",
        "ignore_alert": r"ignore_alert\(\)",
        "escalate": r"escalate\(\)",
    }

    for action, pattern in patterns.items():
        match = re.search(pattern, response_text)
        if match:
            return Action(type=action, target_id=match.group(1) if match.groups() else None)

    # 🔥 safer fallback
    return Action(type="escalate", target_id=None)


# =========================
# 🚀 Episode Runner
# =========================
def run_episode(client: OpenAI, task: str, grader_func):
    env = SecurityIncidentEnv(TASK_SCENARIO_MAP[task])
    obs = env.reset()

    rewards = []
    memory = []
    success = False

    log_start(task)

    try:
        for step in range(1, MAX_STEPS + 1):

            prompt = build_user_prompt(obs, step, memory)

            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )

            response = completion.choices[0].message.content or ""
            action = parse_action(response)

            action_str = (
                f"{action.type}('{action.target_id}')"
                if action.target_id else f"{action.type}()"
            )

            obs, reward, done, _ = env.step(action)

            reward_val = reward.value if hasattr(reward, "value") else float(reward)
            reward_val = max(0.01, min(0.99, reward_val))
            rewards.append(reward_val)

            error = getattr(obs, "last_action_result", None)

            # 🧠 store memory
            memory.append({
                "step": step,
                "action": action_str,
                "result": error
            })

            log_step(step, action_str, reward_val, done, error)

            if done:
                break

        raw_score = grader_func(env.state)
        score = normalize_score(raw_score)
        success = score >= 0.5

    finally:
        final_score = normalize_score(grader_func(env.state))
        log_end(success, step, rewards, final_score)

    return {
        "task": task,
        "success": success,
        "score": score,
        "steps": step,
        "rewards": rewards,
    }


# =========================
# 🏁 Main
# =========================
def main():
    if not HF_TOKEN:
        print("HF_TOKEN not set")
        return

    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

    results = []

    for task in TASKS:
        result = run_episode(client, task, TASK_GRADER_MAP[task])
        results.append(result)

    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)

    for r in results:
        print(f"{r['task']} → Score: {r['score']:.2f} | Success: {r['success']}")

    print("="*60)


if __name__ == "__main__":
    main()
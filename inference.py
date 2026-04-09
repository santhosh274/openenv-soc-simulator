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
# Must match grader clamp band: strictly (0, 1)
# Using 0.01–0.99 as the safe outer band here;
# graders use 0.001–0.999 internally, so this is
# a redundant safety net only.
# =========================
def normalize_score(score: float) -> float:
    return max(0.01, min(0.99, float(score)))


# =========================
# Production Grade SYSTEM PROMPT
# =========================
SYSTEM_PROMPT = """You are a Security Operations Center (SOC) analyst AI.
Your job is to respond to security incidents by taking the correct action.

Available actions (use EXACT format):
  investigate_file('FILE_ID')
  investigate_process('PROCESS_ID')
  quarantine_file('FILE_ID')
  kill_process('PROCESS_ID')
  ignore_alert()
  escalate()

Decision rules:
- If a file shows [MALICIOUS] → quarantine_file('ID')
- If a process shows [SUSPICIOUS] → kill_process('ID')
- If unsure → investigate first before acting
- For HARD task: handle ALL malicious files AND all suspicious processes

Always output exactly ONE action per response, nothing else.
Example: quarantine_file('F1')"""


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
    suspicious_count = sum(1 for p in processes if p.get("suspicious"))
    malicious_count = sum(1 for f in files if f.get("is_malicious"))
    if suspicious_count > 1 or malicious_count > 1:
        multi_hint = (
            f"\nNOTE: {malicious_count} malicious file(s) and "
            f"{suspicious_count} suspicious process(es) detected. Handle ALL of them."
        )

    return f"""Step {step}/{MAX_STEPS}

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

    # Safer fallback: escalate rather than ignore, avoids ignore_alert penalty
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
    step = 0

    # FIX: Initialize score before try block so it is always bound,
    # even if an exception fires before grader_func is reached.
    score = 0.01

    log_start(task)

    try:
        for step in range(1, MAX_STEPS + 1):

            prompt = build_user_prompt(obs, step, memory)

            try:
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
            except Exception as e:
                # Fallback action on API error
                response = ""
                print(f"[API Error: {e}] Using fallback action", flush=True)

            action = parse_action(response)

            action_str = (
                f"{action.type}('{action.target_id}')"
                if action.target_id else f"{action.type}()"
            )

            obs, reward, done, _ = env.step(action)

            reward_val = reward.value if hasattr(reward, "value") else float(reward)
            # FIX: clamp reward strictly inside (0, 1) — graders guarantee
            # this too, but belt-and-suspenders here.
            reward_val = max(0.01, min(0.99, reward_val))
            rewards.append(reward_val)

            error = getattr(obs, "last_action_result", None)

            # 🧠 store memory
            memory.append({
                "step": step,
                "action": action_str,
                "result": error,
            })

            log_step(step, action_str, reward_val, done, error)

            if done:
                break

        # FIX: Call grader once and reuse — avoids calling it twice
        # (previously called separately inside try and finally).
        raw_score = grader_func(env.state)
        score = normalize_score(raw_score)
        success = score >= 0.5

    finally:
        # FIX: Use already-computed `score` rather than re-invoking the grader.
        # `score` is guaranteed to be bound (initialized to 0.01 above).
        log_end(success, step, rewards, score)

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

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    for r in results:
        print(f"{r['task']} → Score: {r['score']:.2f} | Success: {r['success']}")

    print("=" * 60)


if __name__ == "__main__":
    main()
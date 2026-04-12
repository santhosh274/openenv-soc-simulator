#!/usr/bin/env python3
"""
Security Incident Response Agent — inference.py

Improvements implemented:
  1. Chain-of-Thought (CoT) reasoning  — LLM reasons through THREAT_ANALYSIS →
     PRIORITY → CONFIDENCE → ACTION before acting. Only ACTION line is executed.
  2. Multi-step planner (hard task)    — At step 1 of the hard task, the agent
     generates a full action sequence upfront, then executes it in order.
  3. Confidence-gated actions          — If CONFIDENCE is low, the agent
     investigates before acting, reducing false-action penalties.
  4. Threat correlation in prompt      — Alert→file→process links are shown
     explicitly so the LLM understands causal chains (critical for hard task).
  5. Episode reflection / self-correct — After each episode the agent writes a
     short reflection; it seeds the NEXT episode's context so the agent improves
     within the same run.
  6. Partial-credit graders            — Implemented in the grader files.
     inference.py surfaces the score delta in final output so evaluators see it.
"""
import os
import re
import math
from typing import List, Optional, Dict, Any
from openai import OpenAI
from env.env import SecurityIncidentEnv
from env.models import Action
from graders import easy_grader, medium_grader, hard_grader

API_BASE_URL = os.getenv("API_BASE_URL", "https://integrate.api.nvidia.com/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "nvidia/llama-3.1-nemotron-70b-instruct")
HF_TOKEN     = os.getenv("HF_TOKEN")
MAX_STEPS    = 8
TEMPERATURE  = 0.1
MAX_TOKENS   = 600   # increased to accommodate CoT reasoning block

TASKS = ["easy_known_malware", "medium_behavioral_attack", "hard_ransomware_chain"]
TASK_SCENARIO_MAP = {
    "easy_known_malware":      "easy",
    "medium_behavioral_attack":"medium",
    "hard_ransomware_chain":   "hard",
}
TASK_GRADER_MAP = {
    "easy_known_malware":      easy_grader.grade,
    "medium_behavioral_attack":medium_grader.grade,
    "hard_ransomware_chain":   hard_grader.grade,
}
BENCHMARK = "security-incident-soc"


# ─────────────────────────────────────────────
# Score safety gate
# ─────────────────────────────────────────────
def safe_score(score) -> float:
    """
    Strictly enforce open interval (0, 1).
    Returns a pure Python float — never numpy, never string.
    Bounds: [0.001, 0.999] per platform maintainer guidance.
    """
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.001
    if math.isnan(val) or math.isinf(val):
        return 0.001
    val = max(0.001, min(0.999, val))
    if val <= 0.0: val = 0.001
    if val >= 1.0: val = 0.999
    return float(val)


# ─────────────────────────────────────────────
# IMPROVEMENT 1: Chain-of-Thought system prompt
# ─────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst AI.

For EVERY turn, you MUST reason through the situation in this exact format:

THREAT_ANALYSIS: [List each file/process and whether it is malicious/suspicious and why]
CORRELATIONS: [Note any alert→file→process links that suggest a causal chain]
PRIORITY: [Which threat to handle first and why — ransomware files before processes, etc.]
CONFIDENCE: high | medium | low
ACTION: <exactly one action in the format below>

Rules for ACTION:
  investigate_file('FILE_ID')        - Examine a file when status is unclear
  investigate_process('PROCESS_ID')  - Examine a process when status is unclear
  quarantine_file('FILE_ID')         - Isolate a confirmed malicious file
  kill_process('PROCESS_ID')         - Stop a confirmed malicious process
  ignore_alert()                     - Dismiss (use only when everything is benign)
  escalate()                         - ABSOLUTE LAST RESORT only

Hard rules:
  - If CONFIDENCE is low → always investigate before acting (avoids false-action penalty)
  - Files marked [MALICIOUS] or entropy > 7.0 → quarantine_file immediately (high confidence)
  - Processes marked [SUSPICIOUS] → kill_process immediately (high confidence)
  - Handle ALL threats, not just the first one
  - NEVER repeat an action on the same ID

Example output:
THREAT_ANALYSIS: F1 encryptor.exe entropy=7.9 [MALICIOUS] — ransomware signature. P1 svchost32 [SUSPICIOUS] — misspelled system process.
CORRELATIONS: Alert A1 links F1→P1 suggesting F1 spawned P1.
PRIORITY: Quarantine F1 first to stop the source, then kill P1.
CONFIDENCE: high
ACTION: quarantine_file('F1')"""


# ─────────────────────────────────────────────
# IMPROVEMENT 2: Multi-step planner (hard task)
# ─────────────────────────────────────────────
PLANNER_PROMPT = """You are a SOC analyst planning a FULL response to a ransomware incident.

Given the environment state below, produce a complete ordered action plan to neutralise ALL threats.

Output ONLY a JSON array of action strings, nothing else. Example:
["quarantine_file('F1')", "quarantine_file('F2')", "kill_process('P1')"]

Rules:
  - Quarantine malicious files BEFORE killing processes (cut the source first)
  - Include every malicious file and every suspicious process
  - Do not include benign items
  - Maximum {max_steps} actions
"""


def build_plan(obs, client: OpenAI, max_steps: int) -> List[str]:
    """
    IMPROVEMENT 2: At the start of the hard task, ask the LLM to produce a
    full ordered action sequence. Returns a list of action strings, or [] on failure.
    """
    files     = obs.file_metadata or []
    processes = obs.process_tree  or []

    file_lines = "\n".join([
        f"  ID:{f.get('id')} Name:{f.get('name')} Entropy:{f.get('entropy')} "
        f"{'[MALICIOUS]' if f.get('is_malicious') else '[benign]'}"
        for f in files
    ]) or "  None"
    proc_lines = "\n".join([
        f"  ID:{p.get('id')} Name:{p.get('name')} Parent:{p.get('parent') or 'root'} "
        f"{'[SUSPICIOUS]' if p.get('suspicious') else '[benign]'}"
        for p in processes
    ]) or "  None"

    user_msg = (
        f"Files:\n{file_lines}\n\n"
        f"Processes:\n{proc_lines}\n\n"
        "Produce the full action plan as a JSON array."
    )

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system",  "content": PLANNER_PROMPT.format(max_steps=max_steps)},
                {"role": "user",    "content": user_msg},
            ],
            temperature=0.0,
            max_tokens=300,
        )
        raw = completion.choices[0].message.content or ""
        # Extract JSON array from response
        match = re.search(r"\[.*?\]", raw, re.DOTALL)
        if match:
            import json
            plan = json.loads(match.group())
            if isinstance(plan, list) and all(isinstance(s, str) for s in plan):
                print(f"[PLAN] Generated {len(plan)}-step plan: {plan}", flush=True)
                return plan
    except Exception as e:
        print(f"[PLAN Error: {e}] Will use step-by-step reasoning instead", flush=True)
    return []


# ─────────────────────────────────────────────
# IMPROVEMENT 5: Episode reflection prompt
# ─────────────────────────────────────────────
REFLECTION_PROMPT = """You just completed a security incident response episode.

Episode summary:
  Task:    {task}
  Steps:   {steps}
  Score:   {score:.3f}
  Actions: {actions}
  Result:  {result}

In 2-3 sentences, identify:
  1. What you did right
  2. What you should do differently next time
  3. One specific rule to remember

Keep it short and actionable. This will be prepended to your next episode."""


def reflect_on_episode(task: str, steps: int, score: float,
                        memory: List[Dict], client: OpenAI) -> str:
    """
    IMPROVEMENT 5: After each episode, generate a short reflection that will
    seed the next episode's context, enabling within-run self-correction.
    """
    actions = " → ".join(m["action"] for m in memory)
    last_result = memory[-1]["result"] if memory else "unknown"

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "user", "content": REFLECTION_PROMPT.format(
                    task=task, steps=steps, score=score,
                    actions=actions, result=last_result
                )},
            ],
            temperature=0.2,
            max_tokens=150,
        )
        reflection = completion.choices[0].message.content or ""
        print(f"[REFLECT] {reflection.strip()}", flush=True)
        return reflection.strip()
    except Exception as e:
        print(f"[REFLECT Error: {e}]", flush=True)
        return ""


# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
def log_start(task: str):
    print(f"[START] task={task} env={BENCHMARK} model={MODEL_NAME}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]):
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} "
        f"done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )

def log_end(success: bool, steps: int, rewards: List[float], score: float):
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    # field must be `score=` (not task_score=) for platform parser
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"rewards={rewards_str} score={score:.4f}",
        flush=True,
    )


# ─────────────────────────────────────────────
# IMPROVEMENT 4: Threat correlation in prompt
# ─────────────────────────────────────────────
def build_correlations(alerts, files, processes) -> str:
    """
    IMPROVEMENT 4: Explicitly surface alert→file→process causal links so the
    LLM understands the attack chain rather than treating each item in isolation.
    """
    lines = []
    file_map   = {f.get("id"): f.get("name", "?") for f in files}
    proc_map   = {p.get("id"): p.get("name", "?") for p in processes}

    for a in alerts:
        parts = []
        # alerts can be plain strings or dicts — handle both
        if isinstance(a, dict):
            aid  = a.get("id", "?")
            sev  = a.get("severity", "?")
            desc = a.get("description", str(a))
            rf   = a.get("related_file")
            rp   = a.get("related_process")
        else:
            # plain string alert — no structured correlation possible
            lines.append(f"  - {a}")
            continue

        parts.append(f"Alert {aid} [{sev}]: {desc}")
        if rf:
            parts.append(f"→ File {rf} ({file_map.get(rf, '?')})")
        if rp:
            parts.append(f"→ Process {rp} ({proc_map.get(rp, '?')})")
        lines.append("  " + " ".join(parts))

    return "\n".join(lines) if lines else "  None"


def build_user_prompt(observation, step: int, memory: List[Dict],
                       reflection: str = "") -> str:
    alerts    = observation.alerts        or []
    files     = observation.file_metadata or []
    processes = observation.process_tree  or []
    last_result = observation.last_action_result or "None"

    # Basic alert display (kept for backward compat)
    alert_lines = "\n".join([
        f"  - {a}" if isinstance(a, str) else
        f"  - [{a.get('severity','?')}] {a.get('description','?')}"
        for a in alerts
    ]) or "  None"

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
        [f"  - Step {m['step']}: {m['action']} → {m['result']}" for m in memory[-4:]]
    ) or "  None"

    # IMPROVEMENT 4: correlation section
    correlation_lines = build_correlations(alerts, files, processes)

    suspicious_count = sum(1 for p in processes if p.get("suspicious"))
    malicious_count  = sum(1 for f in files     if f.get("is_malicious"))
    multi_hint = ""
    if suspicious_count > 1 or malicious_count > 1:
        multi_hint = (
            f"\n⚠️ {malicious_count} malicious file(s) + "
            f"{suspicious_count} suspicious process(es). Handle ALL.\n"
        )

    # IMPROVEMENT 5: prepend reflection from prior episode if available
    reflection_block = ""
    if reflection:
        reflection_block = f"\n[Prior Episode Lesson]\n{reflection}\n"

    return (
        f"{reflection_block}"
        f"Step {step}/{MAX_STEPS}\n"
        f"Alerts:\n{alert_lines}\n\n"
        f"Alert Correlations (causal links):\n{correlation_lines}\n\n"
        f"Files:\n{file_lines}\n\n"
        f"Processes:\n{proc_lines}\n\n"
        f"Recent History:\n{memory_lines}\n\n"
        f"Last result: {last_result}"
        f"{multi_hint}\n"
        f"Now reason through THREAT_ANALYSIS → CORRELATIONS → PRIORITY → CONFIDENCE → ACTION:"
    )


# ─────────────────────────────────────────────
# Action parsing — extracts ACTION: line from CoT output
# ─────────────────────────────────────────────
def parse_action(response_text: str) -> Action:
    """
    IMPROVEMENT 1: Extract the ACTION: line from the CoT reasoning block.
    Falls back to scanning the full text if the structured tag is absent.
    """
    # Try to extract just the ACTION: line first
    action_match = re.search(r"ACTION\s*:\s*(.+)", response_text, re.IGNORECASE)
    if action_match:
        response_text = action_match.group(1).strip()

    patterns = {
        "investigate_file":    r"investigate_file\(['\"]([^'\"]+)['\"]\)",
        "investigate_process": r"investigate_process\(['\"]([^'\"]+)['\"]\)",
        "quarantine_file":     r"quarantine_file\(['\"]([^'\"]+)['\"]\)",
        "kill_process":        r"kill_process\(['\"]([^'\"]+)['\"]\)",
        "ignore_alert":        r"ignore_alert\(\)",
        "escalate":            r"escalate\(\)",
    }
    for action, pattern in patterns.items():
        match = re.search(pattern, response_text)
        if match:
            return Action(type=action, target_id=match.group(1) if match.groups() else None)
    return Action(type="escalate", target_id=None)


# ─────────────────────────────────────────────
# IMPROVEMENT 3: Confidence-gated heuristic fallback
# ─────────────────────────────────────────────
def parse_confidence(response_text: str) -> str:
    """Extract CONFIDENCE: high|medium|low from CoT output."""
    m = re.search(r"CONFIDENCE\s*:\s*(high|medium|low)", response_text, re.IGNORECASE)
    return m.group(1).lower() if m else "high"


def fallback_action(observation, memory: List[Dict]) -> Action:
    """
    Observation-driven fallback when LLM API is unavailable.
    Fixed: uses p.get("id") not f.get("id") in process loop.
    """
    files     = observation.file_metadata or []
    processes = observation.process_tree  or []

    acted_ids: set = set()
    for m in memory:
        id_match = re.search(r"\('([^']+)'\)", m.get("action", ""))
        if id_match:
            acted_ids.add(id_match.group(1))

    # 1. Quarantine malicious / high-entropy files
    for f in files:
        fid = f.get("id")
        if fid not in acted_ids and (f.get("is_malicious") or f.get("entropy", 0) > 7.0):
            return Action(type="quarantine_file", target_id=fid)

    # 2. Kill suspicious processes
    for p in processes:
        pid  = p.get("id")          # FIX: was f.get("id")
        name = p.get("name", "").lower()
        if pid not in acted_ids and (
            p.get("suspicious") or
            any(k in name for k in ["crypt","encrypt","ransom","svchost32","cmd32","tmp","miner"])
        ):
            return Action(type="kill_process", target_id=pid)

    # 3. Investigate unexamined files (highest entropy first)
    unacted_files = [f for f in files if f.get("id") not in acted_ids]
    if unacted_files:
        target = max(unacted_files, key=lambda x: x.get("entropy", 0))
        return Action(type="investigate_file", target_id=target["id"])

    # 4. Investigate unexamined processes  (FIX: was f.get)
    unacted_procs = [p for p in processes if p.get("id") not in acted_ids]
    if unacted_procs:
        return Action(type="investigate_process", target_id=unacted_procs[0]["id"])

    return Action(type="escalate", target_id=None)


# ─────────────────────────────────────────────
# Episode runner
# ─────────────────────────────────────────────
def run_episode(client: OpenAI, task: str, grader_func,
                prior_reflection: str = "") -> Dict:
    env = SecurityIncidentEnv(TASK_SCENARIO_MAP[task])
    obs = env.reset()

    rewards: List[float] = []
    memory:  List[Dict]  = []
    success = False
    step    = 0
    score   = safe_score(0.0)   # always bound before try

    # IMPROVEMENT 2: generate upfront plan for hard task
    action_plan: List[str] = []
    plan_index = 0
    if task == "hard_ransomware_chain":
        action_plan = build_plan(obs, client, MAX_STEPS)

    log_start(task)

    try:
        for step in range(1, MAX_STEPS + 1):
            action   = None
            api_ok   = False
            response = ""

            # ── IMPROVEMENT 2: execute plan step if available ──
            if action_plan and plan_index < len(action_plan):
                plan_str = action_plan[plan_index]
                plan_index += 1
                action = parse_action(plan_str)
                print(f"[PLAN EXEC] step={step} executing: {plan_str}", flush=True)

            # ── IMPROVEMENT 1 & 3: CoT + confidence-gated LLM ──
            if action is None:
                prompt = build_user_prompt(obs, step, memory, prior_reflection)
                try:
                    completion = client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                        temperature=TEMPERATURE,
                        max_tokens=MAX_TOKENS,
                    )
                    response = completion.choices[0].message.content or ""
                    api_ok   = True
                except Exception as e:
                    print(f"[API Error: {e}] Using heuristic fallback", flush=True)

                if api_ok:
                    # IMPROVEMENT 3: if confidence is low, force investigation first
                    confidence = parse_confidence(response)
                    if confidence == "low":
                        files     = obs.file_metadata or []
                        processes = obs.process_tree  or []
                        acted_ids = {
                            re.search(r"\('([^']+)'\)", m.get("action","")).group(1)
                            for m in memory
                            if re.search(r"\('([^']+)'\)", m.get("action",""))
                        }
                        uninvestigated_files = [
                            f for f in files if f.get("id") not in acted_ids
                        ]
                        if uninvestigated_files:
                            target = max(uninvestigated_files, key=lambda x: x.get("entropy", 0))
                            action = Action(type="investigate_file", target_id=target["id"])
                            print(f"[CONFIDENCE=low] Forcing investigation of {target['id']}", flush=True)

                    if action is None:
                        action = parse_action(response)
                else:
                    action = fallback_action(obs, memory)

            action_str = (
                f"{action.type}('{action.target_id}')"
                if action.target_id else f"{action.type}()"
            )

            obs, reward, done, _ = env.step(action)
            reward_val = reward.value if hasattr(reward, "value") else float(reward)
            reward_val = safe_score(reward_val)
            rewards.append(reward_val)

            error = getattr(obs, "last_action_result", None)
            memory.append({"step": step, "action": action_str, "result": error})
            log_step(step, action_str, reward_val, done, error)

            if done:
                break

        raw_score = grader_func(env.state)
        score     = safe_score(raw_score)
        success   = score >= 0.5

    except Exception as e:
        print(f"[Episode Error: {e}]", flush=True)
        score = safe_score(score)

    finally:
        log_end(success, step, rewards, score)

    return {
        "task":    task,
        "success": success,
        "score":   score,
        "steps":   step,
        "rewards": rewards,
        "memory":  memory,      # passed back so main() can generate reflection
    }


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    if not HF_TOKEN or len(HF_TOKEN.strip()) < 10:
        print("⚠️  WARNING: HF_TOKEN missing/invalid. Heuristic fallback will be used.", flush=True)

    client  = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "")
    results = []
    reflection = ""     # carries reflection from episode N → episode N+1

    for task in TASKS:
        # IMPROVEMENT 5: pass prior reflection into each episode
        result = run_episode(client, task, TASK_GRADER_MAP[task],
                             prior_reflection=reflection)
        results.append(result)

        # Generate reflection to seed the next task
        reflection = reflect_on_episode(
            task=task,
            steps=result["steps"],
            score=result["score"],
            memory=result["memory"],
            client=client,
        )

    print("\n" + "=" * 60, flush=True)
    print("FINAL RESULTS", flush=True)
    print("=" * 60, flush=True)
    for r in results:
        print(
            f"{r['task']} → Score: {r['score']:.4f} | "
            f"Steps: {r['steps']} | Success: {r['success']}",
            flush=True,
        )
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
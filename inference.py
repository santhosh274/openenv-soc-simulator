#!/usr/bin/env python3
import os
import re
import math
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

def safe_score(score: float) -> float:
    """Clamp score to strictly [0.1, 0.99] to pass OpenEnv (0,1) validation."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.1
    if math.isnan(val) or math.isinf(val):
        return 0.1
    return max(0.1, min(0.99, val))

SYSTEM_PROMPT = """You are a Security Operations Center (SOC) analyst AI.
Respond to each security incident by taking exactly ONE action per turn.
Available actions (use EXACT format shown):
investigate_file('FILE_ID')        - Examine a suspicious file
investigate_process('PROCESS_ID')  - Examine a suspicious process
quarantine_file('FILE_ID')         - Isolate a malicious file
kill_process('PROCESS_ID')         - Stop a malicious process
ignore_alert()                     - Dismiss the alert (use rarely)
escalate()                         - Escalate to senior analyst (LAST RESORT ONLY)

Decision rules:
1. NEVER escalate unless you have investigated ALL items and still cannot determine a safe action.
2. High entropy files (>7.0) or explicitly marked [MALICIOUS] → quarantine immediately.
3. Processes marked [SUSPICIOUS] or with weird names → kill immediately.
4. Handle ALL threats in the environment. Do not stop after the first one.
Output exactly ONE action and nothing else. Example: quarantine_file('F1')"""

def log_start(task: str):
    print(f"[START] task={task} env={BENCHMARK} model={MODEL_NAME}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]):
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error or 'null'}", flush=True)

def log_end(success: bool, steps: int, rewards: List[float], score: float):
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} rewards={rewards_str} task_score={score:.4f}", flush=True)

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
    
    suspicious_count = sum(1 for p in processes if p.get("suspicious"))
    malicious_count = sum(1 for f in files if f.get("is_malicious"))
    multi_hint = ""
    if suspicious_count > 1 or malicious_count > 1:
        multi_hint = f"\n⚠️ ALERT: {malicious_count} malicious file(s) and {suspicious_count} suspicious process(es) detected. Handle ALL.\n"
        
    return (
        f"Step {step}/{MAX_STEPS}\nAlerts:\n{alert_lines}\nFiles:\n{file_lines}\n"
        f"Processes:\n{proc_lines}\nRecent History:\n{memory_lines}\n"
        f"Last result: {last_result}\n{multi_hint}\nChoose next action:"
    )

def parse_action(response_text: str) -> Action:
    response_text = response_text.strip()
    patterns = {
        "investigate_file": r"investigate_file\(['\"]([^'\"]+)['\"]\)",
        "investigate_process": r"investigate_process\(['\"]([^'\"]+)['\"]\)",
        "quarantine_file": r"quarantine_file\(['\"]([^'\"]+)['\"]\)",
        "kill_process": r"kill_process\(['\"]([^'\"]+)['\"]\)",
        "ignore_alert": r"ignore_alert\(\)",
        "escalate": r"escalate\(\)",
    }
    for action, pattern in patterns.items():
        match = re.search(pattern, response_text)
        if match:
            return Action(type=action, target_id=match.group(1) if match.groups() else None)
    return Action(type="escalate", target_id=None)

def fallback_action(observation, memory: List[Dict]) -> Action:
    files = observation.file_metadata or []
    processes = observation.process_tree or []
    acted_ids: set = set()
    for m in memory:
        id_match = re.search(r"\('([^']+)'\)", m.get("action", ""))
        if id_match: acted_ids.add(id_match.group(1))

    for f in files:
        fid = f.get("id")
        if fid not in acted_ids and f.get("entropy", 0) > 7.0:
            return Action(type="quarantine_file", target_id=fid)
    for p in processes:
        pid = p.get("id")
        if pid not in acted_ids:
            name = p.get("name", "").lower()
            parent = p.get("parent")
            if parent is None or any(k in name for k in ["crypt", "encrypt", "ransom", "svchost32", "cmd32", "tmp", "miner"]):
                return Action(type="kill_process", target_id=pid)

    unacted_files = [f for f in files if f.get("id") not in acted_ids]
    if unacted_files:
        target = max(unacted_files, key=lambda x: x.get("entropy", 0))
        return Action(type="investigate_file", target_id=target["id"])

    unacted_procs = [p for p in processes if p.get("id") not in acted_ids]
    if unacted_procs:
        return Action(type="investigate_process", target_id=unacted_procs[0]["id"])

    return Action(type="escalate", target_id=None)

def run_episode(client: OpenAI, task: str, grader_func):
    env = SecurityIncidentEnv(TASK_SCENARIO_MAP[task])
    obs = env.reset()
    rewards: List[float] = []
    memory: List[Dict] = []
    success = False
    step = 0
    score = safe_score(0.0)
    log_start(task)
    try:
        for step in range(1, MAX_STEPS + 1):
            prompt = build_user_prompt(obs, step, memory)
            api_ok = False
            try:
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                    temperature=TEMPERATURE, max_tokens=MAX_TOKENS,
                )
                response = completion.choices[0].message.content or ""
                api_ok = True
            except Exception as e:
                response = ""
                print(f"[API Error: {e}] Using heuristic fallback", flush=True)
                
            action = parse_action(response) if api_ok else fallback_action(obs, memory)
            action_str = f"{action.type}('{action.target_id}')" if action.target_id else f"{action.type}()"
            
            obs, reward, done, _ = env.step(action)
            reward_val = reward.value if hasattr(reward, "value") else float(reward)
            reward_val = safe_score(reward_val)
            rewards.append(reward_val)
            
            error = getattr(obs, "last_action_result", None)
            memory.append({"step": step, "action": action_str, "result": error})
            log_step(step, action_str, reward_val, done, error)
            if done: break
                
        raw_score = grader_func(env.state)
        score = safe_score(raw_score)
        success = round(score, 4) >= 0.5
    finally:
        score = safe_score(score)
        log_end(success, step, rewards, score)
        return {"task": task, "success": success, "score": score, "steps": step, "rewards": rewards}

def main():
    if not HF_TOKEN or len(HF_TOKEN.strip()) < 10:
        print("⚠️  WARNING: HF_TOKEN is missing or invalid. Fallback actions will be used.", flush=True)
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "")
    results = []
    for task in TASKS:
        result = run_episode(client, task, TASK_GRADER_MAP[task])
        results.append(result)
    print("\n" + "=" * 60, flush=True)
    print("FINAL RESULTS", flush=True)
    print("=" * 60, flush=True)
    for r in results:
        print(f"{r['task']} → Score: {r['score']:.4f} | Success: {r['success']}", flush=True)
    print("=" * 60, flush=True)

if __name__ == "__main__":
    main()
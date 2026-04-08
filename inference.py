#!/usr/bin/env python3
"""
Baseline inference script for Security Incident SOC Environment.
Uses OpenAI Client to run an LLM agent against the environment.

Required environment variables:
  API_BASE_URL: The API endpoint for the LLM (e.g., https://router.huggingface.co/v1)
  MODEL_NAME: The model identifier to use for inference
  HF_TOKEN: Your Hugging Face / API key

Output format (stdout):
  [START] task=<task_name> env=<benchmark> model=<model_name>
  [STEP] step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
  [END] success=<true|false> steps=<n> rewards=<r1,r2,...,rn>
"""

import os
import json
import re
from typing import List, Optional, Dict, Any

from openai import OpenAI
from env.env import SecurityIncidentEnv
from env.models import Action
from graders import easy_grader, medium_grader, hard_grader

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")  # No default - required
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")  # Optional - for docker-based env
MAX_STEPS = 8
TEMPERATURE = 0.2
MAX_TOKENS = 200

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


SYSTEM_PROMPT = """You are a Security Operations Center (SOC) analyst.
Your job is to respond to security incidents by investigating and containing threats.

TASK ANALYSIS:
- If alert mentions PROCESS (e.g., "Unusual process chain", "suspicious process"): prioritize PROCESS investigation and potential termination
- If alert mentions FILE (e.g., "malware detected", "suspicious file"): prioritize FILE investigation and quarantine
- HIGH severity alerts require IMMEDIATE action

Available actions:
- investigate_file(target_id): Investigate a file for malicious indicators (high entropy = malicious)
- investigate_process(target_id): Investigate a process for suspicious behavior (SUSPICIOUS flag = malicious)
- quarantine_file(target_id): Quarantine a CONFIRMED malicious file
- kill_process(target_id): Terminate a CONFIRMED suspicious process
- ignore_alert(): Dismiss a FALSE POSITIVE alert (only if investigation proves benign)
- escalate(): Escalate to tier 2 if unable to determine

CRITICAL RULES:
- If you identify something as malicious (high entropy file OR suspicious process), TAKE ACTION to contain it
- Do NOT quarantine benign files (entropy < 7.0 and not flagged suspicious)
- Do NOT kill benign processes (not marked SUSPICIOUS)
- Focus on the PRIMARY THREAT mentioned in the alert

You must respond with exactly ONE action in the format: action_type('target_id')
For ignore_alert and escalate, no target_id is needed."""


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} rewards={rewards_str}", flush=True)


def build_user_prompt(observation, step: int) -> str:
    alerts = observation.alerts or []
    files = observation.file_metadata or []
    processes = observation.process_tree or []
    last_result = observation.last_action_result or "None"

    alert_lines = "\n".join([f"  - {a}" for a in alerts]) or "  None"
    
    file_lines = ""
    for f in files:
        suspicious = " [MALICIOUS]" if f.get('is_malicious') else " [benign]"
        file_lines += f"  - ID: {f.get('id')}, Name: {f.get('name')}, Entropy: {f.get('entropy', 'N/A')}{suspicious}\n"
    file_lines = file_lines.strip() or "  None"
    
    proc_lines = ""
    for p in processes:
        parent = p.get('parent') or "None"
        suspicious = " [SUSPICIOUS]" if p.get('suspicious') else " [benign]"
        proc_lines += f"  - ID: {p.get('id')}, Name: {p.get('name')}, Parent: {parent}{suspicious}\n"
    proc_lines = proc_lines.strip() or "  None"

    prompt = f"""Step {step}/8
Alerts (SEVERITY indicates priority - HIGH requires immediate action):
{alert_lines}

Files (look for [MALICIOUS] tag or high entropy >7.0):
{file_lines}

Processes (look for [SUSPICIOUS] tag):
{proc_lines}

Last action result: {last_result}

Choose your next action. Reply with exactly one action like: kill_process('P1') or quarantine_file('F1')"""
    return prompt


def parse_action(response_text: str) -> Action:
    response_text = response_text.strip()
    
    patterns = [
        r"investigate_file\s*\(\s*'([^']+)'\s*\)",
        r"investigate_process\s*\(\s*'([^']+)'\s*\)",
        r"quarantine_file\s*\(\s*'([^']+)'\s*\)",
        r"kill_process\s*\(\s*'([^']+)'\s*\)",
        r"ignore_alert\s*\(\s*\)",
        r"escalate\s*\(\s*\)",
    ]
    
    action_types = [
        "investigate_file", "investigate_process", "quarantine_file", 
        "kill_process", "ignore_alert", "escalate"
    ]
    
    for i, pattern in enumerate(patterns):
        match = re.search(pattern, response_text)
        if match:
            if action_types[i] in ["ignore_alert", "escalate"]:
                return Action(type=action_types[i], target_id=None)
            else:
                target = match.group(1)
                return Action(type=action_types[i], target_id=target)
    
    return Action(type="ignore_alert", target_id=None)


def run_episode(client: OpenAI, task: str, grader_func) -> Dict[str, Any]:
    scenario = TASK_SCENARIO_MAP.get(task, task)
    env = SecurityIncidentEnv(scenario)
    observation = env.reset()
    
    rewards: List[float] = []
    steps_taken = 0
    success = False
    
    log_start(task=task, env=BENCHMARK, model=MODEL_NAME)
    
    try:
        for step in range(1, MAX_STEPS + 1):
            user_prompt = build_user_prompt(observation, step)
            
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ]
            
            try:
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                    stream=False,
                )
                response_text = completion.choices[0].message.content or ""
            except Exception as e:
                response_text = ""
                print(f"[DEBUG] API call failed: {e}", flush=True)
            
            action = parse_action(response_text)
            action_str = f"{action.type}('{action.target_id}')" if action.target_id else f"{action.type}()"
            
            obs, reward, done, info = env.step(action)
            
            reward_val = reward.value if hasattr(reward, 'value') else float(reward)
            error = obs.last_action_result if hasattr(obs, 'last_action_result') else None
            
            rewards.append(reward_val)
            steps_taken = step
            
            log_step(step=step, action=action_str, reward=reward_val, done=done, error=error)
            
            observation = obs
            
            if done:
                state = env.state
                score = grader_func(state)
                success = score >= 0.5
                break
        else:
            state = env.state
            score = grader_func(state)
            success = score >= 0.5
            
    finally:
        # env.close() - no-op for local env
        log_end(success=success, steps=steps_taken, rewards=rewards)
    
    state = env.state
    final_score = grader_func(state)
    
    return {
        "task": task,
        "success": success,
        "steps": steps_taken,
        "rewards": rewards,
        "score": final_score
    }


def main() -> None:
    if not HF_TOKEN:
        print("Error: HF_TOKEN environment variable not set", flush=True)
        return
    
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
    
    results = []
    for task in TASKS:
        grader = TASK_GRADER_MAP[task]
        result = run_episode(client, task, grader)
        results.append(result)
    
    print("\n" + "="*60, flush=True)
    print("FINAL RESULTS", flush=True)
    print("="*60, flush=True)
    for r in results:
        print(f"Task: {r['task']}, Score: {r['score']:.2f}, Success: {r['success']}", flush=True)
    print("="*60, flush=True)


if __name__ == "__main__":
    main()
"""
OpenEnv Server - Security Incident SOC Environment
This module provides the HTTP API for the security incident response environment.
"""

import os
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from env.env import SecurityIncidentEnv
from env.models import Action, Observation as EnvObservation, Reward as EnvReward
from graders import easy_grader, medium_grader, hard_grader

app = FastAPI(title="Security Incident SOC Environment")

current_env: Optional[SecurityIncidentEnv] = None
current_task: Optional[str] = None
task_grader_map = {
    "easy_known_malware": (easy_grader.grade, "easy"),
    "medium_behavioral_attack": (medium_grader.grade, "medium"),
    "hard_ransomware_chain": (hard_grader.grade, "hard"),
}


class ResetResponse(BaseModel):
    observation: Dict[str, Any]
    info: Dict[str, Any] = {}


class StepRequest(BaseModel):
    action: Action


class StepResponse(BaseModel):
    observation: Dict[str, Any]
    reward: Dict[str, Any]
    done: bool
    info: Dict[str, Any] = {}


class GraderResponse(BaseModel):
    task: str
    score: float


@app.get("/")
def root():
    return {"status": "ready", "environment": "security-incident-soc"}


@app.get("/tasks")
def list_tasks() -> Dict[str, Any]:
    return {"tasks": list(task_grader_map.keys())}


@app.post("/reset", response_model=ResetResponse)
def reset(task: Optional[str] = None):
    global current_env, current_task
    if task is None:
        task = "easy_known_malware"
    if task not in task_grader_map:
        raise HTTPException(f"Unknown task: {task}", status_code=400)
    current_task = task
    grader_func, scenario_name = task_grader_map[task]
    current_env = SecurityIncidentEnv(scenario_name)
    obs = current_env.reset()
    return ResetResponse(
        observation=obs.model_dump(),
        info={"task": task, "max_steps": current_env.state.max_steps}
    )


@app.post("/step", response_model=StepResponse)
def step(req: StepRequest):
    global current_env
    if current_env is None:
        raise HTTPException("Environment not initialized. Call /reset first.", status_code=400)
    obs, reward, done, info = current_env.step(req.action)
    return StepResponse(
        observation=obs.model_dump(),
        reward=reward.model_dump() if hasattr(reward, 'model_dump') else {"value": reward, "reason": ""},
        done=done,
        info=info
    )


@app.get("/state")
def get_state():
    global current_env
    if current_env is None:
        raise HTTPException("Environment not initialized. Call /reset first.", status_code=400)
    state = current_env.state
    return {
        "step_count": state.step_count,
        "max_steps": state.max_steps,
        "flags": state.flags,
        "quarantined_files": state.quarantined_files,
        "killed_processes": state.killed_processes,
        "alerts": [a.model_dump() for a in state.alerts],
        "files": [f.model_dump() for f in state.files],
        "processes": [p.model_dump() for p in state.processes],
    }


@app.get("/grader/{task_name}", response_model=GraderResponse)
def grade_task(task_name: str):
    global current_env, current_task
    if current_env is None:
        raise HTTPException("Environment not initialized. Call /reset first.", status_code=400)
    if task_name not in task_grader_map:
        raise HTTPException(f"Unknown task: {task_name}", status_code=400)
    grader_func, _ = task_grader_map[task_name]
    state = current_env.state
    score = grader_func(state)
    return GraderResponse(task=task_name, score=score)


@app.get("/health")
def health_check():
    return {"status": "healthy"}


def main():
    import uvicorn
    port = int(os.getenv("PORT", "7860"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
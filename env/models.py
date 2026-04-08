from pydantic import BaseModel
from typing import List, Optional, Literal, Dict, Any

class Alert(BaseModel):
    id: str
    severity: Literal["low", "medium", "high"]
    description: str
    related_file: Optional[str] = None
    related_process: Optional[str] = None

class FileSample(BaseModel):
    id: str
    name: str
    entropy: float
    is_malicious: bool

class Process(BaseModel):
    id: str
    name: str
    parent: Optional[str]
    suspicious: bool

# Observation
class Observation(BaseModel):
    alerts: List[str]  # summaries
    file_metadata: List[Dict[str, Any]]
    process_tree: List[Dict[str, Any]]
    last_action_result: str

# Action
class Action(BaseModel):
    type: Literal[
        "investigate_file",
        "investigate_process",
        "quarantine_file",
        "kill_process",
        "ignore_alert",
        "escalate"
    ]
    target_id: Optional[str]

# Reward
class Reward(BaseModel):
    value: float
    reason: str
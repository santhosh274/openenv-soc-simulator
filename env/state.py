from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json
import os
from .models import Alert, FileSample, Process

@dataclass
class State:
    alerts: List[Alert] = field(default_factory=list)
    files: List[FileSample] = field(default_factory=list)
    processes: List[Process] = field(default_factory=list)
    quarantined_files: List[str] = field(default_factory=list)
    killed_processes: List[str] = field(default_factory=list)
    flags: Dict[str, Any] = field(default_factory=lambda: {
        'investigated': False,
        'contained': False,
        'early_detection': False,
        'false_actions': 0
    })
    step_count: int = 0
    max_steps: int = 8
    terminal: bool = False

def load_scenario(scenario_name: str) -> State:
    path = f'scenarios/{scenario_name}.json'
    if not os.path.exists(path):
        raise FileNotFoundError(f'Scenario {path} not found')
    
    with open(path, 'r') as f:
        data = json.load(f)
    
    state = State()
    state.alerts = [Alert(**alert) for alert in data.get('alerts', [])]
    state.files = [FileSample(**file) for file in data.get('files', [])]
    state.processes = [Process(**proc) for proc in data.get('processes', [])]
    state.max_steps = data.get('max_steps', 8)
    state.flags['investigated'] = False
    state.flags['contained'] = False
    state.flags['early_detection'] = False
    state.flags['false_actions'] = 0
    state.step_count = 0
    state.terminal = False
    return state

def quarantine_file(state: State, file_id: str) -> dict:
    # Check before remove
    is_mal = any(f.id == file_id and f.is_malicious for f in state.files)
    state.files = [f for f in state.files if f.id != file_id]
    state.quarantined_files.append(file_id)
    return {'success': True, 'was_malicious': is_mal}

# Similar for others
def kill_process(state: State, proc_id: str) -> dict:
    was_susp = any(p.id == proc_id and p.suspicious for p in state.processes)
    state.processes = [p for p in state.processes if p.id != proc_id]
    state.killed_processes.append(proc_id)
    return {'success': True, 'was_suspicious': was_susp}

def increment_false_action(state: State):
    state.flags['false_actions'] += 1

def set_flag(state: State, flag: str, value: Any):
    state.flags[flag] = value

def increment_step(state: State):
    state.step_count += 1

# Note: investigate doesn't change state much, just flags
def investigate_file(state: State):
    state.flags['investigated'] = True

def investigate_process(state: State):
    state.flags['investigated'] = True  # or more specific

# Update contained/early_detection in env logic


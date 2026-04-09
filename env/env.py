from .models import Action, Observation
from .state import (load_scenario, quarantine_file, kill_process, increment_false_action, 
                                            set_flag, increment_step, investigate_file, investigate_process, State)
from .reward import compute_reward
from typing import Dict, Any

class SecurityIncidentEnv:

    def __init__(self, scenario):
        self.scenario = scenario
        self.state = None
        self.done = False
        self.last_action_result = ''

    def reset(self):
        self.state = load_scenario(self.scenario)
        self.done = False
        self.last_action_result = ''
        return self._get_observation()

    def _get_observation(self) -> Observation:
        # Filtered view per spec
        alert_summaries = [f"{a.severity.upper()}: {a.description}" for a in self.state.alerts]
        file_metadata = [
            {'id': f.id, 'name': f.name, 'entropy': f.entropy} for f in self.state.files
        ]
        process_tree = [
            {'id': p.id, 'name': p.name, 'parent': p.parent} for p in self.state.processes
        ]
        return Observation(
            alerts=alert_summaries,  # List[str]
            file_metadata=file_metadata,
            process_tree=process_tree,
            last_action_result=self.last_action_result
        )

    def step(self, action: Action):
        result: Dict[str, Any] = self._apply_action(action)
        reward = compute_reward(self.state, action, result)
        increment_step(self.state)
        self.done = self._check_done()
        obs = self._get_observation()
        info = {'result': result}
        return obs, reward, self.done, info

    def _apply_action(self, action: Action) -> Dict[str, Any]:
        self.last_action_result = ''
        result = {}
        if action.type == 'investigate_file':
            if action.target_id:
                # Simulate reveal
                file = next((f for f in self.state.files if f.id == action.target_id), None)
                if file:
                    investigate_file(self.state)
                    self.last_action_result = f'File {file.name}: entropy {file.entropy:.2f}'
                    result = {'investigated': True}
                else:
                    self.last_action_result = 'File not found'
                    increment_false_action(self.state)
                    result = {'investigated': False}
        elif action.type == 'investigate_process':
            # similar
            if action.target_id:
                proc = next((p for p in self.state.processes if p.id == action.target_id), None)
                if proc:
                    investigate_process(self.state)
                    self.last_action_result = f'Process {proc.name} analyzed'
                    result = {'investigated': True}
                else:
                    increment_false_action(self.state)
                    result = {'investigated': False}
        elif action.type == 'quarantine_file':
            if action.target_id:
                result = quarantine_file(self.state, action.target_id)
                if result['was_malicious']:
                    set_flag(self.state, 'contained', True)
                self.last_action_result = f'Quarantined {action.target_id}: {"malicious" if result["was_malicious"] else "benign"}'
        elif action.type == 'kill_process':
            if action.target_id:
                result = kill_process(self.state, action.target_id)
                if result['was_suspicious']:
                    set_flag(self.state, 'contained', True)
                self.last_action_result = f'Killed {action.target_id}: {"suspicious" if result["was_suspicious"] else "benign"}'
        elif action.type == 'ignore_alert':
            increment_false_action(self.state)
            self.last_action_result = 'Alert ignored'
            result = {}
        elif action.type == 'escalate':
            set_flag(self.state, 'contained', True)
            self.last_action_result = 'Escalated incident'
            result = {'escalated': True}
        # Update early_detection
        if self.state.step_count < 4 and self.state.flags.get('contained'):
            set_flag(self.state, 'early_detection', True)
        return result

    def _check_done(self) -> bool:
        return (self.state.step_count >= self.state.max_steps or 
                self.state.flags.get('contained') and self.state.flags.get('investigated'))

    def state(self):
        return self.state

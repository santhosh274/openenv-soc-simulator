from .models import Reward
from typing import Any

def compute_reward(state, action: Any, result: dict) -> Reward:
    reward_val = 0.0
    reason_parts = []

    # Base action rewards (existing)
    if action.type == "investigate_file" and result.get("investigated"):
        reward_val += 0.2
        reason_parts.append("correct investigate +0.2")
    elif action.type == "investigate_file":
        reward_val -= 0.05
        reason_parts.append("wrong investigate -0.05")

    if action.type == "quarantine_file":
        is_mal = result.get("was_malicious", False)
        if is_mal:
            reward_val += 0.5
            reason_parts.append("malicious quarantine +0.5")
        else:
            reward_val -= 0.4
            reason_parts.append("benign quarantine -0.4")

    if action.type == "kill_process":
        is_susp = result.get("was_suspicious", False)
        if is_susp:
            reward_val += 0.3
            reason_parts.append("suspicious kill +0.3")
        else:
            reward_val -= 0.3
            reason_parts.append("benign kill -0.3")

    if action.type == "ignore_alert":
        reward_val -= 0.1
        reason_parts.append("ignore -0.1")

    # Shaped rewards
    false_actions = state.flags.get("false_actions", 0)
    reward_val -= 0.1 * min(false_actions, 5)  # cap penalty
    if false_actions > 0:
        reason_parts.append(f"false actions x{false_actions} -0.1")

    if state.flags.get("early_detection"):
        reward_val += 0.2
        reason_parts.append("early detection +0.2")

    # Terminal bonus
    if state.terminal and state.flags.get("contained"):
        reward_val += 0.5
        reason_parts.append("containment bonus +0.5")

    reason = "; ".join(reason_parts) or "no reward change"

    return Reward(value=round(reward_val, 2), reason=reason)

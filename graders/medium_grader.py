def safe_score(score: float) -> float:
    """Enforce score to be strictly between 0.0 and 1.0."""
    try: val = float(score)
    except (TypeError, ValueError): return 0.001
    if val != val: return 0.001
    return max(0.001, min(0.999, val))

def grade(state):
    suspicious_ids = {p.id for p in state.processes if p.suspicious}
    correctly_killed = suspicious_ids & set(state.killed_processes)
    process_handled = len(correctly_killed) > 0
    investigated = state.flags.get("investigated", False)
    false_count = state.flags.get("false_actions", 0)
    false_penalty = min(false_count * 0.17, 0.34)

    score = 0.10
    score += 0.35 * int(investigated)
    score += 0.42 * int(process_handled)
    score -= false_penalty
    return safe_score(score)
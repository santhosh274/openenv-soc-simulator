import math

def safe_score(score: float) -> float:
    """Clamp score to strictly (0, 1): [0.1, 0.99] to pass OpenEnv validation."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.1
    if math.isnan(val) or math.isinf(val):
        return 0.1
    return max(0.1, min(0.99, val))

def grade(state):
    malicious_ids = {f.id for f in state.files if f.is_malicious}
    suspicious_ids = {p.id for p in state.processes if p.suspicious}
    correctly_quarantined = malicious_ids & set(state.quarantined_files)
    correctly_killed = suspicious_ids & set(state.killed_processes)

    handled_files = len(correctly_quarantined)
    handled_procs = len(correctly_killed)

    remaining_malicious = sum(
        1 for f in state.files
        if f.is_malicious and f.id not in state.quarantined_files
    )
    remaining_suspicious = sum(
        1 for p in state.processes
        if p.suspicious and p.id not in state.killed_processes
    )

    total_threats = max(
        handled_files + remaining_malicious + handled_procs + remaining_suspicious,
        1,
    )

    threats_handled = handled_files + handled_procs
    containment_ratio = min(threats_handled / total_threats, 1.0)

    efficiency = max(0.0, 1.0 - (state.step_count / state.max_steps))
    early_bonus = 0.20 if (state.step_count <= 4 and containment_ratio >= 0.66) else 0.0
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.43)

    score = 0.10
    score += 0.35 * containment_ratio
    score += early_bonus
    score += efficiency * 0.08
    score -= false_penalty

    return safe_score(score)
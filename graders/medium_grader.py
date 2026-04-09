def safe_score(score: float) -> float:
    """Clamp score to be strictly between 0 and 1 (validator requirement)."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.001
    if val <= 0.0:
        return 0.001
    if val >= 1.0:
        return 0.999
    return val

def grade(state):
    """
    Task 2: Behavioral Attack — Grader
    Score breakdown (strictly between 0 and 1):
    ┌──────────────────────────────────────┬────────┐
    │ Component                            │ Weight │
    ├──────────────────────────────────────┼────────┤
    │ base (always awarded)                │  0.10  │
    │ process investigated flag set        │  0.35  │
    │ suspicious process correctly killed  │  0.42  │
    │ false action penalty (capped)        │ -0.34  │
    ├──────────────────────────────────────┼────────┤
    │ Max achievable                       │  0.87  │
    │ Min achievable (base − max penalty)  │  0.001 │
    └──────────────────────────────────────┴────────┘
    """
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
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
    Task 1: Known Malware — Grader
    Score breakdown (strictly between 0 and 1):
    ┌─────────────────────────────────┬────────┐
    │ Component                       │ Weight │
    ├─────────────────────────────────┼────────┤
    │ base (always awarded)           │  0.10  │
    │ investigated flag set           │  0.35  │
    │ malicious file correctly        │        │
    │   quarantined (ID-verified)     │  0.44  │
    │ containment flag (env-set)      │  0.05  │
    ├─────────────────────────────────┼────────┤
    │ Max achievable                  │  0.94  │
    │ Min achievable (base only)      │  0.10  │
    └─────────────────────────────────┴────────┘
    """
    malicious_ids = {f.id for f in state.files if f.is_malicious}
    correctly_quarantined = malicious_ids & set(state.quarantined_files)
    malicious_quarantined = len(correctly_quarantined) > 0

    env_contained = state.flags.get("contained", False)
    investigated = state.flags.get("investigated", False)

    score = 0.10
    score += 0.35 * int(investigated)
    score += 0.44 * int(malicious_quarantined)
    score += 0.05 * int(env_contained)

    return safe_score(score)
def safe_score(score: float) -> float:
    """Clamp score to be strictly between 0 and 1."""
    if score <= 0:
        return 0.001
    if score >= 1:
        return 0.999
    return score


def grade(state):
    """
    Task 1: Known Malware — Grader
    Score breakdown (all strictly between 0 and 1):
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
    # IDs of truly malicious files in this scenario
    malicious_ids = {f.id for f in state.files if f.is_malicious}

    # Only award containment credit if a MALICIOUS file was quarantined
    correctly_quarantined = malicious_ids & set(state.quarantined_files)
    malicious_quarantined = len(correctly_quarantined) > 0

    # Separate bonus for the env's own containment flag
    env_contained = state.flags.get("contained", False)

    investigated = state.flags.get("investigated", False)

    score = 0.10
    score += 0.35 * int(investigated)
    score += 0.44 * int(malicious_quarantined)
    score += 0.05 * int(env_contained)

    return safe_score(score)
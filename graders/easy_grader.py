def safe_score(score: float) -> float:
    """Enforce score to be strictly between 0.0 and 1.0."""
    try: val = float(score)
    except (TypeError, ValueError): return 0.001
    if val != val: return 0.001
    return max(0.001, min(0.999, val))

def grade(state):
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
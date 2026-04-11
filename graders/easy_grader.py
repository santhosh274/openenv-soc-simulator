import math

def safe_score(score: float) -> float:
    """Clamp score to strictly (0, 1): [0.1, 0.99] to pass OpenEnv validation."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.1
    if math.isnan(val) or math.isinf(val):
        return 0.1
    # Strict clamp: guarantees 0.0 < score < 1.0
    return max(0.1, min(0.99, val))

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
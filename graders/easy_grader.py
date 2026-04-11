import math

def safe_score(score: float) -> float:
    """Clamp strictly inside (0, 1) using [0.01, 0.99]."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.01
    if math.isnan(val) or math.isinf(val):
        return 0.01
    return max(0.01, min(0.99, val))

def _get(obj, attr, default=None):
    try:
        return getattr(obj, attr, default)
    except Exception:
        pass
    try:
        return obj[attr]
    except Exception:
        return default

def grade(state):
    """
    Task 1: Known Malware
    Raw score range: base=0.05 .. max=0.89 (always inside (0,1)).
    """
    try:
        files = _get(state, "files") or []
        quarantined = set(_get(state, "quarantined_files") or [])
        flags = _get(state, "flags") or {}

        malicious_ids = {
            _get(f, "id")
            for f in files
            if _get(f, "is_malicious", False)
        }
        malicious_ids.discard(None)

        correctly_quarantined = malicious_ids & quarantined
        malicious_quarantined = len(correctly_quarantined) > 0

        env_contained = bool(flags.get("contained", False))
        investigated = bool(flags.get("investigated", False))

        # Base is 0.05 ( >0 )
        score = 0.05
        score += 0.30 * int(investigated)            # investigation bonus
        score += 0.44 * int(malicious_quarantined)   # quarantine bonus
        score += 0.10 * int(env_contained)           # containment bonus
        # Max = 0.05 + 0.30 + 0.44 + 0.10 = 0.89 (< 0.99)

        return safe_score(score)
    except Exception:
        return safe_score(0.05)
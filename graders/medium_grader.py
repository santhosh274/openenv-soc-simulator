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
    Task 2: Behavioral Attack
    Raw score range: base=0.05 .. max=0.77, penalties capped so min>0.
    """
    try:
        processes = _get(state, "processes") or []
        killed = set(_get(state, "killed_processes") or [])
        flags = _get(state, "flags") or {}

        suspicious_ids = {
            _get(p, "id")
            for p in processes
            if _get(p, "suspicious", False)
        }
        suspicious_ids.discard(None)

        correctly_killed = suspicious_ids & killed
        process_handled = len(correctly_killed) > 0

        investigated = bool(flags.get("investigated", False))
        false_count = int(flags.get("false_actions", 0) or 0)

        # Cap penalty so score never drops below base (0.05)
        false_penalty = min(false_count * 0.17, 0.05)

        score = 0.05                                # base > 0
        score += 0.30 * int(investigated)           # investigation bonus
        score += 0.42 * int(process_handled)        # correct kill bonus
        score -= false_penalty                      # capped penalty
        # Max = 0.05 + 0.30 + 0.42 = 0.77 (< 0.99)

        return safe_score(score)
    except Exception:
        return safe_score(0.05)
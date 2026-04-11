import math


def safe_score(score: float) -> float:
    """
    Strictly enforce open interval (0, 1).
    Handles NaN, Inf, non-numeric input.
    Clamps to [0.1, 0.99] — both values are strictly inside (0, 1).
    """
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.1
    if math.isnan(val) or math.isinf(val):
        return 0.1
    return max(0.1, min(0.99, val))


def _get(obj, attr, default=None):
    """
    Safe getter: works whether obj is a plain object (attribute access)
    or a dict (key access). Returns default on any failure.
    """
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

    Score table (strictly in (0, 1)):
    ┌──────────────────────────────────────┬───────┐
    │ Component                            │ Value │
    ├──────────────────────────────────────┼───────┤
    │ base (always)                        │  0.10 │
    │ + investigated flag set              │  0.35 │
    │ + suspicious process correctly killed│  0.42 │
    │ - false action penalty (capped)      │ -0.34 │
    ├──────────────────────────────────────┼───────┤
    │ Max achievable                       │  0.87 │  ← never hits 1.0
    │ Min (base − max penalty)             │ -0.24 │  ← safe_score floors to 0.1
    └──────────────────────────────────────┴───────┘
    """
    try:
        processes = _get(state, "processes") or []
        killed = set(_get(state, "killed_processes") or [])
        flags = _get(state, "flags") or {}

        # IDs of truly suspicious processes — safe attribute access
        suspicious_ids = {
            _get(p, "id")
            for p in processes
            if _get(p, "suspicious", False)
        }
        suspicious_ids.discard(None)

        # Credit only if a SUSPICIOUS process was correctly killed
        correctly_killed = suspicious_ids & killed
        process_handled = len(correctly_killed) > 0

        investigated = bool(flags.get("investigated", False))
        false_count = int(flags.get("false_actions", 0) or 0)

        # Cap penalty so it cannot erase the base + partial gains entirely
        false_penalty = min(false_count * 0.17, 0.34)

        score = 0.10                                  # base — always > 0
        score += 0.35 * int(investigated)             # investigation credit
        score += 0.42 * int(process_handled)          # correct kill credit
        score -= false_penalty                        # false action penalty

        return safe_score(score)

    except Exception:
        return safe_score(0.1)
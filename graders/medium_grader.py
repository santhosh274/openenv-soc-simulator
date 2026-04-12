import math


def safe_score(score) -> float:
    """
    Strictly enforce open interval (0, 1) — never 0.0, never 1.0.

    Fixes per platform maintainer (bhaskar raj) guidance:
      1. Pure Python float return — not numpy, not string
      2. Handles NaN, Inf, None, non-numeric
      3. Clamps to [0.001, 0.999]
      4. Explicit == 0.0 / == 1.0 boundary check after clamping
    """
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.001
    if math.isnan(val) or math.isinf(val):
        return 0.001
    val = max(0.001, min(0.999, val))
    if val <= 0.0:
        val = 0.001
    if val >= 1.0:
        val = 0.999
    return float(val)


def _get(obj, attr, default=None):
    """Safe dual-mode getter: tries attribute access then dict access."""
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

    Score table (always strictly inside (0, 1)):
    ┌──────────────────────────────────────┬───────┐
    │ Component                            │ Value │
    ├──────────────────────────────────────┼───────┤
    │ base (always)                        │  0.10 │
    │ + investigated flag                  │  0.35 │
    │ + suspicious process correctly killed│  0.42 │
    │ - false action penalty (capped 0.34) │ -0.34 │
    ├──────────────────────────────────────┼───────┤
    │ Max achievable                       │  0.87 │  ← never 1.0
    │ Min after safe_score floor           │  0.001│  ← never 0.0
    └──────────────────────────────────────┴───────┘
    """
    try:
        processes = _get(state, "processes") or []
        killed    = set(_get(state, "killed_processes") or [])
        flags     = _get(state, "flags") or {}

        suspicious_ids = {
            _get(p, "id")
            for p in processes
            if _get(p, "suspicious", False)
        }
        suspicious_ids.discard(None)

        correctly_killed = suspicious_ids & killed
        process_handled  = len(correctly_killed) > 0
        investigated     = bool(flags.get("investigated", False))
        false_count      = int(flags.get("false_actions", 0) or 0)
        false_penalty    = min(false_count * 0.17, 0.34)

        score = 0.10
        score += 0.35 * int(investigated)
        score += 0.42 * int(process_handled)
        score -= false_penalty

        result = safe_score(score)
        print(f"GRADE: {result} {type(result)}", flush=True)   # debug per maintainer advice
        return result

    except Exception as ex:
        print(f"GRADE ERROR (medium): {ex}", flush=True)
        return safe_score(0.001)
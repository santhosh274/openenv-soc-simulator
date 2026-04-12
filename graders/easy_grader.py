import math


def safe_score(score) -> float:
    """
    Strictly enforce open interval (0, 1) — never 0.0, never 1.0.

    Fixes per platform maintainer (bhaskar raj) guidance:
      1. Pure Python float return — not numpy, not string
      2. Handles NaN, Inf, None, non-numeric
      3. Clamps to [0.001, 0.999] (Prithvi's community fix)
      4. Explicit == 0.0 / == 1.0 boundary check after clamping
         to catch precision errors like 1.0000001 or -0.00001
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
    return float(val)           # always pure Python float


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
    Task 1: Known Malware

    Score table (always strictly inside (0, 1)):
    ┌──────────────────────────────────────┬───────┐
    │ Component                            │ Value │
    ├──────────────────────────────────────┼───────┤
    │ base (always)                        │  0.10 │
    │ + investigated flag                  │  0.35 │
    │ + malicious file correctly quarantined│  0.44 │
    │ + env containment flag bonus         │  0.05 │
    ├──────────────────────────────────────┼───────┤
    │ Max achievable                       │  0.94 │  ← never 1.0
    │ Min (base only)                      │  0.10 │  ← never 0.0
    └──────────────────────────────────────┴───────┘
    """
    try:
        files       = _get(state, "files") or []
        quarantined = set(_get(state, "quarantined_files") or [])
        flags       = _get(state, "flags") or {}

        malicious_ids = {
            _get(f, "id")
            for f in files
            if _get(f, "is_malicious", False)
        }
        malicious_ids.discard(None)

        correctly_quarantined = malicious_ids & quarantined
        malicious_quarantined = len(correctly_quarantined) > 0
        env_contained         = bool(flags.get("contained", False))
        investigated          = bool(flags.get("investigated", False))

        score = 0.10
        score += 0.35 * int(investigated)
        score += 0.44 * int(malicious_quarantined)
        score += 0.05 * int(env_contained)

        result = safe_score(score)
        print(f"GRADE: {result} {type(result)}", flush=True)   # debug per maintainer advice
        return result

    except Exception as ex:
        print(f"GRADE ERROR (easy): {ex}", flush=True)
        return safe_score(0.001)
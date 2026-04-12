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
    Task 3: Ransomware Chain

    Score table (always strictly inside (0, 1)):
    ┌──────────────────────────────────────────┬───────┐
    │ Component                                │ Value │
    ├──────────────────────────────────────────┼───────┤
    │ base (always)                            │  0.10 │
    │ + containment ratio × 0.35              │  0–0.35│
    │ + early detection bonus (≥66% in ≤4 steps│  0.20 │
    │ + efficiency bonus × 0.08               │  0–0.08│
    │ - false action penalty (capped 0.43)    │ −0.43 │
    ├──────────────────────────────────────────┼───────┤
    │ Max achievable  0.10+0.35+0.20+0.08 =   │  0.73 │  ← never 1.0
    │ Min after safe_score floor              │  0.001│  ← never 0.0
    └──────────────────────────────────────────┴───────┘
    """
    try:
        files       = _get(state, "files") or []
        processes   = _get(state, "processes") or []
        quarantined = set(_get(state, "quarantined_files") or [])
        killed      = set(_get(state, "killed_processes") or [])
        flags       = _get(state, "flags") or {}

        step_count = int(_get(state, "step_count", 0) or 0)
        max_steps  = int(_get(state, "max_steps", 8) or 8)
        if max_steps == 0:
            max_steps = 8

        malicious_ids = {
            _get(f, "id")
            for f in files
            if _get(f, "is_malicious", False)
        }
        malicious_ids.discard(None)

        suspicious_ids = {
            _get(p, "id")
            for p in processes
            if _get(p, "suspicious", False)
        }
        suspicious_ids.discard(None)

        correctly_quarantined = malicious_ids & quarantined
        correctly_killed      = suspicious_ids & killed
        handled_files         = len(correctly_quarantined)
        handled_procs         = len(correctly_killed)

        remaining_malicious = sum(
            1 for f in files
            if _get(f, "is_malicious", False) and _get(f, "id") not in quarantined
        )
        remaining_suspicious = sum(
            1 for p in processes
            if _get(p, "suspicious", False) and _get(p, "id") not in killed
        )

        total_threats = max(
            handled_files + remaining_malicious + handled_procs + remaining_suspicious, 1
        )
        threats_handled   = handled_files + handled_procs
        containment_ratio = min(float(threats_handled) / float(total_threats), 1.0)

        efficiency  = max(0.0, 1.0 - (step_count / max_steps))
        early_bonus = 0.20 if (step_count <= 4 and containment_ratio >= 0.66) else 0.0

        false_count   = int(flags.get("false_actions", 0) or 0)
        false_penalty = min(false_count * 0.2, 0.43)

        score = 0.10
        score += 0.35 * containment_ratio
        score += early_bonus
        score += efficiency * 0.08
        score -= false_penalty

        result = safe_score(score)
        print(f"GRADE: {result} {type(result)}", flush=True)   # debug per maintainer advice
        return result

    except Exception as ex:
        print(f"GRADE ERROR (hard): {ex}", flush=True)
        return safe_score(0.001)
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
    Task 3: Ransomware Chain

    Score table (strictly in (0, 1)):
    ┌──────────────────────────────────────────┬───────┐
    │ Component                                │ Value │
    ├──────────────────────────────────────────┼───────┤
    │ base (always)                            │  0.10 │
    │ + containment ratio × 0.35              │  0–0.35│
    │ + early detection bonus (≥66% in ≤4 steps)│  0.20 │
    │ + efficiency bonus × 0.08               │  0–0.08│
    │ - false action penalty (capped at 0.43) │ −0.43 │
    ├──────────────────────────────────────────┼───────┤
    │ Max achievable  0.10+0.35+0.20+0.08 =   │  0.73 │  ← never hits 1.0
    │ Min (base − max penalty)                 │ −0.33 │  ← safe_score floors to 0.1
    └──────────────────────────────────────────┴───────┘
    """
    try:
        files = _get(state, "files") or []
        processes = _get(state, "processes") or []
        quarantined = set(_get(state, "quarantined_files") or [])
        killed = set(_get(state, "killed_processes") or [])
        flags = _get(state, "flags") or {}

        step_count = int(_get(state, "step_count", 0) or 0)
        max_steps = int(_get(state, "max_steps", 8) or 8)
        # Guard against divide-by-zero if max_steps is 0
        if max_steps == 0:
            max_steps = 8

        # True threat IDs — safe attribute access
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

        # Correctly handled threats
        correctly_quarantined = malicious_ids & quarantined
        correctly_killed = suspicious_ids & killed
        handled_files = len(correctly_quarantined)
        handled_procs = len(correctly_killed)

        # Unhandled threats still present in state
        remaining_malicious = sum(
            1 for f in files
            if _get(f, "is_malicious", False) and _get(f, "id") not in quarantined
        )
        remaining_suspicious = sum(
            1 for p in processes
            if _get(p, "suspicious", False) and _get(p, "id") not in killed
        )

        # Total threats ever = handled + remaining (no double-count)
        total_threats = max(
            handled_files + remaining_malicious + handled_procs + remaining_suspicious,
            1,
        )

        threats_handled = handled_files + handled_procs
        containment_ratio = min(threats_handled / total_threats, 1.0)

        # Full 0.0–1.0 efficiency range
        efficiency = max(0.0, 1.0 - (step_count / max_steps))

        # Early detection: meaningful containment achieved quickly
        early_bonus = 0.20 if (step_count <= 4 and containment_ratio >= 0.66) else 0.0

        # False action penalty — capped to preserve partial-credit gains
        false_count = int(flags.get("false_actions", 0) or 0)
        false_penalty = min(false_count * 0.2, 0.43)

        score = 0.10                            # base — always > 0
        score += 0.35 * containment_ratio       # containment credit
        score += early_bonus                    # speed bonus
        score += efficiency * 0.08             # efficiency bonus
        score -= false_penalty                  # false action penalty

        return safe_score(score)

    except Exception:
        return safe_score(0.1)
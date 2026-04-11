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
    Task 3: Ransomware Chain
    Raw score range: base=0.05 .. max=0.78, penalties capped so min>0.
    """
    try:
        files = _get(state, "files") or []
        processes = _get(state, "processes") or []
        quarantined = set(_get(state, "quarantined_files") or [])
        killed = set(_get(state, "killed_processes") or [])
        flags = _get(state, "flags") or {}

        step_count = int(_get(state, "step_count", 0) or 0)
        max_steps = int(_get(state, "max_steps", 8) or 8)
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
        correctly_killed = suspicious_ids & killed
        handled_files = len(correctly_quarantined)
        handled_procs = len(correctly_killed)

        remaining_malicious = sum(
            1 for f in files
            if _get(f, "is_malicious", False) and _get(f, "id") not in quarantined
        )
        remaining_suspicious = sum(
            1 for p in processes
            if _get(p, "suspicious", False) and _get(p, "id") not in killed
        )

        total_threats = max(
            handled_files + remaining_malicious + handled_procs + remaining_suspicious,
            1,
        )

        threats_handled = handled_files + handled_procs
        containment_ratio = min(threats_handled / total_threats, 1.0)

        efficiency = max(0.0, 1.0 - (step_count / max_steps))
        early_bonus = 0.20 if (step_count <= 4 and containment_ratio >= 0.66) else 0.0

        false_count = int(flags.get("false_actions", 0) or 0)
        # Cap penalty so score never drops below base (0.05)
        false_penalty = min(false_count * 0.2, 0.05)

        score = 0.05                              # base > 0
        score += 0.35 * containment_ratio         # containment credit
        score += early_bonus                      # speed bonus
        score += efficiency * 0.08                # efficiency bonus
        score -= false_penalty                    # capped penalty
        # Max = 0.05 + 0.35 + 0.20 + 0.08 = 0.68 (< 0.99)

        return safe_score(score)
    except Exception:
        return safe_score(0.05)
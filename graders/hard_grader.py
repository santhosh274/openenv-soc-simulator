"""
hard_grader.py — Task 3: Ransomware Chain

IMPROVEMENT 6: Partial-credit tiers
  Containment ratio is now broken into three bands:
    - Full containment  (ratio >= 1.0)   → full containment credit
    - Partial (0.5 ≤ ratio < 1.0)        → scaled partial credit
    - Minimal (0.0 < ratio < 0.5)        → reduced partial credit
    - Nothing handled                    → zero containment credit

  Sequence bonus: extra credit if files were quarantined BEFORE processes
  were killed (correct ransomware response order).

Score table (always strictly inside (0, 1)):
┌────────────────────────────────────────────────────┬───────┐
│ Component                                          │ Value │
├────────────────────────────────────────────────────┼───────┤
│ base (always)                                      │  0.10 │
│ containment tiers:                                 │       │
│   full   (ratio=1.0)                              │  0.32 │
│   partial (0.5–1.0) → 0.32 * ratio               │  0–0.32│
│   minimal (0–0.5)   → 0.14 * ratio               │  0–0.07│
│ correct sequence bonus (files before processes)    │  0.10 │
│ early detection bonus (≥66% in ≤4 steps)          │  0.18 │
│ efficiency bonus (0–1 range) × 0.07               │  0–0.07│
│ false action penalty (capped 0.40)                │ -0.40 │
├────────────────────────────────────────────────────┼───────┤
│ Max achievable  0.10+0.32+0.10+0.18+0.07 =        │  0.77 │ ← never 1.0
│ Min after safe_score                              │ 0.001 │ ← never 0.0
└────────────────────────────────────────────────────┴───────┘
"""
import math


def safe_score(score) -> float:
    try:
        val = float(score)
    except (TypeError, ValueError):
        return 0.001
    if math.isnan(val) or math.isinf(val):
        return 0.001
    val = max(0.001, min(0.999, val))
    if val <= 0.0: val = 0.001
    if val >= 1.0: val = 0.999
    return float(val)


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
    try:
        files       = _get(state, "files")              or []
        processes   = _get(state, "processes")          or []
        quarantined = set(_get(state, "quarantined_files") or [])
        killed      = set(_get(state, "killed_processes")  or [])
        flags       = _get(state, "flags")              or {}

        step_count = int(_get(state, "step_count", 0) or 0)
        max_steps  = int(_get(state, "max_steps",  8) or 8)
        if max_steps == 0:
            max_steps = 8

        # True threat IDs
        malicious_ids = {
            _get(f, "id") for f in files if _get(f, "is_malicious", False)
        }
        malicious_ids.discard(None)

        suspicious_ids = {
            _get(p, "id") for p in processes if _get(p, "suspicious", False)
        }
        suspicious_ids.discard(None)

        # Correctly handled
        correctly_quarantined = malicious_ids & quarantined
        correctly_killed      = suspicious_ids & killed
        handled_files = len(correctly_quarantined)
        handled_procs = len(correctly_killed)

        # Remaining threats (no double-count)
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

        # IMPROVEMENT 6: containment tiers instead of linear scaling
        if containment_ratio >= 1.0:
            containment_score = 0.32                         # full containment
        elif containment_ratio >= 0.5:
            containment_score = 0.32 * containment_ratio    # partial: scaled
        else:
            containment_score = 0.14 * containment_ratio    # minimal: reduced rate

        # IMPROVEMENT 6: sequence bonus — files quarantined before processes killed
        # (correct ransomware response: cut the source before killing the spawned process)
        files_handled_first = handled_files > 0 and (
            handled_procs == 0 or handled_files >= handled_procs
        )
        sequence_bonus = 0.10 if files_handled_first else 0.00

        efficiency  = max(0.0, 1.0 - (step_count / max_steps))
        early_bonus = 0.18 if (step_count <= 4 and containment_ratio >= 0.66) else 0.00

        false_count   = int(flags.get("false_actions", 0) or 0)
        false_penalty = min(false_count * 0.2, 0.40)

        score = (
            0.10
            + containment_score
            + sequence_bonus
            + early_bonus
            + efficiency * 0.07
            - false_penalty
        )

        result = safe_score(score)
        print(f"GRADE: {result} {type(result)}", flush=True)
        return result

    except Exception as ex:
        print(f"GRADE ERROR (hard): {ex}", flush=True)
        return safe_score(0.001)
"""
medium_grader.py — Task 2: Behavioral Attack

IMPROVEMENT 6: Partial-credit tiers
  Kill credit is now tiered:
    - Killed the RIGHT process (suspicious, ID-verified)    → full credit
    - Killed SOME process but wrong one                     → zero + false penalty
  Investigation is tiered by order:
    - Investigated BEFORE killing                          → full credit
    - Investigated AFTER killing                           → partial credit
  This rewards proper SOC triage (confirm → act).

Score table (always strictly inside (0, 1)):
┌──────────────────────────────────────────────────┬───────┐
│ Component                                        │ Value │
├──────────────────────────────────────────────────┼───────┤
│ base (always)                                    │  0.10 │
│ investigation tier:                              │       │
│   investigated BEFORE kill (correct order)      │  0.28 │
│   investigated AFTER kill  (wrong order)        │  0.11 │
│   not investigated                              │  0.00 │
│ kill tier:                                       │       │
│   suspicious process correctly killed           │  0.42 │
│   no correct kill                               │  0.00 │
│ false action penalty (capped)                   │ -0.34 │
├──────────────────────────────────────────────────┼───────┤
│ Max achievable  0.10+0.28+0.42 =                │  0.80 │ ← never 1.0
│ Min after safe_score                            │ 0.001 │ ← never 0.0
└──────────────────────────────────────────────────┴───────┘
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

        # IMPROVEMENT 6: investigation order tiers
        investigated         = bool(flags.get("investigated", False))
        investigation_before = bool(flags.get("investigated_before_action", False))

        if investigated and investigation_before:
            investigation_score = 0.28   # full: investigated before killing
        elif investigated:
            investigation_score = 0.11   # partial: investigated but after acting
        else:
            investigation_score = 0.00

        kill_score  = 0.42 if process_handled else 0.00
        false_count = int(flags.get("false_actions", 0) or 0)
        false_penalty = min(false_count * 0.17, 0.34)

        score = 0.10 + investigation_score + kill_score - false_penalty

        result = safe_score(score)
        print(f"GRADE: {result} {type(result)}", flush=True)
        return result

    except Exception as ex:
        print(f"GRADE ERROR (medium): {ex}", flush=True)
        return safe_score(0.001)
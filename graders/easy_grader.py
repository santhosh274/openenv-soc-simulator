"""
easy_grader.py — Task 1: Known Malware

IMPROVEMENT 6: Partial-credit tiers
  Previously each component was binary (did / didn't).
  Now investigation and quarantine are awarded in tiers based on ORDER,
  which reflects real SOC best-practice (triage before action).

Score table (always strictly inside (0, 1)):
┌──────────────────────────────────────────────────┬───────┐
│ Component                                        │ Value │
├──────────────────────────────────────────────────┼───────┤
│ base (always)                                    │  0.10 │
│ investigation tier:                              │       │
│   investigated BEFORE quarantine (correct order)│  0.30 │
│   investigated AFTER quarantine (wrong order)   │  0.12 │
│   not investigated at all                       │  0.00 │
│ quarantine tier:                                 │       │
│   malicious file correctly quarantined          │  0.40 │
│   no quarantine performed                       │  0.00 │
│ env containment flag bonus                      │  0.05 │
├──────────────────────────────────────────────────┼───────┤
│ Max achievable (correct order)  0.10+0.30+0.40+0.05 = 0.85 │ ← never 1.0
│ Min (base only)                               0.10 │ ← never 0.0
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
    """Safe dual-mode getter: attribute access → dict access → default."""
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

        # IMPROVEMENT 6: partial-credit tiers for investigation ORDER
        investigated         = bool(flags.get("investigated", False))
        investigation_before = bool(flags.get("investigated_before_action", False))

        if investigated and investigation_before:
            investigation_score = 0.30   # full credit: correct triage order
        elif investigated:
            investigation_score = 0.12   # partial credit: investigated but after acting
        else:
            investigation_score = 0.00   # no investigation

        quarantine_score = 0.40 if malicious_quarantined else 0.00
        env_bonus        = 0.05 if bool(flags.get("contained", False)) else 0.00

        score = 0.10 + investigation_score + quarantine_score + env_bonus

        result = safe_score(score)
        print(f"GRADE: {result} {type(result)}", flush=True)
        return result

    except Exception as ex:
        print(f"GRADE ERROR (easy): {ex}", flush=True)
        return safe_score(0.001)
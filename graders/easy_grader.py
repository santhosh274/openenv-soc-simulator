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
    This is the core fix — bare f.id / f.is_malicious access would crash
    if the env returns dict-like objects or renames fields, causing the
    grade() function to throw before safe_score() is ever reached.
    The benchmark then records 0.0 → validation fails.
    """
    try:
        # Try attribute access first (dataclass / namedtuple / object)
        return getattr(obj, attr, default)
    except Exception:
        pass
    try:
        # Fallback: dict-style access
        return obj[attr]
    except Exception:
        return default


def grade(state):
    """
    Task 1: Known Malware

    Score table (strictly in (0, 1)):
    ┌──────────────────────────────────────┬───────┐
    │ Component                            │ Value │
    ├──────────────────────────────────────┼───────┤
    │ base (always)                        │  0.10 │
    │ + investigated flag set              │  0.35 │
    │ + malicious file correctly quarantined│  0.44 │
    │ + env containment flag bonus         │  0.05 │
    ├──────────────────────────────────────┼───────┤
    │ Max achievable                       │  0.94 │  ← never hits 1.0
    │ Min (base only, before safe_score)   │  0.10 │  ← never hits 0.0
    └──────────────────────────────────────┴───────┘

    The entire function is wrapped in try/except so that ANY unexpected
    crash (AttributeError, TypeError, env API change, etc.) still returns
    a valid in-range score instead of propagating an exception that the
    benchmark records as 0.0.
    """
    try:
        files = _get(state, "files") or []
        quarantined = set(_get(state, "quarantined_files") or [])
        flags = _get(state, "flags") or {}

        # Collect IDs of truly malicious files using safe _get()
        malicious_ids = {
            _get(f, "id")
            for f in files
            if _get(f, "is_malicious", False)
        }
        # Remove None in case _get returned default
        malicious_ids.discard(None)

        # Credit only if a MALICIOUS file was quarantined (ID cross-checked)
        correctly_quarantined = malicious_ids & quarantined
        malicious_quarantined = len(correctly_quarantined) > 0

        # Independent env-level containment flag (may be set by escalate etc.)
        env_contained = bool(flags.get("contained", False))
        investigated = bool(flags.get("investigated", False))

        score = 0.10                                  # base — always > 0
        score += 0.35 * int(investigated)             # investigation credit
        score += 0.44 * int(malicious_quarantined)    # correct quarantine
        score += 0.05 * int(env_contained)            # env flag bonus

        return safe_score(score)

    except Exception:
        # Catch-all: any crash in grading logic still returns a valid score
        return safe_score(0.1)
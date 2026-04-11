"""
test_graders.py — Automated boundary + correctness tests for all three graders.
Run: python test_graders.py
"""
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from env.state import State
from env.models import Alert, FileSample, Process
from graders import easy_grader, medium_grader, hard_grader


# ─── Helpers ────────────────────────────────────────────────────────────────

def make_state(
    quarantined=None, killed=None,
    investigated=False, contained=False, early=False,
    false_actions=0, step_count=0, max_steps=8,
    files=None, processes=None
):
    s = State()
    s.quarantined_files = quarantined or []
    s.killed_processes = killed or []
    s.flags = {
        'investigated': investigated,
        'contained': contained,
        'early_detection': early,
        'false_actions': false_actions,
    }
    s.step_count = step_count
    s.max_steps = max_steps
    s.files = files or []
    s.processes = processes or []
    return s


def check_strict(score, label):
    """Assert score is exactly 0.0 or 1.0."""
    assert score == 0.0 or score == 1.0, f"FAIL [{label}]: score={score} is not 0.0 or 1.0"
    print(f"  PASS [{label}]: score={score}")


# ─── Easy Grader Tests ───────────────────────────────────────────────────────

def test_easy():
    print("\n[Easy Grader]")

    # Worst case: nothing done
    s = make_state()
    check_strict(easy_grader.grade(s), "nothing done")

    # Only investigated
    s = make_state(investigated=True)
    check_strict(easy_grader.grade(s), "investigated only")

    # Only quarantined
    s = make_state(quarantined=["F1"])
    check_strict(easy_grader.grade(s), "quarantined only")

    # Perfect: investigated + quarantined
    s = make_state(
        quarantined=["F1"], 
        investigated=True,
        files=[FileSample(id='F1', name='malware.exe', entropy=8.0, is_malicious=True)]
    )
    score = easy_grader.grade(s)
    check_strict(score, "perfect (investigated + quarantined)")
    assert score > 0.5, f"FAIL: perfect easy score should be > 0.5, got {score}"

    # Scores must differ between states
    s1 = make_state()
    s2 = make_state(
        quarantined=["F1"], 
        investigated=True,
        files=[FileSample(id='F1', name='malware.exe', entropy=8.0, is_malicious=True)]
    )
    assert easy_grader.grade(s1) != easy_grader.grade(s2), "FAIL: grader is constant"
    print("  PASS [non-constant]")


# ─── Medium Grader Tests ─────────────────────────────────────────────────────

def test_medium():
    print("\n[Medium Grader]")

    # Worst case: nothing done + heavy false actions
    s = make_state(false_actions=10)
    check_strict(medium_grader.grade(s), "nothing + 10 false")

    # Only investigated
    s = make_state(investigated=True)
    check_strict(medium_grader.grade(s), "investigated only")

    # Only killed
    s = make_state(killed=["P1"])
    check_strict(medium_grader.grade(s), "killed only")

    # Perfect: investigated + killed + no false
    s = make_state(
        killed=["P1"], 
        investigated=True, 
        false_actions=0,
        processes=[Process(id='P1', name='bad.exe', parent=None, suspicious=True)]
    )
    score = medium_grader.grade(s)
    check_strict(score, "perfect (killed + investigated)")
    assert score > 0.5, f"FAIL: perfect medium score should be > 0.5, got {score}"

    # Non-constant
    s1 = make_state(false_actions=10)
    s2 = make_state(
        killed=["P1"], 
        investigated=True,
        processes=[Process(id='P1', name='bad.exe', parent=None, suspicious=True)]
    )
    assert medium_grader.grade(s1) != medium_grader.grade(s2), "FAIL: grader is constant"
    print("  PASS [non-constant]")


# ─── Hard Grader Tests ───────────────────────────────────────────────────────

HARD_FILES = [
    FileSample(id="F1", name="ransom.exe", entropy=8.1, is_malicious=True),
    FileSample(id="F2", name="data.bin",   entropy=7.5, is_malicious=True),
    FileSample(id="F3", name="normal.txt", entropy=3.1, is_malicious=False),
]
HARD_PROCS = [
    Process(id="P1", name="encrypter.exe", parent="F1", suspicious=True),
]

def test_hard():
    print("\n[Hard Grader]")

    # Worst case: nothing done, 10 false, max steps
    s = make_state(false_actions=10, step_count=8, max_steps=8,
                   files=HARD_FILES, processes=HARD_PROCS)
    check_strict(hard_grader.grade(s), "nothing + 10 false")

    # All threats handled early
    s = make_state(
        quarantined=["F1", "F2"], killed=["P1"],
        step_count=3, max_steps=8, false_actions=0,
        files=HARD_FILES,
        processes=HARD_PROCS
    )
    score = hard_grader.grade(s)
    check_strict(score, "all threats handled early")
    assert score > 0.4, f"FAIL: perfect hard score should be > 0.4, got {score}"

    # Partial: 1 of 3 threats handled
    s = make_state(
        quarantined=["F1"], step_count=5, max_steps=8,
        files=[HARD_FILES[1], HARD_FILES[2]],
        processes=HARD_PROCS
    )
    check_strict(hard_grader.grade(s), "partial (1/3 threats)")

    # Non-constant
    s1 = make_state(false_actions=10, files=HARD_FILES, processes=HARD_PROCS)
    s2 = make_state(
        quarantined=["F1", "F2"], killed=["P1"],
        step_count=3, max_steps=8, false_actions=0,
        files=HARD_FILES,
        processes=HARD_PROCS
    )
    assert hard_grader.grade(s1) != hard_grader.grade(s2), "FAIL: grader is constant"
    print("  PASS [non-constant]")

    # Exhaustive: try all combinations of step_count and false_actions
    print("  Running exhaustive boundary sweep...")
    for sc in range(0, 9):
        for fa in range(0, 12):
            s = make_state(
                quarantined=["F1", "F2"], killed=["P1"],
                step_count=sc, max_steps=8, false_actions=fa,
                files=[HARD_FILES[2]], processes=[]
            )
            score = hard_grader.grade(s)
            check_strict(score, f"exhaustive sc={sc} fa={fa}")


# ─── Run All ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Grader Boundary Tests")
    print("=" * 55)
    try:
        test_easy()
        test_medium()
        test_hard()
        print("\n" + "=" * 55)
        print("  ALL TESTS PASSED ✓")
        print("=" * 55)
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ {e}")
        sys.exit(1)

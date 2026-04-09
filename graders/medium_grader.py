def grade(state):
    """
    Task 2: Behavioral Attack
    Score components (always strictly between 0 and 1):
      - base:          0.05  (always, prevents 0.0)
      - process_kill: +0.42  (a SUSPICIOUS process was killed — ID cross-checked)
      - investigation:+0.42  (process was investigated)
      - false_penalty: up to -0.34 (capped; clamp handles any remaining floor risk)
      Max achievable:  0.89  (never hits 1.0)
      Min achievable:  0.001 (after clamp, never hits 0.0)

    FIX vs original:
      - Previously `process_handled` was True even if a BENIGN process was
        killed (len(state.killed_processes) > 0).
      - Now we cross-check killed process IDs against actually suspicious
        process IDs so benign kills do not earn the process_kill bonus.
      - Note: the false_penalty cap of 0.34 means worst-case math is
        0.05 - 0.34 = -0.29, which the clamp safely floors to 0.001.
        This is intentional — the clamp IS the final floor guarantee.
    """
    # IDs of processes that are truly suspicious in this scenario
    suspicious_ids = {p.id for p in state.processes if p.suspicious}

    # Credit only if at least one SUSPICIOUS process was killed
    correctly_killed = suspicious_ids & set(state.killed_processes)
    process_handled = len(correctly_killed) > 0

    investigated = state.flags.get("investigated", False)
    false_count = state.flags.get("false_actions", 0)

    # Cap penalty so it cannot exceed the maximum positive gain (0.42 + 0.42 = 0.84)
    # 0.34 cap means even max false actions still leave room for meaningful scoring
    false_penalty = min(false_count * 0.17, 0.34)

    score = 0.05  # base — always > 0
    score += 0.42 * int(process_handled)
    score += 0.42 * int(investigated)
    score -= false_penalty

    # Strict clamp: guarantees 0 < score < 1 under all circumstances
    score = max(0.001, min(0.999, score))
    return round(score, 4)
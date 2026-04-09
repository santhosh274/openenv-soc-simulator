def grade(state):
    """
    Task 2: Behavioral Attack
    Score components (always strictly between 0 and 1):
      - base:         0.05  (always, prevents 0.0)
      - process_kill:+0.42  (suspicious process was killed)
      - investigation:+0.42 (process was investigated)
      - false_penalty: up to -0.34 (scaled, capped so floor >= -0.29 before clamp)
      Max achievable: 0.89  (never hits 1.0)
      Min achievable: 0.01  (after clamp, never hits 0.0)
    """
    process_handled = len(state.killed_processes) > 0
    investigated = state.flags.get("investigated", False)
    false_count = state.flags.get("false_actions", 0)

    # Cap penalty so it cannot eat more than the positive gains
    false_penalty = min(false_count * 0.17, 0.34)

    score = 0.05  # base — always > 0
    score += 0.42 * int(process_handled)
    score += 0.42 * int(investigated)
    score -= false_penalty

    # Safety clamp — handles heavy false-action edge cases
    score = max(0.01, min(0.99, score))
    return round(score, 4)
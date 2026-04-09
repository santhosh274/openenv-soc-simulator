def grade(state):
    """
    Task 1: Known Malware
    Score components (always strictly between 0 and 1):
      - base:         0.05  (always, prevents 0.0)
      - containment: +0.44  (quarantine performed or contained flag set)
      - investigation:+0.45 (file was investigated before containment)
      Max achievable: 0.94  (never hits 1.0)
      Min achievable: 0.05  (never hits 0.0)
    """
    direct_contained = len(state.quarantined_files) > 0 or state.flags.get('contained', False)
    investigated = state.flags.get("investigated", False)

    score = 0.05  # base — always > 0
    score += 0.44 * int(direct_contained)
    score += 0.45 * int(investigated)

    # Safety clamp — should never be needed with the above budgets
    score = max(0.01, min(0.99, score))
    return round(score, 4)
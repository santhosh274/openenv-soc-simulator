def grade(state):
    # Direct containment (quarantine or escalate) without prior investigation is still valid
    direct_contained = len(state.quarantined_files) > 0
    investigated = state.flags.get("investigated", False)
    
    # 0.5 for direct containment, +0.49 if investigated first
    score = 0.5 * int(direct_contained)
    if investigated:
        score += 0.49
    elif direct_contained:
        score = 0.5
    
    # Strictly between 0 and 1: (0.01, 0.99)
    return max(0.01, min(0.99, score))
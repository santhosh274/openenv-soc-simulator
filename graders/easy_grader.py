def grade(state):
    # Direct containment (quarantine or escalate) without prior investigation is still valid
    direct_contained = len(state.quarantined_files) > 0
    investigated = state.flags.get("investigated", False)
    
    # 0.5 for direct containment, +0.5 if investigated first
    score = 0.5 * int(direct_contained)
    if investigated:
        score += 0.5
    # But if quarantined something, at least get 0.5 even without formal investigation
    elif direct_contained:
        score = 0.5
    
    return max(0.0, min(1.0, score))

def grade(state):
    """
    Task 1: Known Malware
    Score components (always strictly between 0 and 1):
      - base:          0.05  (always, prevents 0.0)
      - containment:  +0.44  (a MALICIOUS file was quarantined — ID cross-checked)
      - investigation:+0.45  (file was investigated before containment)
      Max achievable:  0.94  (never hits 1.0)
      Min achievable:  0.05  (before clamp; clamp floor is 0.001)

    FIX vs original:
      - Previously `direct_contained` was True even if a BENIGN file was
        quarantined (len(state.quarantined_files) > 0).
      - Now we cross-check quarantined file IDs against actually malicious
        file IDs so false-positive quarantines do not earn the containment bonus.
    """
    # IDs of files that are truly malicious in this scenario
    malicious_ids = {f.id for f in state.files if f.is_malicious}

    # Containment is only credited when at least one MALICIOUS file was quarantined
    correctly_quarantined = malicious_ids & set(state.quarantined_files)
    direct_contained = len(correctly_quarantined) > 0 or state.flags.get("contained", False)

    investigated = state.flags.get("investigated", False)

    score = 0.05  # base — always > 0
    score += 0.44 * int(direct_contained)
    score += 0.45 * int(investigated)

    # Strict clamp: guarantees 0 < score < 1 under all circumstances
    score = max(0.001, min(0.999, score))
    return round(score, 4)
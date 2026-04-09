def grade(state):
    """
    Task 3: Ransomware Chain
    Score components (always strictly between 0 and 1):
      - base:             0.05  (always, prevents 0.0)
      - containment:     +0.38 * ratio   (threats handled / total threats)
      - early_detection: +0.27  (contained within first 4 steps)
      - efficiency:      +0.08 * eff     (steps remaining ratio, small bonus)
      - false_penalty:   up to -0.58 (capped)
      Max achievable: 0.05 + 0.38 + 0.27 + 0.08 = 0.78  (never hits 1.0)
      Min achievable: 0.01 (after clamp, never hits 0.0)
    """
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.58)

    # Efficiency: bonus for resolving quickly (0.0 to 1.0 range)
    efficiency = max(0.0, 1.0 - (state.step_count / state.max_steps) * 0.1)

    malicious_files_quarantined = len(state.quarantined_files)
    suspicious_processes_killed = len(state.killed_processes)

    # Derive total threats from scenario so hardcoding doesn't cause issues
    total_malicious = sum(1 for f in state.files if f.is_malicious)
    total_suspicious = sum(1 for p in state.processes if p.suspicious)
    # Also count already-quarantined malicious files and killed suspicious processes
    total_threats = max(malicious_files_quarantined + total_malicious +
                        suspicious_processes_killed + total_suspicious, 1)

    threats_handled = malicious_files_quarantined + suspicious_processes_killed
    containment_ratio = min(threats_handled / total_threats, 1.0)

    score = 0.05  # base — always > 0
    score += 0.38 * containment_ratio

    if state.step_count <= 4 and containment_ratio >= 0.66:
        score += 0.27

    score -= false_penalty
    score += efficiency * 0.08

    # Strict clamp to ensure 0 < score < 1
    score = max(0.001, min(0.999, score))
    return round(score, 4)
def grade(state):
    score = 0.0
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.6)
    efficiency = 1.0 - (state.step_count / state.max_steps) * 0.1

    # Count how many malicious components were handled
    malicious_files_quarantined = len(state.quarantined_files)  # Assuming all quarantined are malicious
    suspicious_processes_killed = len(state.killed_processes)
    
    # Full containment: all malicious files and processes handled
    total_threats = 3  # F1, F2, P1 in hard scenario
    threats_handled = malicious_files_quarantined + suspicious_processes_killed
    
    containment_ratio = min(threats_handled / total_threats, 1.0)
    score += 0.4 * containment_ratio
    
    # Early detection bonus (within 4 steps)
    if state.step_count <= 4 and containment_ratio >= 0.66:  # At least 2/3 threats handled early
        score += 0.3
    
    score -= false_penalty
    score += efficiency * 0.1

    return max(0.0, min(1.0, score))


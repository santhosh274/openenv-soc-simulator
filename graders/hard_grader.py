def grade(state):
    score = 0.0
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.6)
    efficiency = 1.0 - (state.step_count / state.max_steps) * 0.1

    malicious_files_quarantined = len(state.quarantined_files)
    suspicious_processes_killed = len(state.killed_processes)
    
    total_threats = 3
    threats_handled = malicious_files_quarantined + suspicious_processes_killed
    
    containment_ratio = min(threats_handled / total_threats, 1.0)
    score += 0.39 * containment_ratio
    
    if state.step_count <= 4 and containment_ratio >= 0.66:
        score += 0.29
    
    score -= false_penalty
    score += efficiency * 0.09

    # Strictly between 0 and 1: (0.01, 0.99)
    return max(0.01, min(0.99, score))
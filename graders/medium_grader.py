def grade(state):
    # Task 2: Behavioral Attack - process focus
    process_handled = len(state.killed_processes) > 0
    investigated = state.flags.get("investigated", False)
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.6)

    # Max score: 0.49 + 0.49 = 0.98
    score = 0.49 * int(process_handled) + 0.49 * int(investigated) - false_penalty
    # Strictly between 0 and 1: (0.01, 0.99)
    return max(0.01, min(0.99, score))
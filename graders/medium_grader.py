def grade(state):
    # Task 2: Behavioral Attack - process focus
    process_handled = len(state.killed_processes) > 0
    investigated = state.flags.get("investigated", False)
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.6)

    score = 0.4 * int(process_handled) + 0.4 * int(investigated) - false_penalty
    return max(0.0, min(1.0, score))


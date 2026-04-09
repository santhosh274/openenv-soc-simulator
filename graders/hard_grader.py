def grade(state):
    """
    Task 3: Ransomware Chain
    Score components (always strictly between 0 and 1):
      - base:             0.05  (always, prevents 0.0)
      - containment:     +0.38 * ratio   (correctly handled threats / total threats)
      - early_detection: +0.27           (contained >= 66% within first 4 steps)
      - efficiency:      +0.08 * eff     (steps-remaining bonus, range 0.0–1.0)
      - false_penalty:   up to -0.58     (capped)
      Max achievable: 0.05 + 0.38 + 0.27 + 0.08 = 0.78  (never hits 1.0)
      Min achievable: 0.001 (after clamp, never hits 0.0)

    FIX vs original:
      1. DOUBLE-COUNT BUG FIXED:
         Original used:
           total_threats = malicious_files_quarantined + total_malicious
                         + suspicious_processes_killed + total_suspicious
         This double-counted already-handled threats because state.files /
         state.processes still contain items after action (or counts remaining
         vs handled depending on env implementation). The correct approach is:

           total_threats = total that EVER existed = (quarantined + remaining malicious)
                           + (killed + remaining suspicious)

         We derive "remaining" from state directly, so:
           total_malicious_ever = quarantined_malicious + remaining_malicious
           total_suspicious_ever = killed_suspicious + remaining_suspicious

      2. EFFICIENCY RANGE FIXED:
         Original:  efficiency = 1.0 - (step_count / max_steps) * 0.1
         This gives a range of 0.9–1.0, so efficiency * 0.08 only varies
         by 0.008 — practically noise. Fixed to full 0.0–1.0 range:
           efficiency = 1.0 - (step_count / max_steps)
         so efficiency * 0.08 now ranges 0.0–0.08 meaningfully.

      3. CORRECT CONTAINMENT RATIO:
         Only correctly handled threats count (malicious quarantined,
         suspicious killed) — not all kills/quarantines regardless of target.
    """
    # --- Identify true threat IDs ---
    malicious_ids = {f.id for f in state.files if f.is_malicious}
    suspicious_ids = {p.id for p in state.processes if p.suspicious}

    # --- Correctly handled threats ---
    correctly_quarantined = malicious_ids & set(state.quarantined_files)
    correctly_killed = suspicious_ids & set(state.killed_processes)

    malicious_files_quarantined = len(correctly_quarantined)
    suspicious_processes_killed = len(correctly_killed)

    # --- Remaining (unhandled) threats still in state ---
    # Files/processes still present in state that haven't been handled
    remaining_malicious = sum(
        1 for f in state.files
        if f.is_malicious and f.id not in state.quarantined_files
    )
    remaining_suspicious = sum(
        1 for p in state.processes
        if p.suspicious and p.id not in state.killed_processes
    )

    # FIX: total threats = correctly handled + still remaining (no double-count)
    total_malicious_ever = malicious_files_quarantined + remaining_malicious
    total_suspicious_ever = suspicious_processes_killed + remaining_suspicious
    total_threats = max(total_malicious_ever + total_suspicious_ever, 1)

    threats_handled = malicious_files_quarantined + suspicious_processes_killed
    containment_ratio = min(threats_handled / total_threats, 1.0)

    # FIX: Full 0.0–1.0 efficiency range (original was 0.9–1.0, nearly useless)
    efficiency = max(0.0, 1.0 - (state.step_count / state.max_steps))

    # Early detection: meaningful containment achieved quickly
    early_detection_bonus = (
        0.27
        if state.step_count <= 4 and containment_ratio >= 0.66
        else 0.0
    )

    # False action penalty capped to prevent runaway negative scores
    false_penalty = min(state.flags.get("false_actions", 0) * 0.2, 0.58)

    score = 0.05  # base — always > 0
    score += 0.38 * containment_ratio
    score += early_detection_bonus
    score += efficiency * 0.08
    score -= false_penalty

    # Strict clamp: guarantees 0 < score < 1 under all circumstances
    score = max(0.001, min(0.999, score))
    return round(score, 4)
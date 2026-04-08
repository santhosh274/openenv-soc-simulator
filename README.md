---
title: Security Incident SOC
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
---

# Security Incident SOC Environment

A deterministic SOC incident response simulation for OpenEnv.
Agents act as security analysts responding to malware, behavioral attacks,
and ransomware incidents.

## What It Does

Agents analyze security alerts, investigate files/processes, and contain
threats. The environment tests decision-making under realistic constraints.

## Three Tasks

| Task | Difficulty | Scenario |
|------|------------|----------|
| easy_known_malware | Easy | Single malware file - quarantine it |
| medium_behavioral_attack | Medium | Suspicious process - kill it |
| hard_ransomware_chain | Hard | Multiple files + processes - contain all |

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Run server
python app.py

# Or run inference
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
export HF_TOKEN="your-token"
python inference.py
```

## Environment Variables

- API_BASE_URL - LLM endpoint (default: https://router.huggingface.co/v1)
- MODEL_NAME - Model ID (default: Qwen/Qwen2.5-72B-Instruct)
- HF_TOKEN - Required - your API key

## Action Space

- investigate_file(id) / investigate_process(id) - Gather evidence
- quarantine_file(id) / kill_process(id) - Contain threat
- ignore_alert() / escalate() - Handle false positives

## Output Format

[START] task=easy_known_malware env=security-incident-soc model=Qwen...
[STEP] step=1 action=quarantine_file('F1') reward=0.70 done=false error=null
[END] success=true steps=2 rewards=0.70,0.00

## Baseline Scores (Qwen/Qwen2.5-72B-Instruct)

- Easy: ~0.50
- Medium: ~0.80
- Hard: ~0.79

## Deploy to Hugging Face Spaces

openenv validate  # Check readiness
openenv push      # Deploy to HF

## Tech Stack

- Python 3.10+
- FastAPI, Pydantic, OpenAI client
- Docker for containerization
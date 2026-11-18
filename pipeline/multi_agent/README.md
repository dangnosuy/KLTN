# Multi-agent role-playing C transformation baseline

This baseline implements a pure multi-agent collaboration architecture (Baseline 7) without evolutionary algorithms (NSGA-II). Three specialized agents coordinate iteratively:

1. **Planner Agent:** Analyzes detector evaluation logs and source structure to formulate tactical evasion instructions.
2. **Coder Agent:** Implements the complete C program according to the plan.
3. **Reviewer Agent:** Validates semantic preservation, syntax correctness, and payload integrity prior to compilation. If changes are requested, the Coder performs an immediate targeted refinement.

## Usage

```bash
python3 -m pipeline.multi_agent doctor \
  --base-url http://127.0.0.1:20128/v1 \
  --model 'cf/@cf/qwen/qwen3.8-27b'

python3 -m pipeline.multi_agent run input.c \
  --output multi-agent-output/run-001 \
  --base-url http://127.0.0.1:20128/v1 \
  --model 'cf/@cf/qwen/qwen3.8-27b' \
  --target ember \
  --max-attempts 5 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember'
```

Outputs are `original.c`, every `attempts/attempt-NNN.c`, `plans.jsonl`, `reviews.jsonl`, `attempts.jsonl`, `best.c`, and `result.json`.

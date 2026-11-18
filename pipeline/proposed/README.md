# Proposed Model: C2 Adaptive Coordinator + NSGA-II + LLM Reflexion

This module implements the proposed model (Baseline 9) for thesis research.

## Architecture

The framework reconciles multi-objective evolutionary optimization with targeted LLM reasoning:

1. **NSGA-II Multi-Objective Engine:**
   - Simultaneously optimizes two conflicting objectives:
     - **Objective 1 (Evasion Fitness):** Maximize detector clean score ($f_1 \in [0, 1]$).
     - **Objective 2 (Compactness / Anti-Bloat):** Maximize size efficiency ratio $\min(1.0, \frac{\text{size}(original)}{\text{size}(candidate)}) \in (0, 1]$.
   - Maintains an explicit Pareto Front using Fast Non-dominated Sorting and Crowding Distance assignment.

2. **C2 Adaptive Cost-Aware Coordinator:**
   - Monitors generation dynamics:
     - **Stagnation Trigger:** Detects when the 2D Hypervolume does not improve for $K$ consecutive generations ($\Delta HV < 0.005$).
     - **Failure Rate Trigger:** Detects when $\ge 50\%$ of candidates fail compilation or runtime verification.
     - **Budget Gate:** Strictly caps LLM calls to `max_llm_calls` to guarantee resource efficiency.
   - When stagnation/failure is detected and budget remains, C2 triggers the **LLM Reflexion Agent** to synthesize an innovative operator recipe that breaks out of local optima.
   - Otherwise, the system operates purely via NSGA-II (zero token expenditure).

## Usage

```bash
# Doctor check
python3 -m pipeline.proposed doctor \
  --pool pipeline/ga_only/operator_pool.example.json \
  --model 'cf/@cf/qwen/qwen2.5-coder-32b-instruct'

# Run proposed model
python3 -m pipeline.proposed run dataset/advanced/sources/baseline/local_exec_xor.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output proposed-output/local-exec-r01 \
  --population-size 8 \
  --generations 5 \
  --stagnation-patience 2 \
  --max-llm-calls 4 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines clamav,ember' \
  --seed 42
```

Outputs include `candidates/`, `evaluations.jsonl`, `c2_decisions.jsonl`, `best.c`, and `result.json` (containing full Pareto Front and hypervolume history).

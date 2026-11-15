# Bandit source transformation baseline

This baseline adapts MAB-Malware to C source transformations. Each Tigress operator is an independent Beta-distributed arm. Thompson sampling chooses one arm at a time; a target-detector bypass increments alpha, while detection or failure increments beta. A successful trace is minimized by deleting redundant actions and rescanning.

It is independent from the GA baseline: there is no population, crossover, mutation, or generation.

## Usage

```bash
python3 -m pipeline.bandit doctor \
  --pool pipeline/ga_only/operator_pool.example.json

python3 -m pipeline.bandit run input.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output bandit-output/run-001 \
  --target ember \
  --budget 32 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember' \
  --seed 42
```

Outputs are `original.c`, every `attempts/attempt-NNN.c`, `evaluations.jsonl`, `best.c`, `bandit-state` inside `result.json`, and—only after a successful bypass—`minimized.c`.


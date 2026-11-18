# Random Search C source transformation baseline

This baseline implements uniform random search (Monte Carlo perturbation) over C source transformations, as referenced in TransForge (Table 13), GAMMA, and AOP-Mal. In each attempt, it selects $k$ operators uniformly at random from the Tigress pool without memory, fitness guidance, or probability updates.

## Usage

```bash
python3 -m pipeline.random_search doctor \
  --pool pipeline/ga_only/operator_pool.example.json

python3 -m pipeline.random_search run input.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output random-output/run-001 \
  --target ember \
  --budget 32 \
  --k-actions 2 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember' \
  --seed 42
```

Outputs are `original.c`, every `attempts/attempt-NNN.c`, `evaluations.jsonl`, `best.c`, and `result.json`.

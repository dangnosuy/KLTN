# Heuristic source transformation baseline

This baseline applies one fixed recipe to every C source. It performs no random search, fitness-guided choice, population evolution, or detector-feedback update. Each intermediate stage is preserved, then only the final source is compiled and scored.

```bash
python3 -m pipeline.heuristic doctor \
  --pool pipeline/ga_only/operator_pool.example.json

python3 -m pipeline.heuristic run input.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --recipe pipeline/heuristic/recipe.example.json \
  --output heuristic-output/run-001 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember'
```

The output contains `original.c`, every `stages/stage-NNN-operator.c`, `final.c`, and `result.json` with per-stage size growth and the final static evaluation.


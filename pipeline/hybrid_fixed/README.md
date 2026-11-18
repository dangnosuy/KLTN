# Fixed hybrid baseline (EoH-inspired)

This baseline keeps a population of executable operator recipes. Each heuristic
contains an EoH-style natural-language `thought`, a `genes` recipe, and detector
`fitness`. GA creates most offspring with crossover and mutation; a fixed fraction
is created by the LLM in every generation, including initialization.

The LLM cycles through EoH's fixed E1, E2, M1, M2, and M3 prompt strategies. It
may only choose operators already present in the shared pool. There is no
stagnation detector, adaptive coordinator, or cost-aware trigger.

```bash
python3 -m pipeline.hybrid_fixed doctor \
  --pool pipeline/ga_only/operator_pool.example.json

python3 -m pipeline.hybrid_fixed run dataset/advanced/sources/baseline/local_exec.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output hybrid-fixed-output/local-exec-r01 \
  --population-size 8 --generations 5 --llm-fraction 0.25 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember'
```

Outputs include all `candidates/`, `evaluations.jsonl`, EoH thought/recipe records
in `llm_heuristics.jsonl`, the selected `best.c`, and `result.json`.

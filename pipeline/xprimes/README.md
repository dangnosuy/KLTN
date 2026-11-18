# xPriMES: Dual-Environment Reinforcement Learning Baseline

This baseline adapts the xPriMES methodology (InSecLab UIT) for C source transformations:
- **Dual-environment interaction**: LightGBM surrogate (EMBER) provides continuous confidence feedback for dense reward shaping ($r_{\text{dense}} = \max(0, s_{t-1} - s_t)$), while the target detector provides binary feedback for episode termination and final bypass reward.
- **Thompson sampling**: Balances exploration and exploitation across Tigress transformation operators.
- **SHAP-guided prioritized replay**: Past mutation transitions are replayed according to surrogate drop magnitude and feature attribution impact.

## Usage

```bash
python3 -m pipeline.xprimes doctor \
  --pool pipeline/ga_only/operator_pool.example.json

python3 -m pipeline.xprimes run input.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output xprimes-output/run-001 \
  --target ember \
  --budget 32 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember' \
  --seed 42
```

Outputs are `original.c`, every `attempts/attempt-NNN.c`, `evaluations.jsonl`, `best.c`, arm statistics inside `result.json`, and—after bypass—`minimized.c`.

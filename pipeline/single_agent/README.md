# Reflexion single-agent C baseline

This baseline follows the programming loop from Reflexion: one LLM generates a
complete C implementation, grounded evaluator feedback is collected, and the
same LLM writes a verbal reflection before revising the previous implementation.
It does not use Tigress or an operator pool.

The original source is scored once before generation. Every reflection receives
the baseline score, current score, and deltas from the baseline and previous
attempt so it can distinguish improvement from regression.

The LLM is called through the local OpenAI-compatible HTTP endpoint. The
generated PE is only compiled and scanned by the supplied score command; this
pipeline does not execute it on the Linux host.

```bash
python3 -m pipeline.single_agent doctor \
  --base-url http://127.0.0.1:20128/v1 \
  --model 'cf/@cf/qwen/qwen3.8-27b'

python3 -m pipeline.single_agent run input.c \
  --output single-agent-output/run-001 \
  --base-url http://127.0.0.1:20128/v1 \
  --model 'cf/@cf/qwen/qwen3.8-27b' \
  --target ember \
  --max-attempts 5 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember'
```

Outputs are `original.c`, every `attempts/attempt-NNN.c`, `attempts.jsonl`,
`reflections.jsonl`, `best.c`, and `result.json`. A successful run means the
configured target detector returned a completed result with `detected=false`;
otherwise `best.c` is only the highest-fitness attempt observed.

Quoted local headers are copied into the run directory at the same relative
location expected by the generated candidate, so includes such as
`../common/payload.h` continue to resolve after the source is relocated.

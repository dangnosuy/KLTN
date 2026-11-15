# Reflexion single-agent C baseline

This baseline follows the programming loop from Reflexion: one LLM generates a
complete C implementation, grounded evaluator feedback is collected, and the
same LLM writes a verbal reflection before revising the previous implementation.
It does not use Tigress or an operator pool.

The LLM runs through local Ollama. The generated PE is only compiled and scanned
by the supplied score command; this pipeline does not execute it on the Linux
host.

```bash
ollama serve
ollama pull qwen2.5-coder:7b

python3 -m pipeline.single_agent doctor --model qwen2.5-coder:7b

python3 -m pipeline.single_agent run input.c \
  --output single-agent-output/run-001 \
  --model qwen2.5-coder:7b \
  --target ember \
  --max-attempts 5 \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source} --engines ember'
```

Outputs are `original.c`, every `attempts/attempt-NNN.c`, `attempts.jsonl`,
`reflections.jsonl`, `best.c`, and `result.json`. A successful run means the
configured target detector returned a completed result with `detected=false`;
otherwise `best.c` is only the highest-fitness attempt observed.

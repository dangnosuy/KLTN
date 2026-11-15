# GA-only source transformation baseline

This module evolves ordered Tigress transformation chains over one C source file and writes every generated C candidate. It does not execute samples or call detectors itself: a score command evaluates each generated source and prints JSON containing a finite `fitness` value.

The evolutionary configuration follows TransForge (population 8, tournament 3, uniform crossover 0.70, mutation 0.20, five generations). Its implementation is dependency-free but follows the same population/evaluation structure as the public GAMMA engine in `pralab/secml_malware`.

## Inputs and outputs

- Input: one `.c` file, an operator-pool JSON, and a score command.
- Output: `original.c`, every `candidates/generation-NNN/candidate-NNN.c`, `best.c`, and `result.json`.

The score command receives `{source}` and must print one JSON object:

```json
{"fitness": 0.75, "build": "PASSED", "detectors": {"ember": "NO_ALERT"}}
```

## Usage

```bash
python3 -m pipeline.ga_only doctor --pool pipeline/ga_only/operator_pool.example.json

python3 -m pipeline.ga_only run input.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output ga-output/run-001 \
  --score-command 'python3 score_candidate.py {source}' \
  --seed 42
```

Copy the example pool and change `functions` to functions present in the input. `doctor` must resolve the configured Tigress binary before a run starts.

## Local static scoring demo

Compile and scan the harmless example without running it:

```bash
~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score \
  pipeline/ga_only/examples/hello.c
```

The scorer reuses the existing ClamAV and EMBER adapters. Fitness is the mean clean score: ClamAV contributes `1` for no detection and `0` for detection; EMBER contributes `1 - score`.

Use it for a GA run with:

```bash
python3 -m pipeline.ga_only run pipeline/ga_only/examples/hello.c \
  --pool pipeline/ga_only/operator_pool.example.json \
  --output ga-output/hello-static \
  --score-command '~/Documents/venv/bin/python3 -m pipeline.ga_only.static_score {source}' \
  --seed 42
```

Tigress is an external research tool and is intentionally not installed or vendored by this repository. Pin its version and license separately in the experiment manifest.

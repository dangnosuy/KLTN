# Repository Guidelines

## Project Structure & Module Organization

Malware detection benchmark monorepo.
- `pipeline/detectors/`: Active 5-engine evaluation pipeline (`clamav`, `ember`, `malconv`, `defender` offline CLI, `cape` dynamic). Entrypoint: `python3 -m pipeline.detectors`.
- `pipeline/vmrun_pipeline.py` & `pipeline/single_revert/`: Direct VMware `vmrun` automation for Elastic Defend, Wazuh, Defender snapshots (`elastic`, `wazuh`, `normal_real`).
- `pipeline/run_pipeline.py`: Legacy SMB/watcher 8-engine orchestrator (`pipeline/unified_server.py` on port `8002` + Windows `pipeline/unified_win_agent.py`).
- `pipeline/tests/`: Unit tests (100% mock-based, no VM/live services needed).
- `dataset/advanced/build/` & `dataset/v2/`: Test sample repositories. DLL companions require a sibling `manifest.json` defining `{"samples": {"loader.exe": {"companions": ["payload.dll"]}}}`.
- `Signature-base/`: Offline models (EMBER LightGBM, MalConv h5, SOREL), ClamAV scripts, YARA rules.
- `Behavior-base/`, `Elastic-Defend/`, `Wazuh-Defend/`: Per-engine legacy watchdog listeners and agents (ports 8000–8003).
- `heldout/`: CAPE behavior scoring policy (`heldout/cape_behavior_score.py`) reused by `pipeline.detectors`.
- `phantom-forge/`: Payload builder and test-case generators.

## Essential Commands

Execute from workspace root:

```bash
# 1. Run all unit tests (fast, mock-based, no external dependencies)
python3 -m unittest discover -s pipeline/tests -p 'test_*.py'

# 2. Run single test file or case
python3 -m unittest pipeline.tests.test_detectors
python3 -m unittest pipeline.tests.test_detectors.DetectorsPipelineTests.test_runner_all_pass

# 3. Active 5-Engine Pipeline (requires ML venv at ~/Documents/venv)
source ~/Documents/venv/bin/activate
# Local-only check (no VM or CAPE needed):
python3 -m pipeline.detectors doctor --engines clamav,ember,malconv
python3 -m pipeline.detectors run dataset/advanced/build/crt_inject.exe --engines clamav,ember,malconv --campaign static-r01

# Full 5-engine run (requires VMware VM on snapshot 'normal_real' + CAPE on http://localhost:8000):
source pipeline/vmrun.env.example  # or custom vmrun.env
python3 -m pipeline.detectors doctor --config pipeline/detectors/config.example.json
python3 -m pipeline.detectors run dataset/advanced/build/ --config pipeline/detectors/config.example.json --campaign thesis-r01

# 4. Direct VMRun dynamic EDR pipeline
set -a; source pipeline/vmrun.env.example; set +a
python3 pipeline/vmrun_pipeline.py doctor --campaign test-doc
python3 pipeline/vmrun_pipeline.py run dataset/advanced/build --campaign thesis-r01 --engines elastic,wazuh,defender
```

## Critical Quirks & Guardrails

- **Active Pipeline vs Legacy**: Primary pipeline is `python3 -m pipeline.detectors`. Do NOT run legacy VMware SMB watchers simultaneously on the same VM.
- **Python Environment**: ML static workers (EMBER, MalConv) strictly require `~/Documents/venv/bin/python3` (LightGBM, TensorFlow, NumPy, thrember). Do not upgrade or auto-install inside pipeline runs.
- **Staging & Quarantines**: Defender CLI uses custom staging `C:\DetectorScans` with exclusion. `-DisableRemediation` outputs detection to stdout; exit code 2 is scan error, not detection.
- **Companion DLLs**: Handled strictly via sibling `manifest.json`. Never guess DLLs or glob loose files. Samples with `benchmark_ready: false` in manifest are excluded during directory scans.
- **Credentials & Safety**: VM credentials stay in local env files (`VMRUN_VMX`, `VM_GUEST_USER`, `VM_GUEST_PASSWORD`, `CAPE_API_TOKEN`). Never commit credentials, binaries, or telemetry reports. Never execute samples on Linux host.
- **Test Style**: Write all new unit tests under `pipeline/tests/test_*.py` using standard `unittest` and `unittest.mock`. Keep tests hermetic without real VM or network dependencies.

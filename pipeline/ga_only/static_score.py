from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from pipeline.detectors.core import digest, load_config
from pipeline.detectors.static import StaticScanner


def score_source(source: Path, engines=("clamav", "ember"), compiler="x86_64-w64-mingw32-gcc"):
    source = Path(source).resolve()
    if not source.is_file() or source.suffix.lower() != ".c":
        raise ValueError(f"Expected an existing .c source: {source}")
    resolved_compiler = shutil.which(compiler)
    if not resolved_compiler:
        raise FileNotFoundError(f"Compiler not found: {compiler}")

    with tempfile.TemporaryDirectory(prefix="ga-static-score-") as temporary:
        executable = Path(temporary) / "candidate.exe"
        built = subprocess.run(
            [resolved_compiler, "-O2", "-Wl,--no-insert-timestamp", str(source), "-o", str(executable)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if built.returncode or not executable.is_file():
            return {
                "fitness": 0.0,
                "build": "BUILD_FAIL",
                "compiler_stderr": built.stderr[-1500:],
            }

        scanner = StaticScanner(load_config())
        artifact = {"path": str(executable)}
        reports = {engine: scanner.scan(engine, artifact) for engine in engines}
        failures = {engine: report for engine, report in reports.items() if report["status"] != "COMPLETED"}
        if failures:
            raise RuntimeError("Static scanner failure: " + "; ".join(f"{engine}={report.get('error', report['status'])}" for engine, report in failures.items()))

        components = []
        for engine, report in reports.items():
            components.append(1.0 - report["score"] if "score" in report else float(not report["detected"]))
        evidence_keys = ("status", "verdict", "detected", "score", "threshold", "threat_names")
        evidence = {engine: {key: report[key] for key in evidence_keys if key in report} for engine, report in reports.items()}
        return {
            "fitness": sum(components) / len(components),
            "build": "PASSED",
            "pe_sha256": digest(executable),
            "detectors": evidence,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compile one C candidate and score it with local static detectors")
    parser.add_argument("source", type=Path)
    parser.add_argument("--engines", default="clamav,ember")
    parser.add_argument("--compiler", default="x86_64-w64-mingw32-gcc")
    args = parser.parse_args(argv)
    engines = tuple(item.strip() for item in args.engines.split(",") if item.strip())
    if not engines or set(engines) - {"clamav", "ember"}:
        parser.error("--engines must contain clamav and/or ember")
    try:
        print(json.dumps(score_source(args.source, engines, args.compiler), allow_nan=False), flush=True)
        return 0
    except Exception as error:
        print(f"ERROR: {error}", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

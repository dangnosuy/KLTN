from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from pipeline.detectors.core import ROOT, digest, load_config
from pipeline.detectors.static import StaticScanner


def score_source(source: Path, engines=("clamav", "ember"), compiler="x86_64-w64-mingw32-gcc"):
    source = Path(source).resolve()
    if not source.is_file() or source.suffix.lower() != ".c":
        raise ValueError(f"Expected an existing .c source: {source}")
    resolved_compiler = shutil.which(compiler)
    if not resolved_compiler:
        raise FileNotFoundError(f"Compiler not found: {compiler}")

    with tempfile.TemporaryDirectory(prefix="ga-static-score-") as temporary:
        target = source.stem
        for t in ("local_exec_xor", "unhook_exec_xor", "classic_dll_injection", "process_hollow", "map_view_xor", "local_exec", "map_view"):
            if t in str(source):
                target = t
                break
        executable = Path(temporary) / f"{target}.exe"
        # Use -O1 for large Tigress outputs to prevent GCC compilation timeouts while still producing valid binaries
        opt_flag = "-O1" if source.stat().st_size > 2_000_000 else "-O2"
        inc_args = []
        default_inc = ROOT / "dataset/advanced/sources/baseline"
        if default_inc.is_dir():
            inc_args.extend(["-I", str(default_inc)])
        if source.parent.is_dir():
            inc_args.extend(["-I", str(source.parent)])

        built = subprocess.run(
            [
                resolved_compiler,
                opt_flag,
                *inc_args,
                "-s",
                "-fno-ident",
                "-Wl,--strip-all",
                "-Wl,--no-insert-timestamp",
                str(source),
                "-o",
                str(executable),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if built.returncode or not executable.is_file():
            return {
                "fitness": 0.0,
                "build": "BUILD_FAIL",
                "compiler_stderr": built.stderr[-1500:],
            }

        config = load_config()
        scanner = StaticScanner(config)
        artifact = {"path": str(executable)}
        reports = {}
        for engine in engines:
            if engine == "cape":
                from pipeline.detectors.cape import CapeScanner
                from pipeline.detectors.core import json_hash
                cape_scanner = CapeScanner(config)
                sha = digest(executable)
                artifacts = [{"name": executable.name, "role": "primary", "path": str(executable), "sha256": sha}]
                for dll in source.parent.glob("*.dll"):
                    dll_target = Path(temporary) / dll.name
                    if not dll_target.exists():
                        shutil.copyfile(dll, dll_target)
                    artifacts.append({
                        "name": dll.name,
                        "role": "companion",
                        "path": str(dll_target),
                        "sha256": digest(dll_target),
                    })
                sample = {
                    "name": executable.name,
                    "artifacts": artifacts,
                    "package_sha256": json_hash([{k: a[k] for k in ("name", "role", "sha256")} for a in artifacts]),
                }
                reports["cape"] = cape_scanner.scan(sample, Path(temporary) / "cape")
            else:
                reports[engine] = scanner.scan(engine, artifact)
        failures = {engine: report for engine, report in reports.items() if report["status"] != "COMPLETED"}
        if failures:
            raise RuntimeError("Scanner failure: " + "; ".join(f"{engine}={report.get('error', report['status'])}" for engine, report in failures.items()))

        components = []
        for engine, report in reports.items():
            if engine == "cape":
                components.append(1.0 - (report["score"] / 10.0) if "score" in report else float(not report["detected"]))
            else:
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
    parser.add_argument("--engines", default="clamav,ember,malconv")
    parser.add_argument("--compiler", default="x86_64-w64-mingw32-gcc")
    args = parser.parse_args(argv)
    engines = tuple(item.strip() for item in args.engines.split(",") if item.strip())
    valid_engines = {"clamav", "ember", "malconv", "cape"}
    if not engines or set(engines) - valid_engines:
        parser.error(f"--engines must contain only {', '.join(sorted(valid_engines))}")
    try:
        print(json.dumps(score_source(args.source, engines, args.compiler), allow_nan=False), flush=True)
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

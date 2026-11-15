"""Dataset metadata, isolated control builds, and evidence-gated releases."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(WORKSPACE))
from pipeline.detectors.core import digest, package, write_json

HOME = Path(__file__).resolve().parent
EXPECTED = b"dataset-v2:0123456789abcdef\n"


def catalog():
    data = json.loads((HOME / "catalog.json").read_text())
    ids = set()
    for entry in data["programs"]:
        name = entry["id"]
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name in ids:
            raise ValueError("Invalid or duplicate program ID")
        ids.add(name)
    tracks = data.get("research_tracks", [])
    track_ids = set()
    for track in tracks:
        track_id = track.get("id")
        if not isinstance(track_id, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", track_id) or track_id in track_ids:
            raise ValueError("Invalid or duplicate research track ID")
        if not isinstance(track.get("legacy"), list) or not all(isinstance(item, str) and item.endswith(".exe") for item in track["legacy"]):
            raise ValueError("Invalid research track legacy mapping")
        track_ids.add(track_id)
    return data["programs"]


def research_tracks():
    data = json.loads((HOME / "catalog.json").read_text())
    catalog()
    legacy_names = set(json.loads((ROOT / "advanced/build/manifest.json").read_text())["samples"])
    for track in data["research_tracks"]:
        unknown = set(track["legacy"]) - legacy_names
        if unknown:
            raise ValueError("Research track references unknown legacy sample")
    return data["research_tracks"]


def contract(entry):
    return {"schema_version": 1, "program_id": entry["id"], "timeout_seconds": 15,
            "working_directory": "fresh per-run directory; no pre-existing result.txt",
            "expected_exit_code": 0, "expected_files": {"result.txt": hashlib.sha256(EXPECTED).hexdigest()},
            "network": "forbidden", "cleanup": "terminate owned processes and remove run directory",
            "mechanism": entry["id"], "self_report_is_sufficient": False}


def audit():
    legacy = json.loads((ROOT / "advanced/build/manifest.json").read_text())
    selected = {entry.get("legacy") for entry in catalog()}
    rows = []
    for name, entry in legacy["samples"].items():
        source = (ROOT / "advanced/build" / entry["source"]).resolve()
        action = "pilot_review" if name in selected else "archive"
        if name in ("api_hash_djb2.exe", "peb_walk.exe"):
            action = "support_variant"
        if name == "mockingjay.exe":
            action = "environment_specific_reserve"
        rows.append({"name": name, "technique": entry["technique"], "fidelity": entry["fidelity"],
                     "legacy_ready": entry["benchmark_ready"], "v2_action": action,
                     "source_sha256": digest(source), "companions": entry["companions"],
                     "split": "development", "v2_ready": False,
                     "provenance": "unverified; review upstream license before redistribution"})
    return {"schema_version": 2, "programs": rows}


def coverage():
    return {"schema_version": 1, "tracks": research_tracks()}


def build_controls(output):
    if not Path("/.dockerenv").exists():
        raise ValueError("Build is container-only; use the documented docker command")
    image = os.getenv("BUILD_IMAGE_ID", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("BUILD_IMAGE_ID must identify the pinned compiler container")
    if output.exists():
        raise ValueError("Output already exists; choose a new build ID")
    output.parent.mkdir(parents=True, exist_ok=True)
    compiler = "x86_64-w64-mingw32-gcc"
    flags = ["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-Wno-cast-function-type", "-Wl,--no-insert-timestamp"]
    sources = sorted([*HOME.glob("programs/*.c"), *HOME.glob("common/*.h"), HOME / "manage.py"])
    metadata = {"schema_version": 2, "architecture": "x86_64", "profile": "controls-O0", "build_image_id": image,
                "compiler": subprocess.check_output([compiler, "--version"], text=True),
                "linker": subprocess.check_output(["x86_64-w64-mingw32-ld", "--version"], text=True),
                "source_date_epoch": os.getenv("SOURCE_DATE_EPOCH"),
                "sources": {str(p.relative_to(HOME)): digest(p) for p in sources}, "commands": [], "samples": {}}
    with tempfile.TemporaryDirectory(dir=output.parent, prefix=".staging-") as temporary:
        stage = Path(temporary)
        def compile_file(source, name, extra=()):
            command = [compiler, *flags, *extra, str(HOME / source), "-o", str(stage / name)]
            run = subprocess.run(command, text=True, capture_output=True, timeout=120)
            metadata["commands"].append({"argv": [part.replace(str(stage), "<build>") for part in command], "stdout": run.stdout, "stderr": run.stderr, "returncode": run.returncode})
            if run.returncode:
                raise RuntimeError(f"Build failed for {name}: {run.stderr}")
        compile_file("programs/fixture_dll.c", "fixture.dll", ["-shared"])
        for entry in catalog():
            if entry["role"] != "control":
                continue
            name = entry["id"] + ".exe"
            compile_file(entry["source"], name)
            metadata["samples"][name] = {"program_id": entry["id"], "group": entry["group"], "split": "development",
                "role": "control", "benchmark_ready": False, "companions": entry["companions"]}
            write_json(stage / (entry["id"] + ".contract.json"), contract(entry))
        metadata["artifact_hashes"] = {p.name: digest(p) for p in stage.iterdir() if p.suffix in (".exe", ".dll")}
        write_json(stage / "manifest.json", metadata)
        stage.rename(output)


def verify_receipts(sample, contract_path, receipts, approval):
    contract_hash = digest(contract_path)
    if approval.get("package_sha256") != sample["package_sha256"] or approval.get("contract_sha256") != contract_hash or approval.get("mechanism_reviewed") is not True or not approval.get("reviewer"):
        raise ValueError("Missing hash-bound independent mechanism review")
    runs = set()
    hashes = {item["name"]: item["sha256"] for item in sample["artifacts"]}
    for receipt in receipts:
        if not isinstance(receipt.get("run_id"), str) or not receipt["run_id"] or receipt["run_id"] in runs:
            raise ValueError("C1 run IDs must be unique and nonempty")
        runs.add(receipt["run_id"])
        if receipt.get("status") != "PASS" or receipt.get("artifact_hashes") != hashes or receipt.get("contract_sha256") != contract_hash or not receipt.get("environment_id"):
            raise ValueError("C1 receipt failed or does not match artifacts/contract/environment")
    if len(runs) < 3:
        raise ValueError("At least three independent C1 runs are required")


def export_release(build, evidence, destination):
    if destination.exists():
        raise ValueError("Release exists; choose a new ID")
    manifest = json.loads((build / "manifest.json").read_text())
    allowed = {entry["id"] for entry in catalog() if entry["role"] == "control"}
    if not manifest.get("samples"):
        raise ValueError("Empty build")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix=".release-") as temporary:
        stage = Path(temporary)
        for name, entry in manifest["samples"].items():
            if entry.get("program_id") not in allowed or name != entry["program_id"] + ".exe":
                raise ValueError("V2 currently exports reviewed benign controls only; seeds require a separate audit")
            sample = package(build / name)
            proof = json.loads((evidence / (entry["program_id"] + ".json")).read_text())
            contract_path = build / (entry["program_id"] + ".contract.json")
            verify_receipts(sample, contract_path, proof["runs"], proof["approval"])
            for artifact in sample["artifacts"]:
                if manifest["artifact_hashes"].get(artifact["name"]) != artifact["sha256"]:
                    raise ValueError("Build artifact hash changed")
                shutil.copyfile(artifact["path"], stage / artifact["name"])
            shutil.copyfile(contract_path, stage / contract_path.name)
            write_json(stage / (entry["program_id"] + ".evidence.json"), proof)
            entry["benchmark_ready"] = True
        write_json(stage / "manifest.json", manifest)
        stage.rename(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("audit", "coverage", "build-controls", "export"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.action == "audit":
        print(json.dumps(audit(), indent=2))
    elif args.action == "coverage":
        print(json.dumps(coverage(), indent=2))
    elif args.action == "build-controls":
        if not args.output: parser.error("--output required")
        build_controls(args.output)
    else:
        if not all((args.build, args.evidence, args.output)): parser.error("--build, --evidence, --output required")
        export_release(args.build, args.evidence, args.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)

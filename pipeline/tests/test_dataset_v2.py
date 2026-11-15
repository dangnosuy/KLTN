import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from pipeline.detectors.runner import directory_inputs
from pipeline.detectors.core import digest, package, write_json
from pipeline.tests.test_detectors import make_exe

spec = importlib.util.spec_from_file_location("dataset_manager", Path(__file__).resolve().parents[2] / "dataset/v2/manage.py")
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class DatasetTests(unittest.TestCase):
    def test_control_build_publishes_atomically_and_failure_leaves_no_output(self):
        original_exists = Path.exists
        def exists(path):
            return str(path) == "/.dockerenv" or original_exists(path)
        def compile_file(command, **kwargs):
            output = Path(command[command.index("-o") + 1])
            make_exe(output)
            return subprocess.CompletedProcess(command, 0, "", "")
        with tempfile.TemporaryDirectory() as temporary, patch.object(Path, "exists", exists), patch.dict("os.environ", {"BUILD_IMAGE_ID": "sha256:" + "a" * 64}), patch.object(manager.subprocess, "check_output", return_value="pinned version"), patch.object(manager.subprocess, "run", side_effect=compile_file):
            output = Path(temporary) / "good"
            manager.build_controls(output)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(len(manifest["samples"]), 4)
            self.assertTrue(all(not e["benchmark_ready"] for e in manifest["samples"].values()))
            with self.assertRaises(ValueError): manager.build_controls(output)
            with patch.object(manager.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "compile error")):
                with self.assertRaises(RuntimeError): manager.build_controls(Path(temporary) / "bad")
            self.assertTrue(output.exists())
            self.assertFalse((Path(temporary) / "bad").exists())
            self.assertFalse(list(Path(temporary).glob(".staging-*")))

    def test_catalog_and_audit(self):
        entries = manager.catalog()
        self.assertEqual(sum(e["role"] == "seed" for e in entries), 8)
        self.assertEqual(sum(e["role"] == "control" for e in entries), 4)
        audit = manager.audit()["programs"]
        self.assertGreaterEqual(len(audit), 21)
        self.assertTrue(all(not e["v2_ready"] for e in audit))
        tracks = {track["id"]: track for track in manager.research_tracks()}
        self.assertEqual(len(tracks), 10)
        self.assertEqual(tracks["native_api_resolution"]["status"], "resolver_only")
        self.assertEqual(tracks["process_hollowing"]["scope"], "archive_pending_review")

    def test_directory_filter_and_legacy_compatibility(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b = make_exe(root / "a.exe"), make_exe(root / "b.exe")
            self.assertEqual(directory_inputs(root), [a, b])
            write_json(root / "manifest.json", {"samples": {"b.exe": {"benchmark_ready": False}}})
            self.assertEqual(directory_inputs(root), [a])
            package(b)  # Direct diagnostic input remains supported.
            write_json(root / "manifest.json", {"samples": {"b.exe": {"benchmark_ready": "false"}}})
            with self.assertRaises(ValueError): directory_inputs(root)

    def test_export_requires_bound_three_run_evidence_and_is_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build, evidence, output = root / "build", root / "evidence", root / "release"
            build.mkdir(); evidence.mkdir()
            exe = make_exe(build / "direct_fixture.exe")
            contract = build / "direct_fixture.contract.json"
            write_json(contract, {"expected": "fixture"})
            write_json(build / "manifest.json", {"samples": {exe.name: {"program_id": "direct_fixture", "benchmark_ready": False, "companions": []}}, "artifact_hashes": {exe.name: digest(exe)}})
            sample = package(exe)
            run = {"status": "PASS", "artifact_hashes": {exe.name: digest(exe)}, "contract_sha256": digest(contract), "environment_id": "isolated-test-vm"}
            approval = {"package_sha256": sample["package_sha256"], "contract_sha256": digest(contract), "mechanism_reviewed": True, "reviewer": "unit-test"}
            proof = {"approval": approval, "runs": [{**run, "run_id": str(i)} for i in range(2)]}
            proof_path = evidence / "direct_fixture.json"
            write_json(proof_path, proof)
            with self.assertRaises(ValueError): manager.export_release(build, evidence, output)
            self.assertFalse(output.exists())
            proof["runs"].append({**run, "run_id": "2"})
            proof["runs"][0]["status"] = "UNDETERMINED"
            write_json(proof_path, proof)
            with self.assertRaises(ValueError): manager.export_release(build, evidence, output)
            proof["runs"][0]["status"] = "PASS"
            write_json(proof_path, proof)
            manager.export_release(build, evidence, output)
            self.assertTrue(json.loads((output / "manifest.json").read_text())["samples"][exe.name]["benchmark_ready"])
            self.assertFalse(json.loads((build / "manifest.json").read_text())["samples"][exe.name]["benchmark_ready"])
            with self.assertRaises(ValueError): manager.export_release(build, evidence, output)

    def test_wrong_hash_duplicate_runs_and_review_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            contract = Path(temporary) / "contract.json"
            write_json(contract, {})
            sample = {"package_sha256": "package", "artifacts": [{"name": "a.exe", "sha256": "abc"}]}
            approval = {"package_sha256": "package", "contract_sha256": digest(contract), "mechanism_reviewed": True, "reviewer": "test"}
            run = {"run_id": "1", "status": "PASS", "artifact_hashes": {"a.exe": "abc"}, "contract_sha256": digest(contract), "environment_id": "vm"}
            with self.assertRaises(ValueError): manager.verify_receipts(sample, contract, [run] * 3, approval)
            with self.assertRaises(ValueError): manager.verify_receipts(sample, contract, [], {**approval, "mechanism_reviewed": False})
            with self.assertRaises(ValueError): manager.verify_receipts(sample, contract, [{**run, "artifact_hashes": {"a.exe": "wrong"}}], approval)

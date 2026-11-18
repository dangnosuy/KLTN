import base64
import copy
import hashlib
import io
import json
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from pipeline.detectors.__main__ import main
from pipeline.detectors.cape import CapeScanner, bundle, score_task
from pipeline.detectors.core import DEFAULTS, ENGINES, digest, failed, load_config, package, probability, result, unchanged, validate_pe, write_json
from pipeline.detectors.defender import DefenderScanner, parse_scan, validate_health
from pipeline.detectors.runner import DetectorRunner, aggregate, lock
from pipeline.detectors.static import StaticScanner, parse_clamav
from pipeline.detectors.vmware import VMwareSettings, VMwareTransport


def make_exe(path, extra=b""):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<HH", data, 68, 0x8664, 1)
    struct.pack_into("<HH", data, 84, 112, 2)
    data[88:90] = b"\x0b\x02"
    path.write_bytes(data + extra)
    return path


def report_for(sample, task_id=7, sha=None, score=4):
    return {
        "info": {"id": task_id, "version": "2.5", "options": {"file": sample["name"]}},
        "target": {"file": {"sha256": sha or sample["sha256"]}},
        "malscore": 10,
        "behavior": {
            "processtree": [{"name": sample["name"], "pid": 42, "children": [{"name": "cmd.exe", "pid": 43}]}],
            "processes": [{"process_id": 42, "calls": [{"api": "Test"}]}, {"process_id": 43, "calls": []}],
        },
        "signatures": [{"name": "runtime_rule", "severity": score + 1, "confidence": 100, "weight": 1, "categories": ["execution"], "data": [{"pid": 42, "cid": 0}]}],
    }


class InputAndConfigTests(unittest.TestCase):
    def test_defaults_and_example_match(self):
        path = Path(__file__).resolve().parents[1] / "detectors/config.example.json"
        example = load_config(path)
        self.assertEqual(example["cape"]["threshold"], 4)
        self.assertEqual(example["static"]["malconv_threshold"], 0.5)

    def test_config_rejects_unknown_fields_secrets_and_invalid_thresholds(self):
        cases = [{"password": "secret"}, {"static": {"sorel": True}}, {"cape": {"threshold": float("nan")}}, {"static": {"ember_threshold": 2}}, {"cape": {"timeout": 0}}, {"cape": {"verify_tls": False}}, {"cape": {"url": "http://remote.example/"}}, {"cape": {"url": "https://user:secret@example.com"}}, {"defender": {"staging_dir": "C:\\"}}]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            for value in cases:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(ValueError):
                        load_config(path)

    def test_invalid_and_dll_pe_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = make_exe(Path(temporary) / "a.exe")
            validate_pe(path)
            data = bytearray(path.read_bytes())
            struct.pack_into("<H", data, 86, 0x2002)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                validate_pe(path)
            path.write_bytes(b"MZ")
            with self.assertRaises(ValueError):
                validate_pe(path)

    def test_manifest_companions_missing_duplicate_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exe = make_exe(root / "a.exe")
            for companion in ("missing.dll", "../other.dll", "A.exe", "x.dll,file=a.exe", "x.dll."):
                write_json(root / "manifest.json", {"samples": {"a.exe": {"companions": [companion]}}})
                with self.subTest(companion=companion), self.assertRaises(ValueError):
                    package(exe)

    def test_package_identity_includes_companion_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exe = make_exe(root / "a.exe")
            dll = root / "p.dll"
            dll.write_bytes(b"first")
            write_json(root / "manifest.json", {"samples": {"a.exe": {"companions": ["p.dll"]}}})
            first = package(exe)
            dll.write_bytes(b"second")
            second = package(exe)
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertNotEqual(first["package_sha256"], second["package_sha256"])
            with self.assertRaises(ValueError):
                unchanged(first)

    def test_probabilities_and_threshold_boundaries(self):
        self.assertTrue(probability(0.5, 0.5)["detected"])
        self.assertFalse(probability(0.49999999, 0.5)["detected"])
        for value in (float("nan"), float("inf"), -1, 2, True, "0.9"):
            with self.assertRaises(ValueError):
                probability(value, 0.5)
        self.assertIsNone(failed("broken")["detected"])


class StaticTests(unittest.TestCase):
    def test_clamav_exit_codes_and_evidence(self):
        self.assertFalse(parse_clamav(0, "x.exe: OK\n")["detected"])
        self.assertTrue(parse_clamav(1, "x.exe: Win.Test FOUND\n")["detected"])
        for code, text in ((2, "error"), (0, ""), (1, ""), (0, "x.exe: Win.Test FOUND")):
            self.assertIsNone(parse_clamav(code, text)["detected"])

    def test_worker_failure_is_not_no_alert(self):
        scanner = StaticScanner(load_config())
        with patch("pipeline.detectors.static.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "load failed")):
            response = scanner.scan("malconv", {"path": "a.exe"})
        self.assertEqual(response["status"], "ERROR")
        self.assertIsNone(response["detected"])

    def test_aggregate_companion_detection_and_partial_failure(self):
        hit = result(True, name="p.dll", role="companion")
        clean = result(False, name="a.exe", role="primary")
        self.assertTrue(aggregate([clean, hit])["detected"])
        mixed = aggregate([hit, failed("timeout")])
        self.assertIsNone(mixed["detected"])
        self.assertEqual(mixed["status"], "ERROR")


class DefenderTests(unittest.TestCase):
    def test_vmware_transport_keeps_guest_credentials_outside_host_commands(self):
        settings = VMwareSettings(Path("/tmp/test.vmx"), "guest", "secret", "vm-secret", 1)
        transport = VMwareTransport(settings)
        host_command = transport._command("listSnapshots")
        guest_command = transport._command("checkToolsState", guest=True)
        self.assertNotIn("guest", host_command)
        self.assertNotIn("secret", host_command)
        self.assertIn("guest", guest_command)
        self.assertIn("secret", guest_command)

    def health(self):
        return {"service_enabled": True, "antivirus_enabled": True, "scanner": "C:\\Trusted\\MpCmdRun.exe", "maps_reporting": 0, "sample_consent": 2, "block_at_first_seen_disabled": True, "exclusions": ["C:\\DetectorScans"], "engine_version": "1", "signature_version": "2", "platform_version": "3"}

    def test_cli_parser_requires_positive_scan_evidence(self):
        self.assertFalse(parse_scan(0, "Scan finished.\nScanning x found no threats.")["detected"])
        self.assertTrue(parse_scan(2, "Threat : Trojan:Win32/Test\n")["detected"])
        for code, output in ((2, "Scan error: failed"), (0, ""), (2, ""), (1, "Threat : Test")):
            self.assertIsNone(parse_scan(code, output)["detected"])

    def test_offline_policy_is_required_without_changing_it(self):
        good = self.health()
        validate_health(good, "C:\\DetectorScans")
        for field, value in (("maps_reporting", 1), ("sample_consent", 1), ("block_at_first_seen_disabled", False), ("exclusions", []), ("service_enabled", False)):
            changed = {**good, field: value}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate_health(changed, "C:\\DetectorScans")

    def test_static_scan_only_and_single_revert(self):
        scanner = DefenderScanner(load_config())
        scanner.vm = Mock()
        scanner.vm.run_powershell.side_effect = [
            '{"sha256":"abc"}', '{"pid":99}',
            '{"returncode":0,"stdout":"Scan finished. found no threats.","stderr":""}', 'removed',
            '{"sha256":"abc"}', '{"pid":100}',
            '{"returncode":2,"stdout":"Threat : Test","stderr":""}', 'removed',
        ]
        health = self.health()
        version = validate_health(health, "C:\\DetectorScans")
        with patch.object(scanner, "health", return_value=(health, version)):
            self.assertFalse(scanner.scan({"name": "a.exe", "path": "/tmp/a.exe", "sha256": "abc"})["detected"])
            self.assertTrue(scanner.scan({"name": "b.exe", "path": "/tmp/b.exe", "sha256": "abc"})["detected"])
        scanner.vm.revert.assert_called_once_with("normal_real")
        scanner.vm.launch.assert_not_called()
        launches = [item.args[0] for item in scanner.vm.run_powershell.call_args_list if "-EncodedCommand" in item.args[0]]
        for launch in launches:
            token = launch.split("-EncodedCommand ", 1)[1].split("'", 1)[0]
            script = base64.b64decode(token).decode("utf-16le")
            self.assertIn("-Scan -ScanType 3 -File", script)
            self.assertIn("-DisableRemediation", script)
            self.assertIn("$result=try", script)
            self.assertNotIn("Set-MpPreference", script)

    def test_cleanup_failure_poison_session(self):
        scanner = DefenderScanner(load_config())
        scanner.vm = Mock()
        scanner.vm.run_powershell.side_effect = ['{"sha256":"wrong"}', RuntimeError("locked")]
        with patch.object(scanner, "health", return_value=(self.health(), {})), self.assertRaisesRegex(RuntimeError, "cleanup"):
            scanner.scan({"name": "a.exe", "path": "/tmp/a.exe", "sha256": "abc"})
        self.assertTrue(scanner.poisoned)
        self.assertEqual(scanner.scan({})["status"], "INFRA_FAILURE")

    def test_timeout_kills_only_scanner_helper_and_poisons_session(self):
        scanner = DefenderScanner(load_config())
        scanner.vm = Mock()
        scanner.vm.run_powershell.side_effect = ['{"sha256":"abc"}', '{"pid":99}', '', 'removed']
        with patch.object(scanner, "health", return_value=(self.health(), {})), patch("pipeline.detectors.defender.time.monotonic", side_effect=[0, 1000]):
            with self.assertRaises(TimeoutError):
                scanner.scan({"name": "a.exe", "path": "/tmp/a.exe", "sha256": "abc"})
        commands = [call.args[0] for call in scanner.vm.run_powershell.call_args_list]
        self.assertTrue(any("taskkill.exe /PID 99 /T /F" in command for command in commands))
        self.assertTrue(scanner.poisoned)


class CapeTests(unittest.TestCase):
    def test_runtime_threshold_and_ignored_static_score(self):
        sample = {"name": "a.exe", "sha256": "abc", "artifacts": [{}]}
        report = report_for(sample, score=4)
        response = score_task(report, sample, 7, "abc", 4)
        self.assertTrue(response["detected"])
        self.assertEqual(response["behavior_verdict"], "SUSPICIOUS")
        report["signatures"] = [{"name": "binary_yara", "severity": 10, "data": [{"pid": 42, "cid": 0}], "categories": ["static"]}]
        response = score_task(report, sample, 7, "abc", 4)
        self.assertFalse(response["detected"])
        self.assertEqual(response["score"], 0)
        self.assertEqual(response["cape_malscore"], 10)

    def test_mismatched_task_hash_entrypoint(self):
        sample = {"name": "a.exe", "sha256": "abc", "artifacts": [{}, {}]}
        for change in ("hash", "task", "entry"):
            report = report_for(sample)
            if change == "hash":
                report["target"]["file"]["sha256"] = "wrong"
            elif change == "task":
                report["info"]["id"] = 8
            else:
                report["info"]["options"] = {"file": "other.exe"}
            with self.subTest(change=change), self.assertRaises(ValueError):
                score_task(report, sample, 7, "abc", 4)

    def test_background_or_missing_telemetry_is_infrastructure_failure(self):
        sample = {"name": "a.exe", "sha256": "abc", "artifacts": [{}]}
        for change in ("tree", "name", "calls", "pid"):
            report = report_for(sample)
            if change == "tree":
                report["behavior"]["processtree"] = []
            elif change == "name":
                report["behavior"]["processtree"][0]["name"] = "unrelated.exe"
            elif change == "calls":
                report["behavior"]["processes"][0]["calls"] = []
            else:
                report["behavior"]["processes"][0]["process_id"] = 1234
            with self.subTest(change=change):
                response = score_task(report, sample, 7, "abc", 4)
                self.assertEqual(response["status"], "INFRA_FAILURE")
                self.assertIsNone(response["detected"])

    def test_signature_from_unrelated_pid_is_not_counted(self):
        sample = {"name": "a.exe", "sha256": "abc", "artifacts": [{}]}
        report = report_for(sample)
        report["signatures"][0]["data"][0]["pid"] = 9999
        self.assertEqual(score_task(report, sample, 7, "abc", 4)["score"], 0)

    def test_zip_is_deterministic_and_includes_companion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exe = make_exe(root / "a.exe")
            (root / "p.dll").write_bytes(b"dll")
            write_json(root / "manifest.json", {"samples": {"a.exe": {"companions": ["p.dll"]}}})
            sample = package(exe)
            first = bundle(sample)
            self.assertEqual(first, bundle(sample))
            self.assertEqual(first[2:], ("zip", "file=a.exe"))
            with zipfile.ZipFile(io.BytesIO(first[1])) as archive:
                self.assertEqual(archive.namelist(), ["a.exe", "p.dll"])
                self.assertEqual(hashlib.sha256(archive.read("a.exe")).hexdigest(), sample["sha256"])

    def test_resume_does_not_resubmit_existing_cape_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = package(make_exe(root / "a.exe"))
            scanner = CapeScanner(load_config())
            with patch.object(scanner, "request", side_effect=[{"data": {"task_ids": [7]}}, {"data": "failed_analysis"}]) as request:
                first = scanner.scan(sample, root / "evidence")
                self.assertEqual(first["status"], "INFRA_FAILURE")
                self.assertEqual(request.call_args_list[0].args[0], "POST")
            with patch.object(scanner, "request", side_effect=[{"data": "reported"}, report_for(sample)]) as request:
                second = scanner.scan(sample, root / "evidence")
                self.assertTrue(second["detected"])
                self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))
            scanner.close()

    def test_ambiguous_submit_is_not_automatically_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = package(make_exe(root / "a.exe"))
            scanner = CapeScanner(load_config())
            with patch.object(scanner, "request", side_effect=TimeoutError("network")):
                with self.assertRaises(TimeoutError):
                    scanner.scan(sample, root / "evidence")
            with patch.object(scanner, "request") as request:
                with self.assertRaisesRegex(RuntimeError, "uncertain"):
                    scanner.scan(sample, root / "evidence")
                request.assert_not_called()
            scanner.close()

    def test_poll_timeout_retains_task_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = package(make_exe(root / "a.exe"))
            scanner = CapeScanner(load_config())
            with patch.object(scanner, "request", return_value={"data": {"task_ids": [7]}}), patch("pipeline.detectors.cape.time.monotonic", side_effect=[0, 1000]):
                response = scanner.scan(sample, root / "evidence")
            self.assertIsNone(response["detected"])
            self.assertEqual(json.loads((root / "evidence/cape-task.json").read_text())["task_id"], 7)
            scanner.close()


class RunnerTests(unittest.TestCase):
    def test_pipeline_keeps_five_results_continues_errors_and_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = make_exe(root / "sample.exe")
            config = load_config()
            config["output_dir"] = str(root / "reports")
            runner = DetectorRunner(config)
            try:
                responses = [result(True), failed("model missing"), result(False), failed("VM offline", "INFRA_FAILURE"), result(True, score=4, threshold=4)]
                with patch.object(runner, "scan_engine", side_effect=responses) as scan, patch.object(runner.defender, "close"):
                    summary = runner.run(sample, "trial", ENGINES)
                self.assertEqual(scan.call_count, 5)
                self.assertEqual(summary["counts"], {"detected": 2, "no_alert": 1, "errors": 2, "skipped": 0})
                self.assertEqual(len(summary["rows"]), 5)
                for row in summary["rows"]:
                    if row["status"] != "COMPLETED":
                        self.assertIsNone(row["detected"])
                self.assertTrue((root / "reports/trial/summary.csv").exists())
                with patch.object(runner, "scan_engine", return_value=result(False)) as scan, patch.object(runner.defender, "close"):
                    final = runner.run(sample, "trial", ENGINES)
                self.assertEqual(scan.call_count, 2)
                self.assertEqual(final["counts"]["errors"], 0)
            finally:
                runner.close()

    def test_engine_major_order_stops_defender_before_cape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_exe(root / "a.exe")
            make_exe(root / "b.exe", b"different")
            config = load_config()
            config["output_dir"] = str(root / "reports")
            runner = DetectorRunner(config)
            calls = []
            with patch.object(runner, "scan_engine", side_effect=lambda engine, *args: calls.append(engine) or result(False)), patch.object(runner.defender, "close", side_effect=lambda: calls.append("defender_stop")):
                runner.run(root, "trial", ENGINES)
            self.assertEqual(calls, ["clamav", "clamav", "ember", "ember", "malconv", "malconv", "defender", "defender", "defender_stop", "cape", "cape"])
            runner.close()

    def test_changed_config_cannot_resume_old_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = make_exe(root / "a.exe")
            config = load_config()
            config["output_dir"] = str(root / "reports")
            runner = DetectorRunner(config)
            with patch.object(runner, "scan_engine", return_value=result(False)):
                runner.run(sample, "trial", ["ember"])
            config["cape"]["threshold"] = 7
            with self.assertRaisesRegex(ValueError, "changed"):
                runner.run(sample, "trial", ["ember"])
            runner.close()

    def test_c1_requires_matching_hash_but_is_not_a_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = make_exe(root / "a.exe")
            c1 = root / "c1.json"
            config = load_config()
            config["output_dir"] = str(root / "reports")
            runner = DetectorRunner(config)
            write_json(c1, {"sha256": "wrong", "status": "PASS"})
            with self.assertRaises(ValueError):
                runner.run(sample, "trial", ["ember"], c1)
            write_json(c1, {"sha256": digest(sample), "status": "UNDETERMINED"})
            with patch.object(runner, "scan_engine", return_value=result(False)) as scan:
                runner.run(sample, "trial", ["ember"], c1)
                scan.assert_called_once()
            runner.close()

    def test_version_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = {"versions": {"clamav": {"database": "old"}}}
            with self.assertRaisesRegex(RuntimeError, "changed"):
                DetectorRunner.pin_version("clamav", {"version": {"database": "new"}}, manifest, Path(temporary) / "manifest.json")

    def test_changed_model_cannot_resume_old_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = make_exe(root / "a.exe")
            model = root / "model"
            model.write_bytes(b"one")
            config = load_config()
            config["output_dir"] = str(root / "reports")
            config["static"]["ember_model"] = str(model)
            runner = DetectorRunner(config)
            with patch.object(runner, "scan_engine", return_value=result(False)):
                runner.run(sample, "trial", ["ember"])
            model.write_bytes(b"two")
            with self.assertRaisesRegex(ValueError, "changed"):
                runner.run(sample, "trial", ["ember"])
            runner.close()

    def test_identical_packages_in_different_directories_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").mkdir()
            (root / "two").mkdir()
            make_exe(root / "one/a.exe")
            make_exe(root / "two/a.exe")
            config = load_config()
            config["output_dir"] = str(root / "reports")
            runner = DetectorRunner(config)
            with patch.object(runner, "scan_engine", return_value=result(False)) as scan:
                summary = runner.run(root, "trial", ["ember"])
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(len(summary["rows"]), 5)
            runner.close()

    def test_campaign_lock_rejects_concurrent_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".lock"
            with lock(path), self.assertRaisesRegex(RuntimeError, "already in use"):
                with lock(path):
                    pass

    def test_csv_does_not_execute_filename_as_formula(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = make_exe(root / "+sample.exe")
            config = load_config()
            config["output_dir"] = str(root / "reports")
            runner = DetectorRunner(config)
            with patch.object(runner, "scan_engine", return_value=result(False)):
                runner.run(sample, "trial", ["ember"])
            self.assertIn("'+sample.exe", (root / "reports/trial/summary.csv").read_text())
            runner.close()

    def test_missing_input_and_no_exe_do_not_submit_tasks(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = DetectorRunner(load_config())
            with patch.object(runner.cape, "scan") as scan, self.assertRaises(ValueError):
                runner.run(Path(temporary), "trial", ENGINES)
            scan.assert_not_called()
            runner.close()

    def test_cli_invalid_engine_is_rejected(self):
        with self.assertRaises(SystemExit):
            main(["doctor", "--engines", "sorel"])


if __name__ == "__main__":
    unittest.main()

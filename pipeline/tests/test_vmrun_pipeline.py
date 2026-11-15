import base64
import json
import io
import os
import hashlib
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from pipeline.vmrun_pipeline import CampaignState, Collector, ExecutionFailure, HostServices, PipelineError, Runner, Settings, VMRun, atomic_json_write, iso_now, sample_package_sha256, sample_paths, suppress_warnings


SAMPLE_ARTIFACTS = [{
    "role": "primary",
    "name": "sample.exe",
    "sha256": "a" * 64,
    "guest_path": r"C:\Detonation\sample.exe",
}]


class VMRunPipelineTests(unittest.TestCase):
    def test_state_skips_only_completed_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            state = CampaignState(Path(directory))
            state.save("elastic", "a" * 64, {"status": "COMPLETED"})
            state.save("wazuh", "a" * 64, {"status": "INFRA_FAILURE"})
            resumed = CampaignState(Path(directory))
            self.assertTrue(resumed.completed("elastic", "a" * 64))
            self.assertFalse(resumed.completed("wazuh", "a" * 64))

    def test_vmrun_command_keeps_guest_credentials_out_of_arguments_without_guest_mode(self):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        command = VMRun(settings)._command("listSnapshots")
        self.assertNotIn("guest", command)
        self.assertNotIn("secret", command)

    @patch.object(VMRun, "call")
    def test_snapshot_listing_accepts_vmrun_crash_after_valid_output(self, call):
        call.return_value.returncode = 139
        call.return_value.stdout = "Total snapshots: 1\nnormal_real\n"
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        self.assertIn("normal_real", VMRun(settings).snapshots())

    @patch.object(VMRun, "call")
    def test_launch_sets_the_package_working_directory(self, call):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        VMRun(settings).launch(r"C:\Detonation\run\loader.exe", r"C:\Detonation\run")
        arguments = call.call_args.args
        encoded = arguments[arguments.index("-EncodedCommand") + 1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("Start-Process", script)
        self.assertIn(r"C:\Detonation\run\loader.exe", script)
        self.assertIn(r"-WorkingDirectory 'C:\Detonation\run'", script)
        self.assertIn("-noWait", arguments)

    @patch("pipeline.vmrun_pipeline.time.sleep")
    def test_execution_proof_requires_alive_marker(self, sleep):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1,
                            execution_proof_timeout=2)
        vm = VMRun(settings)
        with patch.object(vm, "run_powershell", side_effect=["", "ALIVE\n"]):
            proof = vm.wait_for_execution_proof(r"C:\Detonation\run\c1_pass.txt")
        self.assertEqual(proof["status"], "PASSED")
        self.assertEqual(sleep.call_count, 1)

        with patch.object(vm, "run_powershell", return_value="STALE"):
            with self.assertRaises(ExecutionFailure):
                vm.wait_for_execution_proof(r"C:\Detonation\run\c1_pass.txt")

    @patch("pipeline.vmrun_pipeline.subprocess.Popen")
    @patch.object(VMRun, "call")
    def test_revert_starts_vm_headless(self, vmrun_call, popen):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        VMRun(settings).revert("wazuh")
        self.assertEqual(popen.call_args.args[0][-3:], ["start", "/tmp/test.vmx", "nogui"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_wait_for_tools_reports_headless_start_failure(self):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        vm = VMRun(settings)
        vm.start_process = Mock()
        vm.start_process.poll.return_value = 255
        vm.start_process.communicate.return_value = ("Error: The operation was canceled", "")
        with self.assertRaisesRegex(PipelineError, "operation was canceled"):
            vm.wait_for_tools()

    @patch.object(VMRun, "call")
    def test_headless_tools_installed_state_is_ready(self, vmrun_call):
        vmrun_call.side_effect = [
            Mock(returncode=139, stdout="installed\n", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
        ]
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        VMRun(settings).wait_for_tools()
        self.assertIn(r"C:\Windows\System32\whoami.exe", vmrun_call.call_args.args)

    @patch("pipeline.vmrun_pipeline.time.sleep")
    @patch.object(VMRun, "call")
    def test_wait_for_tools_retries_until_guest_operation_works(self, vmrun_call, _sleep):
        ready = Mock(returncode=0, stdout="installed\n", stderr="")
        unavailable = Mock(returncode=255, stdout="", stderr="The virtual machine is not powered on")
        vmrun_call.side_effect = [ready, unavailable, ready, ready]
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 5)
        VMRun(settings).wait_for_tools()
        self.assertEqual(vmrun_call.call_count, 4)
        self.assertTrue(vmrun_call.call_args_list[1].kwargs["guest"])
        self.assertEqual(vmrun_call.call_args_list[1].args[0], "runProgramInGuest")

    @patch.object(VMRun, "copy_from_guest")
    @patch.object(VMRun, "exists", return_value=True)
    @patch.object(VMRun, "call")
    def test_powershell_reads_output_through_guest_file(self, call, _exists, copy_from_guest):
        call.return_value.returncode = 0
        copy_from_guest.side_effect = lambda _source, destination: destination.write_text(
            '\ufeff{"ready":true}', encoding="utf-8"
        )
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 1)
        self.assertEqual(VMRun(settings).run_powershell("Write-Output test"), '{"ready":true}')

    def test_defender_health_allows_missing_optional_sysmon(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 1, 1, 1, 5)
            runner = Runner(settings, "test")
            output = json.dumps({
                "services": {"Name": "WinDefend", "Status": "Running"},
                "defender": {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True},
                "utc": iso_now(),
            })
            with patch.object(runner.vmrun, "run_powershell", return_value=output):
                health = runner._guest_health("defender")
            self.assertEqual(health["optional_services"]["Sysmon64"], "NOT_INSTALLED")

    def test_non_defender_health_rejects_defender_contamination(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            output = json.dumps({
                "services": {"Name": "Elastic Agent", "Status": "Running"},
                "defender": {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True},
                "utc": iso_now(),
            })
            with patch.object(runner.vmrun, "run_powershell", return_value=output):
                with self.assertRaises(PipelineError):
                    runner._guest_health("elastic")

    def test_elastic_health_tolerates_unavailable_defender_status(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            output = json.dumps({
                "services": {"Name": "Elastic Agent", "Status": "Running"},
                "defender": None,
                "utc": iso_now(),
            })
            with patch.object(runner.vmrun, "run_powershell", return_value=output) as run_powershell:
                health = runner._guest_health("elastic")

            self.assertIsNone(health["defender"])
            self.assertIn("Get-MpComputerStatus -ErrorAction Stop", run_powershell.call_args.args[0])

    def test_wazuh_health_requires_sysmon_event_channel_subscription(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            output = json.dumps({
                "services": [{"Name": "WazuhSvc", "Status": "Running"}, {"Name": "Sysmon64", "Status": "Running"}],
                "defender": {"RealTimeProtectionEnabled": False, "BehaviorMonitorEnabled": False},
                "wazuh_sysmon_configured": False,
                "utc": iso_now(),
            })
            with patch.object(runner.vmrun, "run_powershell", return_value=output):
                with self.assertRaises(PipelineError):
                    runner._guest_health("wazuh")

    def test_wazuh_dll_package_requires_sysmon_image_load(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            output = json.dumps({
                "services": [{"Name": "WazuhSvc", "Status": "Running"}, {"Name": "Sysmon64", "Status": "Running"}],
                "defender": {"RealTimeProtectionEnabled": False, "BehaviorMonitorEnabled": False},
                "wazuh_sysmon_configured": True,
                "sysmon_image_load_enabled": False,
                "utc": iso_now(),
            })
            with patch.object(runner.vmrun, "run_powershell", return_value=output):
                with self.assertRaisesRegex(PipelineError, "ImageLoad is disabled"):
                    runner._guest_health("wazuh", require_image_load=True)

    def test_guest_health_retries_transient_service_startup(self):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 30)
        runner = Runner(settings, "test")
        with patch.object(
            runner,
            "_guest_health",
            side_effect=[PipelineError("Guest services not running: Sysmon64"), {"ready": True}],
        ) as health, patch("pipeline.vmrun_pipeline.time.sleep") as sleep:
            self.assertEqual(runner._wait_for_guest_health("wazuh"), {"ready": True})
        self.assertEqual(health.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_run_reports_infrastructure_failure_after_writing_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            with patch.object(runner.services, "ensure", return_value=False), \
                 patch.object(runner.collector, "host_ready"), \
                 patch.object(runner, "_run_one", return_value={"engine": "defender", "status": "INFRA_FAILURE"}):
                with self.assertRaises(PipelineError):
                    runner.run([sample], ["defender"], None)
            self.assertIn("defender:", (root / "test" / "state.json").read_text(encoding="utf-8"))

    def test_result_prints_infrastructure_failure_instead_of_na(self):
        output = io.StringIO()
        with redirect_stdout(output):
            Runner._print_result({"engine": "defender", "status": "INFRA_FAILURE", "error": "guest unavailable"}, 1.0)
        self.assertIn("RESULT  INFRA_FAILURE", output.getvalue())

    def test_run_prints_wazuh_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            report = {"engine": "wazuh", "status": "COMPLETED", "verdict": "DETECTED", "wazuh": {
                "suspicious_alert_count": 1,
                "total_alert_count": 1,
                "raw_alerts": [{"rule": {"id": "100203", "level": 10, "mitre": {"id": ["T1055"]}},
                                "data": {"win": {"system": {"eventID": "8"}}}}],
            }}
            output = io.StringIO()
            with patch.object(runner.services, "ensure", return_value=False), \
                 patch.object(runner.collector, "host_ready"), \
                 patch.object(runner, "_run_one", return_value=report), \
                 redirect_stdout(output):
                runner.run([sample], ["wazuh"], None)
            self.assertIn("RESULT  DETECTED", output.getvalue())
            self.assertIn("rule=100203 level=10 sysmon_event=8 mitre=T1055", output.getvalue())

    def test_run_writes_summary_and_preserves_campaign_creation_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            (root / "manifest.json").write_text(json.dumps({"samples": {
                sample.name: {"technique": "test_technique", "fidelity": "reference_flow"},
            }}), encoding="utf-8")
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            report = {"engine": "wazuh", "status": "COMPLETED", "verdict": "NO_ALERT", "wazuh": {
                "raw_alerts": [], "suspicious_alert_count": 0, "total_alert_count": 0,
            }}
            with patch.object(runner.services, "ensure", return_value=False), \
                 patch.object(runner.collector, "host_ready"), \
                 patch.object(runner, "_run_one", return_value=report), \
                 redirect_stdout(io.StringIO()):
                runner.run([sample], ["wazuh"], None)
            manifest_path = root / "test" / "manifest.json"
            created_at = json.loads(manifest_path.read_text(encoding="utf-8"))["created_at"]
            with patch.object(runner.services, "ensure", return_value=False), \
                 patch.object(runner.collector, "host_ready"), \
                 redirect_stdout(io.StringIO()):
                runner.run([sample], ["wazuh"], None)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            summary = json.loads((root / "test" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["created_at"], created_at)
            self.assertEqual(len(manifest["run_history"]), 2)
            self.assertEqual(summary["jobs"]["skipped"], 1)
            self.assertEqual(summary["rows"][0]["verdict"], "NO_ALERT")
            self.assertEqual(summary["rows"][0]["technique"], "test_technique")
            self.assertIn("NO_ALERT", (root / "test" / "summary.csv").read_text(encoding="utf-8"))

    def test_doctor_prints_realtime_progress_and_result(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 1, 1, 1, 30)
            runner = Runner(settings, "test")
            guest = {
                "services": [{"Name": "WazuhSvc", "Status": "Running"}, {"Name": "Sysmon64", "Status": "Running"}],
                "defender": {"RealTimeProtectionEnabled": False},
                "clock_skew_seconds": 0.5,
            }
            output = io.StringIO()
            with patch.object(runner.vmrun, "snapshots", return_value="wazuh"), \
                 patch.object(runner.services, "ensure", return_value=False), \
                 patch.object(runner.collector, "host_ready"), \
                 patch.object(runner.vmrun, "revert"), \
                 patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value=guest), \
                 redirect_stdout(output):
                result = runner.doctor(["wazuh"])
            self.assertTrue(result["engines"]["wazuh"]["ready"])
            self.assertIn("Reverting VM to snapshot 'wazuh'", output.getvalue())
            self.assertIn("DOCTOR RESULT  READY", output.getvalue())

    @patch("pipeline.vmrun_pipeline.warnings.simplefilter")
    def test_cli_suppresses_python_warnings(self, simplefilter):
        suppress_warnings()
        simplefilter.assert_called_once_with("ignore")

    @patch("pipeline.vmrun_pipeline.requests.post")
    def test_wazuh_query_does_not_assume_agent_001(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {"hits": {"hits": []}}
        post.return_value = response
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30)
        with patch.dict(os.environ, {"WAZUH_AGENT_ID": ""}):
            result = Collector(settings)._poll_wazuh(SAMPLE_ARTIFACTS, iso_now(), iso_now())
        self.assertEqual(result["status"], "NO_ALERT")
        must = post.call_args.kwargs["json"]["query"]["bool"]["must"]
        self.assertFalse(any("agent.id" in item.get("term", {}) for item in must))
        should = must[0]["bool"]["should"]
        self.assertTrue(any("data.win.eventdata.sourceImage" in item.get("wildcard", {}) for item in should))
        self.assertTrue(any("*sample.exe*" in item.get("wildcard", {}).values() for item in should))
        self.assertFalse(any("*payload.bin*" in item.get("wildcard", {}).values() for item in should))

    @patch("pipeline.vmrun_pipeline.requests.post")
    def test_wazuh_telemetry_requires_archives_and_process_hash(self, post):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30)
        collector = Collector(settings)
        post.return_value = Mock(status_code=404)
        with self.assertRaisesRegex(PipelineError, "enable Wazuh JSON archives"):
            collector.wait_for_sample_telemetry("wazuh", r"C:\Detonation\sample.exe", "a" * 64, iso_now())
        post.return_value = Mock(status_code=200)
        post.return_value.json.return_value = {"_shards": {"total": 0}, "hits": {"hits": []}}
        with self.assertRaisesRegex(PipelineError, "Wazuh archives index is missing"):
            collector.wait_for_sample_telemetry("wazuh", r"C:\Detonation\sample.exe", "a" * 64, iso_now())
        post.return_value = Mock(status_code=200)
        post.return_value.json.return_value = {"hits": {"hits": [{"_index": "wazuh-archives-4.x-2026.10.14", "_source": {
            "timestamp": iso_now(), "data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "guid-1"}}}}}]}}
        result = collector.wait_for_sample_telemetry("wazuh", r"C:\Detonation\sample.exe", "a" * 64, iso_now())
        self.assertEqual(result["process_guid"], "guid-1")
        query = post.call_args.kwargs["json"]["query"]["bool"]
        self.assertIn("*" + "A" * 64 + "*", str(query["should"]))
        self.assertIn("data.win.system.eventID", str(query["filter"]))

    @patch("pipeline.vmrun_pipeline.requests.post")
    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_wazuh_preflight_rejects_missing_archives_before_vm_run(self, get, post):
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"status": "green"}
        post.return_value = Mock(status_code=200)
        post.return_value.json.return_value = {"_shards": {"total": 0}}
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30)
        with self.assertRaisesRegex(PipelineError, "Wazuh archives index is missing"):
            Collector(settings).host_ready("wazuh", timeout=1)
        self.assertIn("wazuh-archives-*/_search", post.call_args.args[0])

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_telemetry_matches_exact_guest_path_or_hash(self, get):
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 1,
                            elastic_poll_attempts=1)
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"hits": {"hits": [{"_index": "logs-endpoint.events.process-default",
            "_source": {"@timestamp": iso_now(), "event": {"id": "e-1"}, "process": {"entity_id": "p-1"}}}]}}
        result = Collector(settings).wait_for_sample_telemetry("elastic", r"C:\Detonation\sample.exe", "a" * 64, iso_now())
        self.assertEqual(result["process_guid"], "p-1")
        self.assertEqual(result["evidence_type"], "sample_process")
        self.assertIn("case_insensitive", str(get.call_args.kwargs["json"]))

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_telemetry_accepts_child_of_exact_sample_path(self, get):
        guest_file = r"C:\Detonation\runs\run-1\sample.exe"
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 1,
                            elastic_poll_attempts=1)
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"hits": {"hits": [{"_index": "logs-endpoint.events.process-default",
            "_source": {"@timestamp": iso_now(), "process": {"entity_id": "child-1", "executable": r"C:\Windows\notepad.exe",
                "parent": {"entity_id": "sample-1", "executable": guest_file}}}}]}}
        result = Collector(settings).wait_for_sample_telemetry("elastic", guest_file, "a" * 64, iso_now())
        self.assertEqual(result["process_guid"], "sample-1")
        self.assertEqual(result["evidence_type"], "child_process")
        should = get.call_args.kwargs["json"]["query"]["bool"]["should"]
        self.assertIn({"term": {"process.parent.executable": {"value": guest_file, "case_insensitive": True}}}, should)

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_companion_dll_telemetry_is_required_by_hash_or_path(self, get):
        dll = {"role": "companion", "name": "payload.dll", "sha256": "b" * 64,
               "guest_path": r"C:\Detonation\run\payload.dll"}
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"hits": {"hits": [{"_index": "logs-endpoint.events.library-default",
            "_source": {"@timestamp": iso_now(), "event": {"id": "dll-1"},
                        "dll": {"path": dll["guest_path"], "hash": {"sha256": dll["sha256"]}}}}]}}
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 1,
                            elastic_poll_attempts=1)
        result = Collector(settings).wait_for_companion_telemetry("elastic", [*SAMPLE_ARTIFACTS, dll], iso_now())
        self.assertEqual(result[0]["status"], "LOADED")
        self.assertIn("logs-endpoint.events.library-*", get.call_args.args[0])
        self.assertIn(dll["sha256"], str(get.call_args.kwargs["json"]))

    @patch("pipeline.vmrun_pipeline.requests.post")
    def test_wazuh_companion_dll_telemetry_uses_sysmon_event_7(self, post):
        dll = {"role": "companion", "name": "payload.dll", "sha256": "b" * 64,
               "guest_path": r"C:\Detonation\run\payload.dll"}
        post.return_value = Mock(status_code=200)
        post.return_value.json.return_value = {"hits": {"hits": [{"_index": "wazuh-archives-4.x",
            "_source": {"timestamp": iso_now(), "data": {"win": {"eventdata": {
                "imageLoaded": dll["guest_path"], "hashes": "SHA256=" + dll["sha256"].upper()}}}}}]}}
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 1)
        result = Collector(settings).wait_for_companion_telemetry("wazuh", [*SAMPLE_ARTIFACTS, dll], iso_now())
        self.assertEqual(result[0]["status"], "LOADED")
        filters = post.call_args.kwargs["json"]["query"]["bool"]["filter"]
        self.assertIn({"term": {"data.win.system.eventID": "7"}}, filters)

    def test_runtime_checks_telemetry_before_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            digest = hashlib.sha256(b"MZ").hexdigest()
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            with patch.object(runner.vmrun, "revert"), patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value={}), \
                 patch.object(runner, "_guest_summary", return_value="healthy"), \
                 patch.object(runner.vmrun, "create_directory"), patch.object(runner.vmrun, "copy_to_guest"), \
                 patch.object(runner.vmrun, "run_powershell", return_value=digest.upper()), \
                 patch.object(runner.vmrun, "exists", return_value=True), patch.object(runner.vmrun, "launch"), \
                 patch("pipeline.vmrun_pipeline.time.sleep"), \
                 patch.object(runner.collector, "wait_for_sample_telemetry", return_value={"status": "OBSERVED"}) as telemetry, \
                 patch.object(runner.collector, "collect", return_value={"status": "NO_ALERT"}) as collect:
                collect.side_effect = lambda *_args: ({"status": "NO_ALERT"} if telemetry.called else self.fail("alert checked before telemetry"))
                report = runner._run_one("wazuh", sample, digest)
                self.assertEqual(report["verdict"], "NO_ALERT")
                self.assertEqual(report["telemetry"]["status"], "OBSERVED")
                telemetry.side_effect = PipelineError("sample process telemetry not observed")
                collect.reset_mock()
                report = runner._run_one("wazuh", sample, digest)
                self.assertEqual(report["status"], "INFRA_FAILURE")
                self.assertNotIn("verdict", report)
                collect.assert_not_called()

    def test_high_signal_sample_requires_execution_proof_before_detector_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            digest = hashlib.sha256(b"MZ").hexdigest()
            (root / "manifest.json").write_text(json.dumps({"samples": {
                sample.name: {"execution_profile": "high_signal_v1"},
            }}), encoding="utf-8")
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            with patch.object(runner.vmrun, "revert"), patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value={}), \
                 patch.object(runner, "_guest_summary", return_value="healthy"), \
                 patch.object(runner.vmrun, "create_directory"), patch.object(runner.vmrun, "copy_to_guest"), \
                 patch.object(runner.vmrun, "run_powershell", return_value=digest.upper()), \
                 patch.object(runner.vmrun, "exists", return_value=True), patch.object(runner.vmrun, "launch"), \
                 patch.object(runner.vmrun, "wait_for_execution_proof",
                              side_effect=ExecutionFailure("proof missing")), \
                 patch.object(runner.collector, "wait_for_sample_telemetry") as telemetry, \
                 patch.object(runner.collector, "collect") as collect:
                report = runner._run_one("wazuh", sample, digest)
            self.assertEqual(report["status"], "EXECUTION_FAILURE")
            self.assertIn("proof missing", report["error"])
            telemetry.assert_not_called()
            collect.assert_not_called()

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_alerts_use_event_id_to_remove_cross_index_duplicates(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"hits": {"hits": [
            {"_id": "endpoint-copy", "_source": {"event": {"id": "same-event", "code": "behavior"}}},
            {"_id": "security-copy", "_source": {"event": {"id": "same-event", "code": "behavior"}}},
            {"_id": "file", "_source": {"event": {"id": "file-event", "code": "malicious_file"}}},
        ]}}
        get.return_value = response
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30,
                            elastic_poll_attempts=1)
        result = Collector(settings)._poll_elastic(SAMPLE_ARTIFACTS, iso_now(), iso_now())
        self.assertEqual(result["raw_alert_count"], 3)
        self.assertEqual(result["unique_alert_count"], 2)
        self.assertEqual(result["behavior_alert_count"], 1)
        self.assertEqual(result["file_alert_count"], 1)
        self.assertEqual(result["status"], "DETECTED")
        self.assertFalse(result["collection_ended_early"])
        self.assertEqual(get.call_count, 2)

    @patch("pipeline.vmrun_pipeline.time.sleep")
    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_file_only_alert_is_not_behavior_detection(self, get, sleep):
        response = Mock(status_code=200)
        response.json.return_value = {"hits": {"hits": [
            {"_id": "file", "_source": {"event": {"id": "file-event", "code": "malicious_file"}}},
        ]}}
        get.return_value = response
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 5, 1, 1, 30,
                            elastic_poll_attempts=3)
        result = Collector(settings)._poll_elastic(SAMPLE_ARTIFACTS, iso_now(), iso_now())
        self.assertEqual(result["status"], "NO_ALERT")
        self.assertEqual(result["file_alert_count"], 1)
        self.assertEqual(result["behavior_alert_count"], 0)
        self.assertFalse(result["collection_ended_early"])
        self.assertEqual(get.call_count, 6)
        self.assertEqual(sleep.call_count, 2)

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_behavior_alert_stops_collection_early(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"hits": {"hits": [
            {"_id": "behavior", "_source": {"event": {"id": "behavior-event", "code": "behavior"}}},
        ]}}
        get.return_value = response
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 5, 1, 1, 30,
                            elastic_poll_attempts=3)
        result = Collector(settings)._poll_elastic(SAMPLE_ARTIFACTS, iso_now(), iso_now())
        self.assertEqual(result["status"], "DETECTED")
        self.assertTrue(result["collection_ended_early"])
        self.assertEqual(get.call_count, 2)

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_query_failure_is_not_no_alert(self, get):
        get.return_value = Mock(status_code=503)
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30,
                            elastic_poll_attempts=1)
        with self.assertRaisesRegex(PipelineError, "HTTP 503"):
            Collector(settings)._poll_elastic(SAMPLE_ARTIFACTS, iso_now(), iso_now())

    @patch("pipeline.vmrun_pipeline.requests.post")
    def test_wazuh_query_failure_is_not_no_alert(self, post):
        post.return_value = Mock(status_code=503)
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30)
        with self.assertRaisesRegex(PipelineError, "HTTP 503"):
            Collector(settings)._poll_wazuh(SAMPLE_ARTIFACTS, iso_now(), iso_now())

    def test_elastic_static_block_is_not_behavior_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            digest = hashlib.sha256(b"MZ").hexdigest()
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            with patch.object(runner.vmrun, "revert"), \
                 patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value={"hostname": "WIN11"}), \
                 patch.object(runner, "_guest_summary", return_value="healthy"), \
                 patch.object(runner, "_wait_for_elastic_readiness", return_value={"canary": {"event_id": "ok"}}), \
                 patch.object(runner.vmrun, "create_directory"), \
                 patch.object(runner.vmrun, "copy_to_guest"), \
                 patch.object(runner.vmrun, "run_powershell", return_value=""), \
                 patch.object(runner.vmrun, "exists", return_value=False), \
                 patch.object(runner.vmrun, "launch") as launch, \
                 patch.object(runner.collector, "collect") as collect:
                report = runner._run_one("elastic", sample, digest)
            self.assertEqual(report["status"], "COMPLETED")
            self.assertEqual(report["verdict"], "NOT_EXECUTED")
            self.assertIsNone(report["execution_started_at"])
            launch.assert_not_called()
            collect.assert_not_called()

    def test_elastic_readiness_requires_endpoint_fleet_and_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            fleet_agent = {"id": "agent-1", "status": "degraded", "policy_revision": 11, "last_checkin": iso_now()}
            endpoint = {"healthy": True, "agent_state": 2, "agent_message": "Running",
                        "agent_policy_revision": 11, "endpoint": []}
            with patch.object(runner, "_elastic_endpoint_status", return_value=endpoint), \
                 patch.object(runner.collector, "elastic_agent", return_value=fleet_agent), \
                 patch.object(runner.vmrun, "run_powershell") as run_powershell, \
                 patch.object(runner.collector, "wait_for_elastic_canary", return_value={"marker": "ok"}) as wait_canary:
                readiness = runner._wait_for_elastic_readiness("run-1", {"hostname": "WIN11"})
            self.assertEqual(readiness["fleet_agent_id"], "agent-1")
            self.assertEqual(wait_canary.call_args.args[0], "WIN11")
            self.assertTrue(wait_canary.call_args.args[1].startswith("vmrun-canary-run-1-"))
            self.assertIn("$env:ComSpec /d /c", run_powershell.call_args.args[0])
            self.assertEqual(readiness["fleet_status"], "degraded")

    def test_elastic_readiness_retries_a_missing_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            fleet_agent = {"id": "agent-1", "status": "degraded", "policy_revision": 11, "last_checkin": iso_now()}
            endpoint = {"healthy": True, "agent_state": 2, "agent_message": "Running",
                        "agent_policy_revision": 11, "endpoint": []}
            with patch.object(runner, "_elastic_endpoint_status", return_value=endpoint), \
                 patch.object(runner.collector, "elastic_agent", return_value=fleet_agent), \
                 patch.object(runner.vmrun, "run_powershell") as run_powershell, \
                 patch.object(runner.collector, "wait_for_elastic_canary",
                              side_effect=[PipelineError("missing"), {"event_id": "canary-1"}]) as wait_canary:
                readiness = runner._wait_for_elastic_readiness("run-1", {"hostname": "WIN11"})
            self.assertEqual(readiness["canary"]["event_id"], "canary-1")
            self.assertEqual(run_powershell.call_count, 2)
            self.assertEqual(wait_canary.call_count, 2)

    def test_elastic_endpoint_status_requires_healthy_units_and_policy_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 1, 1, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            status = {"state": 2, "message": "Running", "components": [{"id": "endpoint", "state": 2,
                "units": [{"unit_id": "endpoint", "state": 2,
                           "message": "Applied policy 'elastic-defend-windows' (Defend policy rev. 6. Agent policy rev. 11.)"}]}]}
            with patch.object(runner.vmrun, "run_powershell", return_value=json.dumps(status)):
                result = runner._elastic_endpoint_status()
            self.assertTrue(result["healthy"])
            self.assertEqual(result["agent_policy_revision"], 11)
            status["components"][0]["units"][0]["state"] = 3
            with patch.object(runner.vmrun, "run_powershell", return_value=json.dumps(status)):
                self.assertFalse(runner._elastic_endpoint_status()["healthy"])

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_agent_accepts_current_fleet_items_response(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"items": [{"id": "agent-1", "local_metadata": {"host": {"hostname": "WIN11"}}}]}
        get.return_value = response
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 30)
        self.assertEqual(Collector(settings).elastic_agent("win11")["id"], "agent-1")

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_canary_query_allows_guest_clock_skew(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"hits": {"hits": [{"_source": {"event": {"id": "canary-1"}, "@timestamp": iso_now()}}]}}
        get.return_value = response
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 0, 1, 1, 30)
        started = "2026-10-14T08:00:30+00:00"
        Collector(settings).wait_for_elastic_canary("WIN11", "marker", started, timeout=1)
        filters = get.call_args.kwargs["json"]["query"]["bool"]["filter"]
        canary_start = filters[1]["range"]["@timestamp"]["gte"]
        self.assertEqual(canary_start, "2026-10-14T08:00:00+00:00")
        self.assertEqual(filters[0]["term"]["host.name"], {"value": "WIN11", "case_insensitive": True})

    def test_run_one_copies_the_original_sample_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.exe"
            source.write_bytes(b"MZ")
            sample = root / "original-name.exe"
            sample.symlink_to(source)
            digest = hashlib.sha256(b"MZ").hexdigest()
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            guest_health = {"services": {"Name": "WinDefend", "Status": "Running"},
                            "defender": {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True},
                            "clock_skew_seconds": 0}
            with patch.object(runner.vmrun, "revert"), \
                 patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value=guest_health), \
                 patch.object(runner.vmrun, "create_directory"), \
                 patch.object(runner.vmrun, "copy_to_guest") as copy_to_guest, \
                 patch.object(runner.vmrun, "run_powershell", return_value=digest), \
                 patch.object(runner.vmrun, "exists", return_value=True), \
                 patch.object(runner.vmrun, "launch"), \
                 patch.object(runner, "_collect_defender", return_value={"status": "NO_ALERT"}), \
                 patch.object(runner.vmrun, "rename_guest_file") as rename_guest_file:
                report = runner._run_one("defender", sample, digest)
            self.assertEqual(report["status"], "COMPLETED")
            self.assertEqual(copy_to_guest.call_args.args[0], source)
            self.assertTrue(copy_to_guest.call_args.args[1].endswith(r"\original-name.exe"))
            rename_guest_file.assert_not_called()

    def test_sample_paths_excludes_manifest_prototypes_for_directory_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ready.exe").write_bytes(b"MZ")
            (root / "prototype.exe").write_bytes(b"MZ")
            (root / "manifest.json").write_text(json.dumps({"samples": {
                "ready.exe": {"benchmark_ready": True},
                "prototype.exe": {"benchmark_ready": False},
            }}), encoding="utf-8")

            self.assertEqual(sample_paths(root), [root / "ready.exe"])
            self.assertEqual(sample_paths(root / "prototype.exe"), [root / "prototype.exe"])

    def test_run_one_copies_and_verifies_manifest_companion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "dll_injection.exe"
            companion = root / "payload.dll"
            sample.write_bytes(b"MZ-sample")
            companion.write_bytes(b"MZ-companion")
            sample_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
            companion_digest = hashlib.sha256(companion.read_bytes()).hexdigest()
            (root / "manifest.json").write_text(json.dumps({"samples": {
                sample.name: {"benchmark_ready": True, "companions": [companion.name]},
            }}), encoding="utf-8")
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            guest_health = {"services": {"Name": "WinDefend", "Status": "Running"},
                            "defender": {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True},
                            "clock_skew_seconds": 0}

            def guest_hash(command):
                return companion_digest if companion.name in command else sample_digest

            with patch.object(runner.vmrun, "revert"), \
                 patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value=guest_health), \
                 patch.object(runner.vmrun, "create_directory"), \
                 patch.object(runner.vmrun, "copy_to_guest") as copy_to_guest, \
                 patch.object(runner.vmrun, "run_powershell", side_effect=guest_hash), \
                 patch.object(runner.vmrun, "exists", return_value=True), \
                 patch.object(runner.vmrun, "launch"), \
                 patch.object(runner, "_collect_defender", return_value={"status": "NO_ALERT"}):
                report = runner._run_one("defender", sample, sample_digest)

            copied_sources = [call.args[0] for call in copy_to_guest.call_args_list]
            self.assertEqual(copied_sources, [companion, sample])
            self.assertEqual(report["companions"][0]["sha256"], companion_digest)

    def test_package_fingerprint_changes_when_a_companion_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "loader.exe"
            companion = root / "payload.dll"
            sample.write_bytes(b"MZ-loader")
            companion.write_bytes(b"MZ-dll-v1")
            (root / "manifest.json").write_text(json.dumps({"samples": {
                sample.name: {"companions": [companion.name]},
            }}), encoding="utf-8")
            first = sample_package_sha256(sample)
            companion.write_bytes(b"MZ-dll-v2")
            self.assertNotEqual(first, sample_package_sha256(sample))

            (root / "manifest.json").write_text(json.dumps({"samples": {sample.name: {}}}), encoding="utf-8")
            self.assertEqual(sample_package_sha256(sample), hashlib.sha256(sample.read_bytes()).hexdigest())

    def test_companion_manifest_rejects_paths_outside_the_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "loader.exe"
            sample.write_bytes(b"MZ")
            (root / "manifest.json").write_text(json.dumps({"samples": {
                sample.name: {"companions": ["../payload.dll"]},
            }}), encoding="utf-8")
            with self.assertRaisesRegex(PipelineError, "must be a filename"):
                sample_package_sha256(sample)

    def test_missing_dll_load_telemetry_is_an_execution_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "loader.exe"
            companion = root / "payload.dll"
            sample.write_bytes(b"MZ-loader")
            companion.write_bytes(b"MZ-dll")
            sample_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
            companion_digest = hashlib.sha256(companion.read_bytes()).hexdigest()
            (root / "manifest.json").write_text(json.dumps({"samples": {
                sample.name: {"companions": [companion.name]},
            }}), encoding="utf-8")
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, root, 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")

            def guest_hash(command):
                return companion_digest if companion.name in command else sample_digest

            with patch.object(runner.vmrun, "revert"), patch.object(runner.vmrun, "wait_for_tools"), \
                 patch.object(runner, "_guest_health", return_value={}), patch.object(runner, "_guest_summary", return_value="healthy"), \
                 patch.object(runner.vmrun, "create_directory"), patch.object(runner.vmrun, "copy_to_guest"), \
                 patch.object(runner.vmrun, "run_powershell", side_effect=guest_hash), \
                 patch.object(runner.vmrun, "exists", return_value=True), patch.object(runner.vmrun, "launch"), \
                 patch.object(runner.collector, "wait_for_sample_telemetry", return_value={"status": "OBSERVED"}), \
                 patch.object(runner.collector, "wait_for_companion_telemetry",
                              side_effect=ExecutionFailure("wazuh DLL-load telemetry not observed for: payload.dll")), \
                 patch.object(runner.collector, "collect") as collect:
                report = runner._run_one("wazuh", sample, sample_digest)

            self.assertEqual(report["status"], "EXECUTION_FAILURE")
            self.assertEqual(report["stage"], "RUNTIME")
            collect.assert_not_called()

    def test_defender_cim_failure_cannot_be_reported_as_no_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            (runner.campaign_dir / "evidence").mkdir(parents=True)
            payload = {"defender_events": [], "threat_detections": [], "threat_query_error": "CIM unavailable"}
            with patch.object(runner.vmrun, "copy_to_guest"), \
                 patch.object(runner.vmrun, "run_powershell"), \
                 patch.object(runner.vmrun, "copy_from_guest",
                              side_effect=lambda _source, destination: destination.write_text(json.dumps(payload))) as copy:
                with self.assertRaisesRegex(PipelineError, "Get-MpThreatDetection failed"):
                    runner._collect_defender(r"C:\Detonation\run", SAMPLE_ARTIFACTS, iso_now(), iso_now())
                payload["defender_events"] = [{"id": 1116, "message": r"C:\Detonation\sample.exe"}]
                result = runner._collect_defender(r"C:\Detonation\run", SAMPLE_ARTIFACTS, iso_now(), iso_now())
            self.assertEqual(copy.call_count, 2)
            self.assertEqual(result["status"], "DETECTED")
            self.assertEqual(result["threat_query_error"], "CIM unavailable")
            self.assertEqual(result["matched_artifacts"], [{"name": "sample.exe", "match_reason": "name"}])

    def test_defender_target_paths_are_not_detection_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path(directory), 0, 0, 0, 1, 1, 30)
            runner = Runner(settings, "test")
            (runner.campaign_dir / "evidence").mkdir(parents=True)
            payload = {"target_paths": [SAMPLE_ARTIFACTS[0]["guest_path"]], "defender_events": [],
                       "sysmon_events": [], "threat_detections": [], "threat_query_error": None}
            with patch.object(runner.vmrun, "copy_to_guest"), patch.object(runner.vmrun, "run_powershell"), \
                 patch.object(runner.vmrun, "copy_from_guest",
                              side_effect=lambda _source, destination: destination.write_text(json.dumps(payload))):
                result = runner._collect_defender(r"C:\Detonation\run", SAMPLE_ARTIFACTS, iso_now(), iso_now())
            self.assertEqual(result["status"], "NO_ALERT")
            self.assertEqual(result["matched_artifacts"], [])

    @patch("pipeline.vmrun_pipeline.requests.get")
    def test_elastic_backend_requires_healthy_fleet_server(self, get):
        cluster = Mock(status_code=200)
        cluster.json.return_value = {"status": "green"}
        fleet = Mock(status_code=200)
        fleet.json.return_value = {"status": "HEALTHY"}
        get.side_effect = [cluster, fleet]
        settings = Settings(Path("/tmp/test.vmx"), "guest", "secret", None, Path("/tmp/out"), 1, 1, 1, 1, 1, 30)

        Collector(settings).host_ready("elastic", timeout=1)

        self.assertEqual(get.call_count, 2)
        self.assertEqual(get.call_args_list[1].args[0], "https://127.0.0.1:8220/api/status")

    def test_atomic_json_write_produces_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            atomic_json_write(path, {"status": "COMPLETED"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "COMPLETED")

    @patch("pipeline.vmrun_pipeline.subprocess.run")
    def test_service_manager_does_not_start_an_active_stack(self, run):
        run.return_value.returncode = 0
        self.assertFalse(HostServices().ensure("elastic"))


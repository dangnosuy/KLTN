import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.single_revert.vmrun_pipeline import SingleRevertRunner, SingleRevertVMRun
from pipeline.vmrun_pipeline import PipelineError, Runner, Settings, VMRun


def settings(output: Path) -> Settings:
    return Settings(Path("/tmp/test.vmx"), "guest", "secret", None, output, 1, 1, 1, 1, 1, 30)


class SingleRevertPipelineTests(unittest.TestCase):
    def test_same_snapshot_is_reverted_only_once(self):
        vm = SingleRevertVMRun(settings(Path("/tmp/out")))
        with patch.object(VMRun, "revert") as revert, patch.object(VMRun, "wait_for_tools") as wait:
            vm.revert("elastic")
            vm.wait_for_tools()
            vm.revert("elastic")
            vm.wait_for_tools()
            vm.revert("wazuh")
            vm.wait_for_tools()

        self.assertEqual([call.args[0] for call in revert.call_args_list], ["elastic", "wazuh"])
        self.assertEqual(wait.call_count, 2)

    def test_elastic_readiness_canary_is_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            with patch.object(runner.vmrun, "call") as reset, \
                    patch.object(runner.vmrun, "wait_for_tools") as tools, \
                    patch.object(runner, "_wait_for_guest_health", return_value={"hostname": "LAB"}) as health, \
                    patch.object(runner.vmrun, "run_powershell") as refresh, \
                    patch.object(Runner, "_wait_for_elastic_readiness", return_value={"canary": {"event_id": "1"}}) as ready:
                first = runner._wait_for_elastic_readiness("run-1", {"hostname": "LAB"})
                second = runner._wait_for_elastic_readiness("run-2", {"hostname": "LAB"})

        self.assertEqual(first, second)
        reset.assert_called_once_with("reset", "hard", timeout=30)
        tools.assert_called_once()
        health.assert_called_once_with("elastic")
        ready.assert_called_once()
        refresh.assert_called_once()

    def test_elastic_endpoint_allows_applied_policy_unit_state(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            base_status = {
                "healthy": False,
                "agent_state": 3,
                "agent_message": "1 or more components/units in a degraded state",
                "agent_policy_revision": 11,
                "endpoint": [
                    {"id": "endpoint", "state": 2, "message": "Healthy: communicating with endpoint service"},
                    {"id": None, "state": 3, "message": "Applied policy 'elastic-defend-windows'"},
                ],
            }
            runtime = json.dumps({
                "component_state": 2,
                "units": [{"state": 2, "message": "Applied policy", "output_error": "Success"}],
            })
            with patch.object(Runner, "_elastic_endpoint_status", return_value=base_status), \
                    patch.object(runner.vmrun, "run_powershell", return_value=runtime):
                status = runner._elastic_endpoint_status()

        self.assertTrue(status["healthy"])
        self.assertEqual(status["agent_warning"], base_status["agent_message"])

    def test_elastic_endpoint_rejects_output_error(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            base_status = {
                "healthy": False,
                "agent_state": 3,
                "agent_message": "degraded",
                "agent_policy_revision": 11,
                "endpoint": [
                    {"id": "endpoint", "state": 2, "message": "Healthy"},
                    {"id": None, "state": 3, "message": "Applied policy"},
                ],
            }
            runtime = json.dumps({
                "component_state": 2,
                "units": [{"state": 3, "message": "Applied policy", "output_error": "Unable to connect to output server"}],
            })
            with patch.object(Runner, "_elastic_endpoint_status", return_value=base_status), \
                    patch.object(runner.vmrun, "run_powershell", return_value=runtime):
                status = runner._elastic_endpoint_status()

        self.assertFalse(status["healthy"])
        self.assertEqual(status["endpoint_output_errors"], ["Unable to connect to output server"])

    def test_wazuh_health_requires_manager_tcp(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            with patch.object(Runner, "_guest_health", return_value={"services": []}), \
                    patch.object(runner.vmrun, "run_powershell", return_value='{"server":"192.168.183.1","tcp1514":false}') as powershell:
                with self.assertRaisesRegex(PipelineError, "TCP/1514"):
                    runner._guest_health("wazuh")
        self.assertEqual(powershell.call_count, 3)
        self.assertIn("ipconfig /renew", powershell.call_args_list[1].args[0])

    def test_wazuh_health_recovers_apipa_with_dhcp_renewal(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            with patch.object(Runner, "_guest_health", return_value={"services": []}), \
                    patch.object(
                        runner.vmrun,
                        "run_powershell",
                        side_effect=[
                            '{"server":"192.168.183.1","tcp1514":false}',
                            "Windows IP Configuration",
                            '{"server":"192.168.183.1","tcp1514":true}',
                        ],
                    ) as powershell:
                health = runner._guest_health("wazuh")

        self.assertTrue(health["wazuh_manager"]["tcp1514"])
        self.assertEqual(powershell.call_count, 3)

    def test_cleanup_failure_stops_later_samples_for_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            runner.vmrun.tools_ready = True
            runner.vmrun.active_snapshot = "wazuh"
            completed = {"engine": "wazuh", "status": "COMPLETED", "verdict": "NO_ALERT"}
            failed_cleanup = {"status": "FAILED", "remaining_pids": [321], "directory_removed": True}
            with patch.object(Runner, "_run_one", return_value=completed), \
                    patch.object(runner.vmrun, "cleanup_run", return_value=failed_cleanup), \
                    patch.object(runner, "_guest_health"):
                report = runner._run_one("wazuh", Path("sample.exe"), "a" * 64, "a" * 64)
                skipped = runner._run_one("wazuh", Path("next.exe"), "b" * 64, "b" * 64)

        self.assertEqual(report["status"], "CONTAMINATED")
        self.assertEqual(skipped["status"], "NOT_RUN_CONTAMINATED")

    def test_successful_cleanup_preserves_detection_result(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            runner.vmrun.tools_ready = True
            runner.vmrun.active_snapshot = "wazuh"
            completed = {"engine": "wazuh", "status": "COMPLETED", "verdict": "DETECTED"}
            cleanup = {"status": "PASSED", "remaining_pids": [], "directory_removed": True}
            with patch.object(Runner, "_run_one", return_value=completed), \
                    patch.object(runner.vmrun, "cleanup_run", return_value=cleanup), \
                    patch.object(runner, "_guest_health", return_value={"services": []}):
                report = runner._run_one("wazuh", Path("sample.exe"), "a" * 64, "a" * 64)

        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["verdict"], "DETECTED")
        self.assertEqual(report["cleanup"]["status"], "PASSED")
        self.assertEqual(report["session_validation"]["status"], "PASSED")

    def test_health_failure_does_not_relabel_successful_process_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = SingleRevertRunner(settings(Path(directory)), "test")
            runner.vmrun.tools_ready = True
            runner.vmrun.active_snapshot = "elastic"
            completed = {"engine": "elastic", "status": "COMPLETED", "verdict": "NO_ALERT"}
            cleanup = {"status": "PASSED", "remaining_pids": [], "directory_removed": True}
            with patch.object(Runner, "_run_one", return_value=completed), \
                    patch.object(runner.vmrun, "cleanup_run", return_value=cleanup), \
                    patch.object(runner, "_guest_health", side_effect=PipelineError("Defender enabled")):
                report = runner._run_one("elastic", Path("sample.exe"), "a" * 64, "a" * 64)

        self.assertEqual(report["status"], "CONTAMINATED")
        self.assertEqual(report["cleanup"]["status"], "PASSED")
        self.assertEqual(report["session_validation"]["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()

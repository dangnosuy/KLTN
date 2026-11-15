import unittest

from heldout.cape_behavior_score import has_dynamic_evidence, score_report


def signature(name, severity, confidence, categories, data):
    return {
        "name": name,
        "severity": severity,
        "weight": 1,
        "confidence": confidence,
        "categories": categories,
        "data": data,
    }


class CapeBehaviorScoreTest(unittest.TestCase):
    def test_excludes_static_yara(self):
        yara = signature("procmem_yara", 3, 100, ["malware"], [{"Hit": "rule"}])
        self.assertFalse(has_dynamic_evidence(yara))

    def test_scores_correlated_memory_execution(self):
        report = {
            "behavior": {"processtree": [{"pid": 1}], "processes": [{"calls": [{}, {}]}]},
            "signatures": [
                signature("injection_rwx", 2, 50, ["injection"], [{"pid": 1, "cid": 1}]),
                signature("thread_unbacked_memory", 3, 80, ["execution"], [{"unbacked_memory_threads": []}]),
                signature("unbacked_library_load", 3, 100, ["execution"], [{"unbacked_library_loads": []}]),
                signature("unbacked_process_creation", 3, 100, ["execution"], [{"unbacked_processes": []}]),
                signature("recon_systeminfo", 3, 100, ["discovery"], [{"pid": 1, "cid": 2}]),
                signature("procmem_yara", 3, 100, ["malware"], [{"Hit": "rule"}]),
            ],
        }
        result = score_report(report)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["score"], 7.0)
        self.assertEqual(result["verdict"], "HIGH_RISK")
        self.assertEqual(result["chain_bonus"], 1.0)
        self.assertNotIn("procmem_yara", result["evidence"])

    def test_missing_process_tree_is_infrastructure_failure(self):
        result = score_report({"behavior": {}, "signatures": []})
        self.assertEqual(result["status"], "NO_TELEMETRY")
        self.assertEqual(result["verdict"], "INFRA_FAILURE")
        self.assertIsNone(result["score"])


if __name__ == "__main__":
    unittest.main()

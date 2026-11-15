import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "heldout" / "run_heldout.py"
SPEC = importlib.util.spec_from_file_location("run_heldout", MODULE_PATH)
heldout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(heldout)


class HeldoutPipelineTests(unittest.TestCase):
    def test_collect_samples_accepts_only_pe_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.dll").write_bytes(b"dll")
            (root / "a.exe").write_bytes(b"exe")
            (root / "ignore.bin").write_bytes(b"bin")

            self.assertEqual(
                [path.name for path in heldout.collect_samples(root)],
                ["a.exe", "b.dll"],
            )

    def test_parse_engines_rejects_unknown_engine(self):
        with self.assertRaises(Exception):
            heldout.parse_engines("capa,ember")

    def test_capa_policy_detects_only_configured_attack_ids(self):
        document = {
            "meta": {"version": "10.0.0"},
            "rules": {
                "inject": {
                    "meta": {
                        "namespace": "load-code/inject",
                        "lib": False,
                        "attack": [{"id": "T1055"}],
                    }
                },
                "helper": {
                    "meta": {
                        "lib": True,
                        "attack": [{"id": "T1106"}],
                    }
                },
            },
        }

        result = heldout.classify_capa(
            document,
            {
                "capa_high_risk_attack_ids": ["T1055"],
                "capa_high_risk_namespace_prefixes": ["host-interaction/process/inject"],
            },
        )

        self.assertTrue(result["detected"])
        self.assertEqual(result["triggered_attack_ids"], ["T1055"])
        self.assertEqual(result["matched_rule_count"], 1)

    def test_capa_policy_detects_high_risk_namespace_without_attack_id(self):
        document = {
            "rules": {
                "rwx": {
                    "meta": {
                        "namespace": "host-interaction/process/inject",
                        "lib": False,
                        "attack": [],
                    }
                }
            }
        }

        result = heldout.classify_capa(
            document,
            {
                "capa_high_risk_attack_ids": [],
                "capa_high_risk_namespace_prefixes": ["host-interaction/process/inject"],
            },
        )

        self.assertTrue(result["detected"])
        self.assertEqual(result["triggered_rules"], ["rwx"])

    def test_file_metadata_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"abc")

            metadata = heldout.file_metadata(sample)

            self.assertEqual(metadata["size_bytes"], 3)
            self.assertEqual(
                metadata["sha256"],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )


if __name__ == "__main__":
    unittest.main()

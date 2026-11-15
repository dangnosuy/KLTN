import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SIGNATURE_BASE = Path(__file__).resolve().parents[2] / "Signature-base"
sys.path.insert(0, str(SIGNATURE_BASE))

from malconv_official import MAX_LENGTH, PADDING_TOKEN, prepare_input, scan_file


class MalConvOfficialTests(unittest.TestCase):
    def test_prepare_input_uses_distinct_padding_token(self):
        with tempfile.NamedTemporaryFile() as sample:
            sample.write(bytes([0, 1, 255]))
            sample.flush()

            result = prepare_input(sample.name)

        self.assertEqual(result.shape, (MAX_LENGTH,))
        self.assertEqual(result.dtype.name, "uint16")
        self.assertEqual(result[:4].tolist(), [0, 1, 255, PADDING_TOKEN])

    @mock.patch("malconv_official.subprocess.run")
    def test_scan_file_returns_runner_json(self, run):
        run.return_value = mock.Mock(
            stdout='{"score": 0.9, "detected": true, "verdict": "MALWARE"}\n',
            stderr="",
            returncode=0,
        )

        result = scan_file("sample.exe", python_executable="python")

        self.assertTrue(result["detected"])
        self.assertEqual(result["verdict"], "MALWARE")


if __name__ == "__main__":
    unittest.main()

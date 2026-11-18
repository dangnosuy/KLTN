import tempfile
import unittest
from pathlib import Path

from pipeline.ga_only.operators import Gene, TigressPool
from pipeline.mutators.pool import NativePool
from pipeline.mutators.transforms import MUTATORS


class NativeMutatorTests(unittest.TestCase):
    def test_native_pool_loads_from_json(self):
        pool = TigressPool.load(Path("pipeline/mutators/native_pool.json"))
        self.assertIsInstance(pool, NativePool)
        self.assertTrue(pool.doctor()["ready"])
        self.assertIn("dynamic_api", pool.operators)
        self.assertIn("benign_workload", pool.operators)

    def test_native_transforms_produce_valid_c(self):
        source_code = """#include <windows.h>
int main() {
    void *exec = VirtualAlloc(0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "input.c"
            src.write_text(source_code)
            out = Path(td) / "output.c"

            pool = NativePool()
            genes = (
                Gene("dynamic_api", 10),
                Gene("benign_workload", 20),
                Gene("benign_iat", 30),
                Gene("opaque_predicate", 40),
                Gene("variable_renaming", 50),
                Gene("clean_strip", 60),
            )
            trace = pool.transform(src, genes, out)
            self.assertEqual(len(trace), 6)
            self.assertTrue(out.is_file())

            result_code = out.read_text()
            self.assertIn("NATIVE_DYNAMIC_API_RESOLVED", result_code)
            self.assertIn("NATIVE_BENIGN_WORKLOAD", result_code)
            self.assertIn("NATIVE_BENIGN_IAT", result_code)
            self.assertIn("NATIVE_OPAQUE_PREDICATE", result_code)

    def test_idempotent_transforms(self):
        source_code = """#include <windows.h>
int main() {
    return 0;
}
"""
        code = source_code
        for _ in range(2):
            for name, fn in MUTATORS.items():
                code = fn(code, seed=42)
        self.assertIn("int main", code)


if __name__ == "__main__":
    unittest.main()

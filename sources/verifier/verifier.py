"""
verifier.py - Three-State Behavior Verifier (Contribution C1)
Adaptive Program Transformation for Robustness Evaluation of Malware Detection Systems

Evaluates Windows C source samples and variants against functional contracts:
  - BUILD_FAIL: Compilation failed (syntax error, missing symbol, invalid flags)
  - UNDETERMINED: Compilation succeeded, but execution crashed, timed out, or failed proof marker
  - PASSED_TEST: Compilation succeeded AND 100% functional proof verified
"""

import os
import sys
import json
import time
import shutil
import logging
import argparse
import subprocess
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("BehaviorVerifier")


class VerifierStatus(str, Enum):
    BUILD_FAIL = "BUILD_FAIL"
    UNDETERMINED = "UNDETERMINED"
    PASSED_TEST = "PASSED_TEST"


@dataclass
class SampleContract:
    id: str
    name: str
    group: str
    tactic: str
    technique: str
    description: str
    sources: List[str]
    include_dirs: List[str]
    flags: List[str]
    libraries: List[str]
    timeout_seconds: int
    arguments: List[str]
    expected_exit_code: int
    proof_type: str
    proof_file: str
    expected_marker: str
    alternative_marker: Optional[str] = None
    sysmon_events: List[int] = field(default_factory=list)

    @classmethod
    def from_json(cls, json_path: Path) -> "SampleContract":
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        build_cfg = data.get("build", {})
        exec_cfg = data.get("execution", {})
        verif_cfg = data.get("verification", {})

        return cls(
            id=data.get("id", json_path.stem),
            name=data.get("name", ""),
            group=data.get("group", ""),
            tactic=data.get("tactic", ""),
            technique=data.get("technique", ""),
            description=data.get("description", ""),
            sources=build_cfg.get("sources", [f"{data.get('id', json_path.stem)}.c"]),
            include_dirs=build_cfg.get("include_dirs", ["."]),
            flags=build_cfg.get("flags", ["-O2", "-Wall"]),
            libraries=build_cfg.get("libraries", ["kernel32"]),
            timeout_seconds=exec_cfg.get("timeout_seconds", 15),
            arguments=exec_cfg.get("arguments", []),
            expected_exit_code=exec_cfg.get("expected_exit_code", 0),
            proof_type=verif_cfg.get("proof_type", "file_marker"),
            proof_file=verif_cfg.get("proof_file", "c1_proof.txt"),
            expected_marker=verif_cfg.get("expected_marker", ""),
            alternative_marker=verif_cfg.get("alternative_marker"),
            sysmon_events=verif_cfg.get("sysmon_events", [1])
        )


@dataclass
class VerificationResult:
    sample_id: str
    status: VerifierStatus
    exit_code: Optional[int] = None
    execution_time_ms: int = 0
    proof_matched: bool = False
    matched_marker: Optional[str] = None
    compiler: str = "unknown"
    compile_error: Optional[str] = None
    runtime_error: Optional[str] = None
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "execution_time_ms": self.execution_time_ms,
            "proof_matched": self.proof_matched,
            "matched_marker": self.matched_marker,
            "compiler": self.compiler,
            "compile_error": self.compile_error,
            "runtime_error": self.runtime_error,
            "diagnostics": self.diagnostics
        }


class CompilerAdapter:
    """Manages compiler invocation across MSVC, MinGW GCC, and Clang."""

    def __init__(self, preferred_compiler: str = "auto", vcvars_path: Optional[str] = None):
        self.compiler_type = self._detect_compiler(preferred_compiler)
        self.vcvars_path = vcvars_path or self._find_vcvars()
        logger.info(f"Initialized CompilerAdapter using '{self.compiler_type}' (vcvars: {self.vcvars_path is not None})")

    def _detect_compiler(self, preferred: str) -> str:
        if preferred in ("msvc", "gcc", "clang"):
            return preferred

        # Check GCC / MinGW in PATH
        if shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("gcc"):
            return "gcc"

        # Check Clang in PATH
        if shutil.which("clang"):
            return "clang"

        # Check MSVC
        if shutil.which("cl") or self._find_vcvars():
            return "msvc"

        return "msvc"  # Default fallback on Windows

    def _find_vcvars(self) -> Optional[str]:
        candidates = [
            r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    def compile(self, contract: SampleContract, source_dir: Path, output_binary: Path) -> tuple[bool, str]:
        output_binary.parent.mkdir(parents=True, exist_ok=True)
        source_paths = [str(source_dir / s) for s in contract.sources]

        # Verify all source files exist
        for sp in source_paths:
            if not os.path.isfile(sp):
                return False, f"Source file not found: {sp}"

        if self.compiler_type == "msvc":
            return self._compile_msvc(contract, source_paths, output_binary, source_dir)
        else:
            return self._compile_gcc(contract, source_paths, output_binary, source_dir)

    def _compile_msvc(self, contract: SampleContract, source_paths: List[str], output_binary: Path, source_dir: Path) -> tuple[bool, str]:
        libs = [f"{lib}.lib" if not lib.endswith(".lib") else lib for lib in contract.libraries]
        # Include paths
        inc_args = [f"/I{source_dir}"]
        for inc in contract.include_dirs:
            p = source_dir / inc
            inc_args.append(f"/I{p.resolve()}")

        # Build command line
        obj_file = output_binary.with_suffix(".obj")
        cl_args = [
            "cl.exe",
            "/nologo",
            "/O2",
            "/W3",
            *inc_args,
            *source_paths,
            f"/Fo:{obj_file}",
            "/link",
            *libs,
            f"/out:{output_binary}"
        ]

        if self.vcvars_path:
            full_cmd = f'call "{self.vcvars_path}" >nul 2>&1 && ' + " ".join(f'"{a}"' if " " in a else a for a in cl_args)
            proc = subprocess.run(f'cmd.exe /c "{full_cmd}"', shell=True, capture_output=True, text=True)
        else:
            proc = subprocess.run(cl_args, capture_output=True, text=True)

        # Cleanup intermediate obj file if left behind
        if obj_file.exists():
            try:
                obj_file.unlink()
            except Exception:
                pass

        if proc.returncode == 0 and output_binary.is_file():
            return True, proc.stdout
        else:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            return False, f"MSVC compilation failed (code {proc.returncode}): {err_msg}"

    def _compile_gcc(self, contract: SampleContract, source_paths: List[str], output_binary: Path, source_dir: Path) -> tuple[bool, str]:
        compiler_bin = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("gcc") or "gcc"
        libs = [f"-l{lib}" if not lib.startswith("-l") else lib for lib in contract.libraries]
        inc_args = [f"-I{source_dir}"]
        for inc in contract.include_dirs:
            p = source_dir / inc
            inc_args.append(f"-I{p.resolve()}")

        cmd = [compiler_bin, "-O2", "-Wall", *inc_args, *source_paths, "-o", str(output_binary), *libs]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0 and output_binary.is_file():
            return True, proc.stdout
        else:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            return False, f"GCC compilation failed (code {proc.returncode}): {err_msg}"


class BehaviorVerifier:
    """Core C1 3-State Behavior Verifier Engine."""

    def __init__(
        self,
        dataset_dir: Path,
        build_dir: Optional[Path] = None,
        compiler_type: str = "auto"
    ):
        self.dataset_dir = Path(dataset_dir).resolve()
        self.build_dir = Path(build_dir or (self.dataset_dir / ".." / "verifier" / "build")).resolve()
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.compiler = CompilerAdapter(preferred_compiler=compiler_type)

    def verify_sample(self, contract_path: Path) -> VerificationResult:
        contract_path = Path(contract_path).resolve()
        contract = SampleContract.from_json(contract_path)
        logger.info(f"Verifying sample '{contract.id}' ({contract.name})")

        # Isolated working sandbox directory for execution and proof checking
        sandbox_dir = self.build_dir / f"sandbox_{contract.id}"
        if sandbox_dir.exists():
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        binary_path = sandbox_dir / f"{contract.id}.exe"

        # --- STAGE 1: COMPILATION ---
        t_start_compile = time.perf_counter()
        compile_ok, compile_log = self.compiler.compile(
            contract=contract,
            source_dir=self.dataset_dir,
            output_binary=binary_path
        )
        compile_ms = int((time.perf_counter() - t_start_compile) * 1000)

        if not compile_ok or not binary_path.is_file():
            logger.warning(f"[{contract.id}] State: BUILD_FAIL")
            shutil.rmtree(sandbox_dir, ignore_errors=True)
            return VerificationResult(
                sample_id=contract.id,
                status=VerifierStatus.BUILD_FAIL,
                compiler=self.compiler.compiler_type,
                compile_error=compile_log,
                diagnostics={"compile_ms": compile_ms}
            )

        # --- STAGE 2: EXECUTION & WATCHDOG ---
        proof_file_path = sandbox_dir / contract.proof_file
        if proof_file_path.exists():
            proof_file_path.unlink()

        t_start_exec = time.perf_counter()
        timed_out = False
        exec_error = None
        exit_code = None

        try:
            exec_args = [str(binary_path)] + contract.arguments
            proc = subprocess.run(
                exec_args,
                cwd=str(sandbox_dir),
                capture_output=True,
                text=True,
                timeout=contract.timeout_seconds
            )
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exec_error = f"Execution timed out after {contract.timeout_seconds} seconds"
        except Exception as e:
            exec_error = f"Execution invocation error: {str(e)}"

        exec_ms = int((time.perf_counter() - t_start_exec) * 1000)

        # Check for abnormal exit or timeout
        if timed_out or exit_code != contract.expected_exit_code:
            logger.warning(f"[{contract.id}] State: UNDETERMINED (exit={exit_code}, timeout={timed_out})")
            shutil.rmtree(sandbox_dir, ignore_errors=True)
            return VerificationResult(
                sample_id=contract.id,
                status=VerifierStatus.UNDETERMINED,
                exit_code=exit_code,
                execution_time_ms=exec_ms,
                compiler=self.compiler.compiler_type,
                runtime_error=exec_error or f"Exit code {exit_code} != expected {contract.expected_exit_code}",
                diagnostics={"compile_ms": compile_ms, "timed_out": timed_out}
            )

        # --- STAGE 3: PROOF MARKER VERIFICATION ---
        proof_content = ""
        proof_found = False
        matched_marker = None

        if proof_file_path.is_file():
            proof_found = True
            try:
                proof_content = proof_file_path.read_text(encoding="utf-8").strip()
            except Exception as e:
                proof_content = f"Error reading proof file: {e}"

        # Match expected or alternative marker
        is_expected = (contract.expected_marker in proof_content)
        is_alternative = bool(contract.alternative_marker and (contract.alternative_marker in proof_content))

        if is_expected:
            matched_marker = "EXPECTED"
        elif is_alternative:
            matched_marker = "ALTERNATIVE"

        # Cleanup sandbox directory
        shutil.rmtree(sandbox_dir, ignore_errors=True)

        if proof_found and (is_expected or is_alternative):
            logger.info(f"[{contract.id}] State: PASSED_TEST (Marker: {matched_marker}, Time: {exec_ms}ms)")
            return VerificationResult(
                sample_id=contract.id,
                status=VerifierStatus.PASSED_TEST,
                exit_code=exit_code,
                execution_time_ms=exec_ms,
                proof_matched=True,
                matched_marker=matched_marker,
                compiler=self.compiler.compiler_type,
                diagnostics={
                    "compile_ms": compile_ms,
                    "proof_content": proof_content
                }
            )
        else:
            logger.warning(f"[{contract.id}] State: UNDETERMINED (Proof marker mismatch or missing)")
            return VerificationResult(
                sample_id=contract.id,
                status=VerifierStatus.UNDETERMINED,
                exit_code=exit_code,
                execution_time_ms=exec_ms,
                proof_matched=False,
                compiler=self.compiler.compiler_type,
                runtime_error=f"Proof file missing or marker mismatch. Read: '{proof_content}'",
                diagnostics={
                    "compile_ms": compile_ms,
                    "proof_found": proof_found,
                    "raw_proof": proof_content
                }
            )

    def verify_all(self, manifest_path: Path) -> List[VerificationResult]:
        manifest_path = Path(manifest_path).resolve()
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        results = []
        samples = manifest.get("samples", [])
        logger.info(f"Starting batch verification of {len(samples)} samples from manifest...")

        for s in samples:
            contract_file = self.dataset_dir / s["contract"]
            res = self.verify_sample(contract_file)
            results.append(res)

        return results


def main():
    parser = argparse.ArgumentParser(description="Three-State Behavior Verifier (C1) Runner")
    parser.add_argument("--dataset-dir", default="sources/dataset", help="Path to dataset directory")
    parser.add_argument("--manifest", default="sources/dataset/manifest.json", help="Path to manifest.json")
    parser.add_argument("--sample", help="Sample ID to verify (e.g. g1_01_local_thread)")
    parser.add_argument("--all", action="store_true", help="Verify all samples in manifest")
    parser.add_argument("--compiler", default="auto", choices=["auto", "msvc", "gcc", "clang"])
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    dataset_path = Path(args.dataset_dir).resolve()
    verifier = BehaviorVerifier(dataset_dir=dataset_path, compiler_type=args.compiler)

    if args.sample:
        contract_path = dataset_path / f"{args.sample}.json"
        if not contract_path.is_file():
            print(f"Error: Contract not found: {contract_path}", file=sys.stderr)
            sys.exit(1)
        res = verifier.verify_sample(contract_path)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"Sample: {res.sample_id} | Status: {res.status.value} | Marker: {res.matched_marker} | Time: {res.execution_time_ms}ms")
            if res.status != VerifierStatus.PASSED_TEST:
                print(f"  Compile Err: {res.compile_error}")
                print(f"  Runtime Err: {res.runtime_error}")
        sys.exit(0 if res.status == VerifierStatus.PASSED_TEST else 2)

    elif args.all:
        manifest_path = Path(args.manifest).resolve()
        results = verifier.verify_all(manifest_path)
        passed = sum(1 for r in results if r.status == VerifierStatus.PASSED_TEST)
        build_fail = sum(1 for r in results if r.status == VerifierStatus.BUILD_FAIL)
        undetermined = sum(1 for r in results if r.status == VerifierStatus.UNDETERMINED)

        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print("\n" + "="*70)
            print("C1 BEHAVIOR VERIFICATION SUMMARY REPORT")
            print("="*70)
            print(f"Total Samples   : {len(results)}")
            print(f"PASSED_TEST     : {passed} ({passed/len(results)*100:.1f}%)")
            print(f"UNDETERMINED    : {undetermined}")
            print(f"BUILD_FAIL      : {build_fail}")
            print("="*70)
            for r in results:
                status_icon = "✔" if r.status == VerifierStatus.PASSED_TEST else "✖"
                print(f"[{status_icon}] {r.sample_id:<32} -> {r.status.value:<14} ({r.execution_time_ms}ms)")

        sys.exit(0 if passed == len(results) else 1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

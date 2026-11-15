from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .core import ROOT, digest, failed, local_path, probability, result


def parse_clamav(code, stdout, stderr=""):
    if code not in (0, 1):
        return failed(f"ClamAV scan failed ({code}): {stderr or stdout}")
    threats = [line.rsplit(": ", 1)[-1][:-6] for line in stdout.splitlines() if line.endswith(" FOUND")]
    if code == 1 and not threats:
        return failed("ClamAV reported a detection without threat evidence")
    if code == 0 and (threats or not stdout.strip().endswith(": OK")):
        return failed("ClamAV did not confirm a complete clean scan")
    return result(code == 1, threat_names=threats, returncode=code)


class StaticScanner:
    def __init__(self, config):
        self.config = config["static"]

    def scan(self, engine, artifact):
        timeout = self.config["timeout"]
        if engine == "clamav":
            version = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=timeout, check=True).stdout.strip()
            process = subprocess.run(["clamscan", "--no-summary", "--", artifact["path"]], capture_output=True, text=True, timeout=timeout)
            response = parse_clamav(process.returncode, process.stdout, process.stderr)
            response.update(stdout=process.stdout, stderr=process.stderr, version={"engine_database": version})
            return response
        model = local_path(self.config[f"{engine}_model"])
        command = [str(local_path(self.config["python"])), "-m", "pipeline.detectors.static", engine, artifact["path"], str(model)]
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        if process.returncode:
            return failed(f"{engine} worker failed ({process.returncode}): {process.stderr[-1500:]}")
        lines = [line for line in process.stdout.splitlines() if line.startswith("{")]
        if not lines:
            return failed(f"{engine} worker did not return JSON")
        output = json.loads(lines[-1])
        response = probability(output["score"], self.config[f"{engine}_threshold"])
        response.update(version={**output["version"], "model_sha256": digest(model)}, stderr=process.stderr)
        return response

    def doctor(self, engine):
        if engine == "clamav":
            process = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=15, check=True)
            if process.stdout.count("/") < 2:
                raise RuntimeError("ClamAV did not report a signature database version")
            with tempfile.TemporaryDirectory(prefix="detector-doctor-") as temporary:
                probe = Path(temporary) / "probe.txt"
                probe.write_bytes(b"Detector scanner health check\n")
                scanned = subprocess.run(["clamscan", "--no-summary", "--", str(probe)], capture_output=True, text=True, timeout=self.config["timeout"])
                if parse_clamav(scanned.returncode, scanned.stdout, scanned.stderr)["detected"] is not False:
                    raise RuntimeError("ClamAV failed to load its database and scan a harmless probe")
            return {"engine_database": process.stdout.strip()}
        command = [str(local_path(self.config["python"])), "-m", "pipeline.detectors.static", engine, "--doctor", str(local_path(self.config[f"{engine}_model"]))]
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=self.config["timeout"])
        if process.returncode:
            raise RuntimeError(process.stderr[-1500:] or "Model readiness check failed")
        return json.loads(next(line for line in reversed(process.stdout.splitlines()) if line.startswith("{")))


def worker(engine, path, model):
    model = Path(model)
    if not model.is_file():
        raise FileNotFoundError(f"Model not found: {model}")
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
    if engine == "ember":
        sys.path.insert(0, str(ROOT / "Signature-base/ML-based/EMBER2024/src"))
        import lightgbm
        import thrember
        predictor = lightgbm.Booster(model_file=str(model))
        extractor = thrember.PEFeatureExtractor()
        version = {"lightgbm": lightgbm.__version__, "numpy": importlib.metadata.version("numpy"), "pefile": importlib.metadata.version("pefile"), "extractor_sha256": digest(Path(thrember.__file__).parent / "features.py")}
        if path == "--doctor":
            features = extractor.feature_vector(b"MZ")
            predictor.predict([features])
            return {"version": version, "model_sha256": digest(model)}
        score = float(predictor.predict([extractor.feature_vector(Path(path).read_bytes())])[0])
    elif engine == "malconv":
        sys.path.insert(0, str(ROOT / "Signature-base"))
        from malconv_official import predict_file
        version = {"tensorflow": importlib.metadata.version("tensorflow"), "adapter_sha256": digest(ROOT / "Signature-base/malconv_official.py"), "max_input_bytes": 1 << 20}
        if path == "--doctor":
            import tensorflow as tf
            import numpy as np
            predictor = tf.keras.models.load_model(str(model), compile=False)
            score = float(predictor.predict(np.full((1, 1 << 20), 256, dtype=np.uint16), verbose=0)[0][0])
            probability(score, 0.5)
            return {"version": version, "model_sha256": digest(model)}
        score = predict_file(path, str(model))
    else:
        raise ValueError("Unknown static worker")
    probability(score, 0.5)
    return {"score": score, "version": version}


if __name__ == "__main__":
    print(json.dumps(worker(*sys.argv[1:]), allow_nan=False))

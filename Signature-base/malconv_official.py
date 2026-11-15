#!/usr/bin/env python3
"""Inference adapter for Elastic's pretrained EMBER MalConv model."""

import argparse
import json
import math
import os
import subprocess
import sys
from pathlib import Path

import numpy as np


MAX_LENGTH = 1 << 20
PADDING_TOKEN = 256
DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent
    / "ML-based"
    / "malconv"
    / "Reference"
    / "ember-malconv"
    / "malconv.h5"
)


def prepare_input(file_path: str) -> np.ndarray:
    """Return the 1 MiB uint16 input expected by Elastic's MalConv model."""
    raw = Path(file_path).read_bytes()[:MAX_LENGTH]
    sample = np.full(MAX_LENGTH, PADDING_TOKEN, dtype=np.uint16)
    sample[: len(raw)] = np.frombuffer(raw, dtype=np.uint8)
    return sample


def predict_file(file_path: str, model_path: str = str(DEFAULT_MODEL_PATH)) -> float:
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
    import tensorflow as tf

    model = tf.keras.models.load_model(model_path, compile=False)
    score = float(model.predict(prepare_input(file_path)[None, :], verbose=0)[0][0])
    if not math.isfinite(score):
        raise ValueError(f"MalConv returned a non-finite score: {score}")
    return score


def scan_file(
    file_path: str,
    python_executable: str = sys.executable,
    model_path: str = str(DEFAULT_MODEL_PATH),
    timeout: int = 30,
) -> dict:
    """Run TensorFlow in an isolated interpreter and return a detector result."""
    command = [
        python_executable,
        str(Path(__file__).resolve()),
        file_path,
        "--model",
        model_path,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"detected": False, "verdict": "ERROR", "error": str(exc)}

    for line in reversed(result.stdout.splitlines()):
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    error = result.stderr.strip() or f"MalConv runner exited with code {result.returncode}"
    return {"detected": False, "verdict": "ERROR", "error": error[:500]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Elastic's pretrained MalConv model")
    parser.add_argument("file", help="PE file to classify")
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="Keras model path")
    args = parser.parse_args()

    try:
        score = predict_file(args.file, args.model)
        detected = score >= 0.5
        output = {
            "raw_pred": round(score, 6),
            "score": round(score, 6),
            "threshold": 0.5,
            "detected": detected,
            "verdict": "MALWARE" if detected else "BENIGN",
            "model": "elastic-ember-malconv",
            "note": "Score is probability of malware (1.0 = malware)",
        }
    except Exception as exc:
        output = {"detected": False, "verdict": "ERROR", "error": str(exc)}

    print(json.dumps(output))
    return 0 if output["verdict"] != "ERROR" else 1


if __name__ == "__main__":
    raise SystemExit(main())

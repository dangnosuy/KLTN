#!/usr/bin/env python3
import argparse
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F


class Core1DConvNet(nn.Module):
    """Quo Vadis emulation network architecture from the upstream project."""

    def __init__(self, vocab_size):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, 96, padding_idx=0)
        self.conv1d_module = nn.ModuleList(
            nn.Conv1d(96, 128, kernel_size=size) for size in (2, 3, 4, 5)
        )
        self.ffnn = nn.Sequential(
            nn.Sequential(nn.Linear(512, 1024), nn.BatchNorm1d(1024), nn.ReLU(), nn.Dropout(0.5)),
            nn.Sequential(nn.Linear(1024, 512), nn.BatchNorm1d(512), nn.ReLU(), nn.Dropout(0.5)),
            nn.Sequential(nn.Linear(512, 256), nn.BatchNorm1d(256), nn.ReLU(), nn.Dropout(0.5)),
            nn.Sequential(nn.Linear(256, 128), nn.BatchNorm1d(128), nn.ReLU(), nn.Dropout(0.5)),
        )
        self.fc_output = nn.Linear(128, 2)

    def forward(self, inputs):
        embedded = self.embedding(inputs).permute(0, 2, 1)
        pooled = [F.relu(conv(embedded).permute(0, 2, 1).max(1)[0]) for conv in self.conv1d_module]
        return self.fc_output(self.ffnn(torch.cat(pooled, dim=1)))


def encode_api_sequence(api_sequence, api_map, length=150):
    values = np.array([api_map.get(api, 1) for api in api_sequence], dtype=int)
    if values.shape[0] < length:
        values = np.pad(values, (0, length - values.shape[0]), constant_values=0)
    else:
        values = np.hstack((values[: length // 2], values[-round(length / 2) :]))
    return torch.as_tensor(values.reshape(1, -1), dtype=torch.long)


def emulate_api_sequence(sample, config_path):
    import speakeasy

    config = json.loads(config_path.read_text(encoding="utf-8"))
    emulator = speakeasy.Speakeasy(config=config)
    module = emulator.load_module(str(sample))
    emulator.run_module(module)
    report = emulator.get_report()
    api_sequence = [
        call["api_name"].lower()
        for entry_point in report.get("entry_points", [])
        for call in entry_point.get("apis", [])
        if call.get("api_name")
    ]
    return api_sequence, float(report.get("emulation_total_runtime", 0.0))


def score_sample(sample, assets, threshold):
    started = time.monotonic()
    with (assets / "pickle.apicalls").open("rb") as handle:
        preserved_apis = pickle.load(handle)
    api_map = dict(zip(preserved_apis, range(2, len(preserved_apis) + 2)))

    api_sequence, emulation_seconds = emulate_api_sequence(
        sample, assets / "speakeasy-config.json"
    )
    if not api_sequence:
        raise RuntimeError("Speakeasy produced no API telemetry")

    model = Core1DConvNet(len(api_map) + 2)
    model.load_state_dict(torch.load(assets / "torch.model", map_location="cpu"))
    model.eval()
    with torch.no_grad():
        logits = model(encode_api_sequence(api_sequence, api_map))

    # Preserve the upstream feature transformation used to train its meta-model.
    module_score = float(torch.sigmoid(logits)[0, 1].item())
    with (assets / "meta.model").open("rb") as handle:
        meta_model = pickle.load(handle)
    score = float(meta_model.predict_proba([[module_score]])[0, 1])
    return {
        "status": "COMPLETED",
        "detected": score >= threshold,
        "verdict": "MALWARE" if score >= threshold else "BENIGN",
        "score": round(score, 6),
        "threshold": threshold,
        "module_score": round(module_score, 6),
        "api_call_count": len(api_sequence),
        "api_calls_preview": api_sequence[:20],
        "emulation_seconds": round(emulation_seconds, 3),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "model": "Quo Vadis MLP emulation-only",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", nargs="?", type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--doctor", action="store_true")
    args = parser.parse_args()

    required = ("torch.model", "pickle.apicalls", "meta.model", "speakeasy-config.json")
    missing = [name for name in required if not (args.assets / name).is_file()]
    if missing:
        print(json.dumps({"status": "ERROR", "error": f"Missing assets: {', '.join(missing)}"}))
        return 2

    if args.doctor:
        import sklearn
        import speakeasy

        with (args.assets / "pickle.apicalls").open("rb") as handle:
            preserved_apis = pickle.load(handle)
        model = Core1DConvNet(len(preserved_apis) + 2)
        model.load_state_dict(torch.load(args.assets / "torch.model", map_location="cpu"))
        with (args.assets / "meta.model").open("rb") as handle:
            pickle.load(handle)
        json.loads((args.assets / "speakeasy-config.json").read_text(encoding="utf-8"))
        print(json.dumps({
            "status": "READY",
            "python": sys.version.split()[0],
            "torch": torch.__version__,
            "sklearn": sklearn.__version__,
            "speakeasy": str(Path(speakeasy.__file__).resolve()),
            "api_vocabulary_size": len(preserved_apis),
        }))
        return 0

    if args.sample is None or not args.sample.is_file():
        print(json.dumps({"status": "ERROR", "error": "A readable sample is required"}))
        return 2

    try:
        result = score_sample(args.sample.resolve(), args.assets.resolve(), args.threshold)
    except Exception as exc:
        result = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result))
    return 0 if result["status"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())


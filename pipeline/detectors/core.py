from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENGINES = ("clamav", "ember", "malconv", "defender", "cape")
DEFAULTS = {
    "output_dir": "pipeline/reports/detectors",
    "static": {
        "python": str(Path.home() / "Documents/venv/bin/python3"),
        "timeout": 120,
        "ember_model": "Signature-base/ML-based/EMBER2024/ember2024_models/EMBER2024_PE.model",
        "malconv_model": "Signature-base/ML-based/malconv/Reference/ember-malconv/malconv.h5",
        "ember_threshold": 0.5,
        "malconv_threshold": 0.5,
    },
    "defender": {
        "snapshot": "normal_real",
        "staging_dir": "C:\\DetectorScans",
        "timeout": 180,
    },
    "cape": {
        "url": "http://localhost:8000",
        "machine": "",
        "threshold": 4.0,
        "analysis_timeout": 120,
        "timeout": 900,
        "poll_interval": 10,
        "request_timeout": 15,
        "verify_tls": True,
    },
}


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def json_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def local_path(value):
    path = Path(os.path.expandvars(value)).expanduser()
    return path if path.is_absolute() else ROOT / path


def load_config(path=None):
    config = deepcopy(DEFAULTS)
    if path:
        incoming = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(incoming, dict) or set(incoming) - set(config):
            raise ValueError("Unknown configuration fields; credentials belong in environment variables")
        for key, value in incoming.items():
            if isinstance(config[key], dict):
                if not isinstance(value, dict) or set(value) - set(config[key]):
                    raise ValueError(f"Unknown or invalid {key} configuration")
                config[key].update(value)
            else:
                config[key] = value
    for section in ("static", "defender", "cape"):
        for key, value in config[section].items():
            if key.endswith("threshold") or key == "threshold":
                upper = 10 if section == "cape" else 1
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= upper:
                    raise ValueError(f"Invalid {section}.{key}")
            elif "timeout" in key or key == "poll_interval":
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ValueError(f"{section}.{key} must be a positive integer")
            elif key == "verify_tls":
                if not isinstance(value, bool) or not value:
                    raise ValueError("CAPE TLS verification must remain enabled")
            elif not isinstance(value, str) or (not value and key != "machine"):
                raise ValueError(f"Invalid {section}.{key}")
    if not isinstance(config["output_dir"], str) or not config["output_dir"]:
        raise ValueError("output_dir must be a path")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", config["defender"]["snapshot"]):
        raise ValueError("Invalid Defender snapshot name")
    if not re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9_-]+(?:\\[A-Za-z0-9_-]+)*", config["defender"]["staging_dir"]):
        raise ValueError("Defender staging_dir must be a dedicated absolute Windows directory")
    from urllib.parse import urlsplit
    url = urlsplit(config["cape"]["url"])
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("CAPE URL must be an HTTP(S) URL without credentials/query/fragment")
    if url.scheme == "http" and url.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Remote CAPE requires HTTPS; use localhost for local HTTP")
    return config


def validate_pe(path):
    with Path(path).open("rb") as handle:
        header = handle.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError(f"Not a PE file: {path}")
        offset = struct.unpack_from("<I", header, 60)[0]
        if offset < 64 or offset > Path(path).stat().st_size - 24:
            raise ValueError(f"Invalid PE header offset: {path}")
        handle.seek(offset)
        if handle.read(4) != b"PE\0\0":
            raise ValueError(f"Invalid PE signature: {path}")
        coff = handle.read(20)
        machine, sections = struct.unpack_from("<HH", coff)
        optional_size, characteristics = struct.unpack_from("<HH", coff, 16)
        if machine not in (0x14C, 0x8664, 0xAA64) or not sections or optional_size < 2 or not characteristics & 0x0002 or characteristics & 0x2000:
            raise ValueError(f"Expected an executable PE image, not a DLL: {path}")
        if offset + 24 + optional_size + sections * 40 > Path(path).stat().st_size:
            raise ValueError(f"Truncated PE headers: {path}")
        if handle.read(2) not in (b"\x0b\x01", b"\x0b\x02"):
            raise ValueError(f"Invalid PE optional header: {path}")


def package(sample):
    sample = Path(sample).absolute()
    if sample.suffix.lower() != ".exe" or not sample.is_file():
        raise ValueError(f"Expected an existing EXE: {sample}")
    validate_pe(sample)
    manifest = sample.parent / "manifest.json"
    metadata = {}
    if manifest.exists():
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("samples"), dict):
            raise ValueError("manifest.json must contain a samples object")
        metadata = document["samples"].get(sample.name, {})
        if not isinstance(metadata, dict):
            raise ValueError("Invalid sample manifest entry")
    companions = metadata.get("companions", [])
    if not isinstance(companions, list) or not all(isinstance(name, str) for name in companions):
        raise ValueError("companions must be a list of filenames")
    names = {sample.name.casefold()}
    paths = [("primary", sample)]
    for name in sorted(companions, key=str.casefold):
        if not isinstance(name, str) or not name or name in (".", "..") or re.search(r'[<>:"/\\|?*\x00-\x1f,=]', name) or name.endswith((".", " ")):
            raise ValueError("Companions must be safe filenames within the sample directory")
        if name.casefold() in names:
            raise ValueError(f"Duplicate artifact: {name}")
        names.add(name.casefold())
        path = sample.parent / name
        if not path.is_file():
            raise ValueError(f"Missing companion: {name}")
        paths.append(("companion", path))
    # The same filename becomes a Windows path, ZIP entry, and CAPE option.
    if re.search(r'[<>:"/\\|?*\x00-\x1f,=]', sample.name) or sample.name.endswith((".", " ")):
        raise ValueError("Unsafe primary filename")
    artifacts = [{"name": path.name, "role": role, "path": str(path), "sha256": digest(path), "size_bytes": path.stat().st_size} for role, path in paths]
    identity = [{key: item[key] for key in ("name", "role", "sha256")} for item in artifacts]
    return {"name": sample.name, "sha256": artifacts[0]["sha256"], "package_sha256": json_hash(identity), "artifacts": artifacts}


def unchanged(sample):
    for item in sample["artifacts"]:
        if digest(item["path"]) != item["sha256"]:
            raise ValueError(f"Input changed after registration: {item['name']}")


def result(detected=None, *, status="COMPLETED", **details):
    if status != "COMPLETED":
        detected = None
    elif not isinstance(detected, bool):
        raise ValueError("Completed results require a boolean detected value")
    return {"status": status, "verdict": ("DETECTED" if detected else "NO_ALERT") if status == "COMPLETED" else "N/A", "detected": detected, **details}


def failed(error, status="ERROR"):
    return result(status=status, error=str(error))


def probability(value, threshold):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("Model score must be finite and within [0, 1]")
    return result(value >= threshold, score=value, threshold=threshold)


def log(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)

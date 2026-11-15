#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="$ROOT/.tools"
CAPA_DIR="$TOOLS/capa"
QV_DIR="$TOOLS/quo-vadis"

CAPA_VERSION="10.0.0"
CAPA_ZIP_SHA256="96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca"
CAPA_URL="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip"

download_checked() {
    local url="$1"
    local output="$2"
    local expected="$3"
    mkdir -p "$(dirname "$output")"
    curl -fsSL --retry 5 --retry-all-errors "$url" -o "$output"
    echo "$expected  $output" | sha256sum --check --status
}

install_capa() {
    local archive="$TOOLS/capa-v${CAPA_VERSION}-linux.zip"
    if [[ -x "$CAPA_DIR/capa" ]] && [[ "$($CAPA_DIR/capa --version)" == "capa ${CAPA_VERSION}" ]]; then
        echo "[setup] capa v${CAPA_VERSION} already installed"
        return
    fi
    echo "[setup] Installing capa v${CAPA_VERSION}"
    download_checked "$CAPA_URL" "$archive" "$CAPA_ZIP_SHA256"
    mkdir -p "$CAPA_DIR"
    unzip -oq "$archive" -d "$CAPA_DIR"
    chmod +x "$CAPA_DIR/capa"
    rm -f "$archive"
    "$CAPA_DIR/capa" --version
}

install_quo_vadis() {
    command -v uv >/dev/null 2>&1 || {
        echo "ERROR: uv is required to create the isolated Python 3.9 environment." >&2
        exit 1
    }

    echo "[setup] Installing Quo Vadis emulation-only environment"
    if [[ ! -x "$QV_DIR/venv/bin/python" ]]; then
        uv venv --python 3.9 "$QV_DIR/venv"
    fi
    uv pip install --python "$QV_DIR/venv/bin/python" setuptools==68.2.2
    uv pip install --python "$QV_DIR/venv/bin/python" \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        torch==1.12.1+cpu \
        numpy==1.23.5 \
        scikit-learn==1.1.1 \
        pandas==1.4.4 \
        pefile==2022.5.30 \
        speakeasy-emulator==1.5.11

    download_checked \
        "https://raw.githubusercontent.com/dtrizna/quo.vadis/main/modules/emulation/pretrained/torch.model" \
        "$QV_DIR/torch.model" \
        "ca77af297a99cd055c408afe4dc12bb083c2360c3356eff6fc1cfe0d21ebaefd"
    download_checked \
        "https://raw.githubusercontent.com/dtrizna/quo.vadis/main/modules/emulation/pretrained/pickle.apicalls" \
        "$QV_DIR/pickle.apicalls" \
        "f5a8b6392f57037b3487acf33b25fcfe86e20413a86d3b1b0af3921e84fa5ff5"
    download_checked \
        "https://raw.githubusercontent.com/dtrizna/quo.vadis/main/modules/meta_model/MultiLayerPerceptron15_emulation.model" \
        "$QV_DIR/meta.model" \
        "bf2f9a77f986b7bb22c570349e4a760001cc82712e8c9693579b7fcf689d6f4b"
    download_checked \
        "https://raw.githubusercontent.com/dtrizna/quo.vadis/main/data/emulation.dataset/sample_emulation/speakeasy_config.json" \
        "$QV_DIR/speakeasy-config.json" \
        "4eb66cf79e87512168b6e4402f64ae7ed3ca33d27d7255cc0bbd1fa707222aa4"
}

mkdir -p "$TOOLS"
install_capa
install_quo_vadis
echo "[setup] Held-out signature and ML detectors are ready."


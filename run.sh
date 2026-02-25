#!/usr/bin/env bash
set -e

echo "✦ God's Hands v3.0 Launcher ✦"
echo "Searching for compatible Python environment..."

# Prefer python3, fall back to python
if command -v python3 &>/dev/null; then
    PY="python3"
elif command -v python &>/dev/null; then
    PY="python"
else
    echo "[ERROR] Python not found. Install Python 3.10+ first."
    exit 1
fi

# Version check (need >= 3.10)
PY_VERSION=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[OK] Found Python $PY_VERSION. Launching..."

# Install deps if needed
if ! $PY -c "import cryptography" &>/dev/null; then
    echo "Installing dependencies..."
    $PY -m pip install -r requirements.txt
fi

# pywebview on Linux needs GTK
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if ! $PY -c "import gi" &>/dev/null; then
        echo ""
        echo "[NOTE] pywebview on Linux requires GTK3. Install with:"
        echo "  sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1"
        echo ""
    fi
fi

$PY app.py

#!/usr/bin/env bash
# deps -> vmlinux -> make -> demo
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[1/4] deps"
sudo bash scripts/setup_deps_ubuntu.sh

echo "[2/4] vmlinux.h"
bash scripts/gen_vmlinux.sh

echo "[3/4] build"
make clean || true
make

echo "[4/4] demo"
sudo bash scripts/demo.sh

echo "OK: bin/netmon ready"

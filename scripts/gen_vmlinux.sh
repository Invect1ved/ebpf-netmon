#!/usr/bin/env bash
# Генерация bpf/vmlinux.h из BTF работающего ядра (CO-RE)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bpf/vmlinux.h"
BTF="${BTF_PATH:-/sys/kernel/btf/vmlinux}"

if [[ ! -r "$BTF" ]]; then
  echo "Нет BTF: $BTF" >&2
  echo "Нужно ядро с CONFIG_DEBUG_INFO_BTF=y" >&2
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool не найден. Установите linux-tools / bpftool." >&2
  exit 1
fi

echo "Generating $OUT from $BTF ..."
bpftool btf dump file "$BTF" format c > "$OUT"
echo "Done ($(wc -l < "$OUT") lines)."

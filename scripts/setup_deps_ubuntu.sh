#!/usr/bin/env bash
# Установка зависимостей для Ubuntu 22.04 / 24.04
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Запустите с sudo: sudo $0" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update

pkgs=(
  build-essential
  clang
  llvm
  pkg-config
  libelf-dev
  zlib1g-dev
  libbpf-dev
  linux-tools-common
  iproute2
  iputils-ping
  curl
  netcat-openbsd
  python3
)

# на WSL нет headers/tools под microsoft-ядро — берём generic
kver="$(uname -r)"
if [[ "$kver" == *microsoft* || "$kver" == *WSL* ]]; then
  pkgs+=(linux-tools-generic)
else
  pkgs+=("linux-headers-$kver" "linux-tools-$kver")
fi

apt-get install -y "${pkgs[@]}"

# wrapper из linux-tools-common ищет tools под uname -r — на WSL его нет
real="$(find /usr/lib/linux-tools-* -name bpftool -type f 2>/dev/null | head -n1 || true)"
if [[ -n "$real" ]]; then
  ln -sf "$real" /usr/local/bin/bpftool
  ln -sf "$real" /usr/sbin/bpftool
fi
hash -r 2>/dev/null || true

if ! bpftool version >/dev/null 2>&1; then
  echo "bpftool так и не завёлся" >&2
  exit 1
fi

echo
echo "OK. Дальше:"
echo "  ./scripts/gen_vmlinux.sh"
echo "  make"
echo "  sudo ./bin/netmon"

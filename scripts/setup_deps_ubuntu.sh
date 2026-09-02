#!/usr/bin/env bash
# Установка зависимостей для Ubuntu 22.04 / 24.04
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Запустите с sudo: sudo $0" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  build-essential \
  clang \
  llvm \
  pkg-config \
  libelf-dev \
  zlib1g-dev \
  libbpf-dev \
  linux-headers-$(uname -r) \
  linux-tools-common \
  linux-tools-$(uname -r) \
  bpftool \
  iproute2 \
  iputils-ping \
  curl \
  netcat-openbsd \
  python3

echo
echo "OK. Дальше:"
echo "  ./scripts/gen_vmlinux.sh"
echo "  make"
echo "  sudo ./bin/netmon"

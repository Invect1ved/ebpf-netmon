#!/usr/bin/env bash
# Короткое демо: TCP + UDP трафик на фоне агента
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/netmon"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Нужен root: sudo $0" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "Сначала: make" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

echo "[demo] start agent..."
"$BIN" --stats 3 >"$WORKDIR/agent.log" 2>"$WORKDIR/agent.err" &
AGENT_PID=$!
sleep 1

echo "[demo] TCP: local python http + curl"
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
HTTP_PID=$!
sleep 0.5
curl -s -o /dev/null http://127.0.0.1:18080/ || true
kill "$HTTP_PID" 2>/dev/null || true

echo "[demo] UDP: nc echo"
nc -u -l -p 18081 -w 2 >/dev/null 2>&1 &
sleep 0.3
echo "hello-udp" | nc -u -w 1 127.0.0.1 18081 || true

sleep 4
kill -INT "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

echo
echo "=== agent stdout (tail) ==="
tail -n 40 "$WORKDIR/agent.log" || true
echo
echo "=== agent stderr ==="
cat "$WORKDIR/agent.err" || true
echo
echo "[demo] done"

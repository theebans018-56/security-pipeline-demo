#!/usr/bin/env bash
# SSH compliance-test DEMO (best-effort, never fails the job).
# Tries a throwaway SSH container; if unavailable, falls back to a local read-only check.
# Always writes host_results.json and always exits 0. Synthetic target only; no real device.

WORK="${1:-$PWD}"
KEY="$WORK/id_demo"
OUT="$WORK/host_results.json"
PORT=2222
OBSERVED=""
HOST=""

cleanup() { docker stop demo-sshd >/dev/null 2>&1 || true; rm -f "$KEY" "$KEY.pub"; }
trap cleanup EXIT

try_ssh() {
  command -v docker >/dev/null 2>&1 || return 1
  rm -f "$KEY" "$KEY.pub"
  ssh-keygen -t ed25519 -N "" -f "$KEY" -q || return 1
  docker run -d --rm --name demo-sshd \
    -e PUID=1000 -e PGID=1000 -e USER_NAME=tester \
    -e PUBLIC_KEY="$(cat "$KEY.pub")" \
    -p ${PORT}:2222 linuxserver/openssh-server >/dev/null 2>&1 || return 1
  for i in $(seq 1 20); do
    OBSERVED=$(ssh -i "$KEY" -p $PORT -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
      tester@127.0.0.1 "openssl version" 2>/dev/null) && [ -n "$OBSERVED" ] && { HOST="demo-sshd(container)"; return 0; }
    sleep 2
  done
  return 1
}

echo "[compliance] attempting SSH compliance test against throwaway container..."
if try_ssh; then
  echo "[compliance] SSH OK -> $OBSERVED"
else
  echo "[compliance] SSH container unavailable; falling back to local read-only check"
  OBSERVED=$(openssl version 2>/dev/null || echo "unknown")
  HOST="local(fallback)"
fi

# Recipe: target must run a TLS-1.2-capable OpenSSL (>= 1.1)
NUM=$(echo "$OBSERVED" | grep -oE '[0-9]+\.[0-9]+' | head -1)
MAJ=${NUM%%.*}; MIN=${NUM##*.}
if [ -n "$MAJ" ] && { [ "$MAJ" -gt 1 ] 2>/dev/null || { [ "$MAJ" -eq 1 ] && [ "$MIN" -ge 1 ]; }; }; then
  VERDICT=PASS
else
  VERDICT=FAIL
fi

cat > "$OUT" <<JSON
[
  { "test_id": "CTRL-SSH-001",
    "title": "Target supports TLS 1.2 (OpenSSL >= 1.1)",
    "command": "openssl version (over SSH or local fallback)",
    "observed": "${OBSERVED:-unknown}",
    "verdict": "$VERDICT",
    "cwe": "CWE-327", "severity": "Medium",
    "host": "${HOST:-unknown}" }
]
JSON

echo "[compliance] wrote $OUT ($VERDICT, host=$HOST)"
exit 0

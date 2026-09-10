#!/usr/bin/env bash
# SSH compliance-test DEMO: creates an ephemeral SSH key, starts a throwaway
# SSH-enabled container, SSHes in, runs a READ-ONLY compliance check, and writes
# a PASS/FAIL result. No real host, no committed key. Synthetic target only.
set -euo pipefail

WORK="${1:-$PWD}"
KEY="$WORK/id_demo"
OUT="$WORK/host_results.json"

echo "[ssh] generating ephemeral key (not committed)"
rm -f "$KEY" "$KEY.pub"
ssh-keygen -t ed25519 -N "" -f "$KEY" -q

echo "[ssh] starting throwaway SSH container (linuxserver/openssh-server)"
PORT=2222
docker run -d --rm --name demo-sshd \
  -e PUID=1000 -e PGID=1000 -e USER_NAME=tester \
  -e PUBLIC_KEY="$(cat "$KEY.pub")" \
  -p ${PORT}:2222 linuxserver/openssh-server >/dev/null

echo "[ssh] waiting for sshd..."
for i in $(seq 1 30); do
  if ssh -i "$KEY" -p $PORT -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
       tester@127.0.0.1 "echo up" >/dev/null 2>&1; then break; fi
  sleep 2
done

echo "[ssh] running read-only compliance check over SSH"
# Recipe: 'the target must run a supported OpenSSL (>= 1.1, i.e. TLS 1.2 capable)'
OBSERVED=$(ssh -i "$KEY" -p $PORT -o StrictHostKeyChecking=no tester@127.0.0.1 \
  "openssl version 2>/dev/null || echo unknown")

MAJOR=$(echo "$OBSERVED" | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
MINOR=$(echo "$OBSERVED" | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f2)
if [ -n "${MAJOR:-}" ] && { [ "$MAJOR" -gt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -ge 1 ]; }; }; then
  VERDICT=PASS
else
  VERDICT=FAIL
fi
echo "[ssh] observed: $OBSERVED -> $VERDICT"

cat > "$OUT" <<JSON
[
  { "test_id": "CTRL-SSH-001",
    "title": "Target supports TLS 1.2 (OpenSSL >= 1.1)",
    "command": "ssh target 'openssl version'",
    "observed": "$OBSERVED",
    "verdict": "$VERDICT",
    "cwe": "CWE-327", "severity": "Medium",
    "host": "demo-sshd(container)" }
]
JSON

echo "[ssh] wrote $OUT"
docker stop demo-sshd >/dev/null 2>&1 || true
rm -f "$KEY" "$KEY.pub"
echo "[ssh] cleaned up (container stopped, key removed)"

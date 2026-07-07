#!/usr/bin/env bash
# One-shot: back up, swap the nurproxy-agent binary on durox, restart, verify.
# Run as root on durox. Rollback hints printed at the end.
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
NEW=/tmp/nurproxy-agent.new
BIN=/usr/bin/nurproxy-agent
DATA=/var/lib/nurproxy-agent

[ -x "$NEW" ] || { echo "FATAL: $NEW missing/not executable"; exit 1; }

echo "=== 1. nginx sane before we touch anything ==="
nginx -t

echo "=== 2. backups (tag $TS) ==="
cp -a "$BIN" "${BIN}.bak-${TS}"
cp -a "$DATA" "${DATA}.bak-${TS}"
tar czf "/tmp/durox-nginx-${TS}.tgz" -C / etc/nginx
echo "binary  -> ${BIN}.bak-${TS}"
echo "datadir -> ${DATA}.bak-${TS}"
echo "nginx   -> /tmp/durox-nginx-${TS}.tgz"

echo "=== 3. versions ==="
echo -n "old: "; "$BIN" --version 2>/dev/null || echo "(no --version flag)"
echo -n "new build staged at $NEW"; echo

echo "=== 4. swap binary + restart agent ==="
systemctl stop nurproxy-agent
install -m755 "$NEW" "$BIN"
systemctl start nurproxy-agent
sleep 4

echo "=== 5. verify agent ==="
systemctl is-active nurproxy-agent
journalctl -u nurproxy-agent --since "40 seconds ago" --no-pager | tail -25

echo "=== 6. verify nginx unaffected ==="
nginx -t
systemctl is-active nginx

echo
echo "=== DONE. Rollback if needed: ==="
echo "  systemctl stop nurproxy-agent"
echo "  install -m755 ${BIN}.bak-${TS} ${BIN}"
echo "  rm -rf ${DATA} && mv ${DATA}.bak-${TS} ${DATA}   # only if datadir changed badly"
echo "  systemctl start nurproxy-agent"
echo "  # nginx config snapshot: /tmp/durox-nginx-${TS}.tgz"

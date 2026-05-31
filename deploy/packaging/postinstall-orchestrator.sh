#!/bin/sh
# Post-install for the nurproxy orchestrator package. The orchestrator starts
# with sane defaults, so enable + start it straight away.
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable --now nurproxy.service || true
  echo "nurproxy started. Open the dashboard on the configured port (default 8080)."
  echo "Edit /etc/nurproxy/nurproxy.env and 'systemctl restart nurproxy' to change it."
fi

#!/bin/sh
# Post-install for the nurproxy orchestrator package. The orchestrator starts
# with sane defaults, so enable + start it straight away.
set -e

# Apply the same idempotent, no-symlink migration used at normal startup before
# starting (or restarting) a packaged service. A failure is intentionally fatal.
/usr/bin/nurproxy permissions --data-dir /var/lib/nurproxy

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable --now nurproxy.service || true
  # On an UPGRADE the unit may have changed; enable --now does not restart an
  # already-running service, so try-restart picks up the new unit. (Fresh install:
  # enable --now just started it, so this is a harmless no-op restart.)
  systemctl try-restart nurproxy.service || true
  echo "nurproxy started. Open the dashboard on the configured port (default 8080)."
  echo "Edit /etc/nurproxy/nurproxy.env and 'systemctl restart nurproxy' to change it."
fi

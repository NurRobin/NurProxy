#!/bin/sh
# Post-install for the nurproxy orchestrator package. The orchestrator starts
# with sane defaults, so enable + start it straight away.
set -e

data_dir=/var/lib/nurproxy
if [ -r /etc/nurproxy/nurproxy.env ]; then
  configured_data_dir=$(sed -n 's/^NP_DATA_DIR=//p' /etc/nurproxy/nurproxy.env | tail -n 1)
  if [ -n "$configured_data_dir" ]; then
    data_dir=$configured_data_dir
  fi
fi
/usr/bin/nurproxy permissions --data-dir "$data_dir" --systemd-drop-in /etc/systemd/system/nurproxy.service.d/data-dir.conf

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now nurproxy.service
  # On an UPGRADE the unit may have changed; enable --now does not restart an
  # already-running service, so try-restart picks up the new unit. (Fresh install:
  # enable --now just started it, so this is a harmless no-op restart.)
  systemctl try-restart nurproxy.service
  echo "nurproxy started. Open the dashboard on the configured port (default 8080)."
  echo "Edit /etc/nurproxy/nurproxy.env and 'systemctl restart nurproxy' to change it."
fi

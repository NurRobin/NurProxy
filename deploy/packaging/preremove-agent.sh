#!/bin/sh
# Stop and disable the service on real removal (not on upgrade).
# deb passes "remove"; rpm passes "0" on final erase.
set -e
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now nurproxy-agent.service 2>/dev/null || true
  fi
fi

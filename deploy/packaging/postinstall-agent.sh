#!/bin/sh
# Post-install for the nurproxy-agent package. The agent needs a per-host
# orchestrator URL and FQDN before it can start, so the unit is left disabled
# until the admin fills in the env file.
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  # On an UPGRADE, restart a running agent so it actually picks up the new unit —
  # the systemd sandbox (ProtectSystem/ReadWritePaths) is built at process start,
  # so daemon-reload alone leaves the live process on the old, stale sandbox.
  # try-restart only acts when the service is already running, so a FRESH install
  # (intentionally left disabled until `setup`) stays untouched.
  systemctl try-restart nurproxy-agent.service || true
fi

echo "NurProxy agent installed. Finish setup with:"
echo "  sudo nurproxy-agent setup"
echo
echo "That asks for the orchestrator URL and this agent's FQDN, then starts the"
echo "service. (Manual alternative: edit /etc/nurproxy-agent/agent.env and run"
echo "'systemctl enable --now nurproxy-agent'.)"

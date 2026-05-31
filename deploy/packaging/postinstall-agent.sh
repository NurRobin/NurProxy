#!/bin/sh
# Post-install for the nurproxy-agent package. The agent needs a per-host
# orchestrator URL and FQDN before it can start, so the unit is left disabled
# until the admin fills in the env file.
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

echo "NurProxy agent installed. Configure it, then enable the service:"
echo "  edit /etc/nurproxy-agent/agent.env   # set NP_ORCHESTRATOR and NP_FQDN"
echo "  systemctl enable --now nurproxy-agent"

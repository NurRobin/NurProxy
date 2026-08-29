#!/bin/sh
set -e

agent_was_active=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet nurproxy-agent.service; then
    agent_was_active=1
    systemctl stop nurproxy-agent.service
  fi
  if systemctl is-active --quiet nurproxy-agent-helper.service; then
    systemctl stop nurproxy-agent-helper.service
  fi
  if systemctl is-active --quiet nurproxy-agent-helper.socket; then
    systemctl stop nurproxy-agent-helper.socket
  fi
fi

if ! getent group nurproxy >/dev/null 2>&1; then
  groupadd --system nurproxy
fi
if ! id -u nurproxy >/dev/null 2>&1; then
  nologin_shell=$(command -v nologin || printf '%s' /usr/sbin/nologin)
  useradd --system --gid nurproxy --home-dir /var/lib/nurproxy-agent/state --shell "$nologin_shell" nurproxy
fi

legacy_dropin_backup=/var/backups/nurproxy-agent/legacy-dropins
install -d -o root -g root -m 0700 "$legacy_dropin_backup"
disable_legacy_dropin() {
  legacy_path=$1
  expected_digest=$2
  if [ ! -e "$legacy_path" ] && [ ! -L "$legacy_path" ]; then
    return
  fi
  if [ ! -f "$legacy_path" ] || [ -L "$legacy_path" ]; then
    echo "NurProxy refuses non-regular legacy drop-in: $legacy_path" >&2
    exit 1
  fi
  actual_digest=$(sha256sum "$legacy_path" | awk '{print $1}')
  if [ "$actual_digest" != "$expected_digest" ]; then
    echo "NurProxy refuses modified operator drop-in: $legacy_path" >&2
    exit 1
  fi
  backup_path="$legacy_dropin_backup/${legacy_path##*/}"
  if [ -e "$backup_path" ] || [ -L "$backup_path" ]; then
    echo "NurProxy legacy drop-in backup already exists: $backup_path" >&2
    exit 1
  fi
  mv -- "$legacy_path" "$backup_path"
}

disable_legacy_dropin /etc/systemd/system/nurproxy-agent.service.d/10-cap-chown.conf 71c1b1e52be6db3695cae1bdd93d4099b5f6ef47ef8334e4d1b333729ff2e9e7
disable_legacy_dropin /etc/systemd/system/nurproxy-agent.service.d/10-nurproxy-writepaths.conf 50aaeffd8375da927c66d2e9d22af9e5ee834ffb12b18f8db6125d27da4437de
disable_legacy_dropin /etc/systemd/system/nurproxy-agent.service.d/20-nurproxy-caps.conf c39e4fa9d6b5f78b4a6e33d616e72acb9b4c8299377ad7f36f40a81359edc87a

install -d -o root -g root -m 0755 /var/lib/nurproxy-agent
install -d -o nurproxy -g nurproxy -m 0700 /var/lib/nurproxy-agent/state

for entry in /var/lib/nurproxy-agent/* /var/lib/nurproxy-agent/.[!.]* /var/lib/nurproxy-agent/..?*; do
  if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then
    continue
  fi
  name=${entry##*/}
  case "$name" in
    state|helper|helper-staging|certs) continue ;;
  esac
  if [ -e "/var/lib/nurproxy-agent/state/$name" ] || [ -L "/var/lib/nurproxy-agent/state/$name" ]; then
    echo "NurProxy agent state migration collision: $name" >&2
    exit 1
  fi
  mv -- "$entry" /var/lib/nurproxy-agent/state/
done

find /var/lib/nurproxy-agent/state -xdev -exec chown -h nurproxy:nurproxy {} +
chmod 0700 /var/lib/nurproxy-agent/state

install -d -o root -g nurproxy -m 0770 /var/lib/nurproxy-agent/helper-staging
install -d -o root -g root -m 0700 /var/lib/nurproxy-agent/helper
install -d -o root -g root -m 0700 /var/lib/nurproxy-agent/certs
find /var/lib/nurproxy-agent/helper /var/lib/nurproxy-agent/certs -xdev -exec chown -h root:root {} +

install -d -o root -g root -m 0755 /etc/nurproxy-agent
if [ -e /etc/nurproxy-agent/agent.env ]; then
  chown root:nurproxy /etc/nurproxy-agent/agent.env
  chmod 0640 /etc/nurproxy-agent/agent.env
fi

if command -v systemctl >/dev/null 2>&1; then

  /usr/bin/nurproxy-agent helper-refresh-build
  systemctl daemon-reload
  systemctl enable --now nurproxy-agent-helper.socket
  if [ "$agent_was_active" -eq 1 ]; then
    systemctl start nurproxy-agent.service
  fi
fi

echo "NurProxy agent installed. Finish setup with:"
echo "  sudo nurproxy-agent setup"
echo
echo "That asks for the orchestrator URL and this agent's FQDN, then starts the service."

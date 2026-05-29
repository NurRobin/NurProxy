#!/usr/bin/env bash
#
# NurProxy installer — downloads the latest release binaries and installs them
# to a bin directory. After this, run the per-component setup:
#
#   sudo nurproxy install --port 8080
#   sudo nurproxy-agent install --orchestrator https://np.example.com --fqdn edge1.example.com
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NurRobin/NurProxy/main/scripts/install.sh | bash
#   ... | bash -s -- --component agent --version v1.2.3 --bin-dir /usr/local/bin
#
# Env overrides: REPO, VERSION, INSTALL_DIR, COMPONENT.

set -euo pipefail

REPO="${REPO:-NurRobin/NurProxy}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
COMPONENT="${COMPONENT:-both}" # orchestrator | agent | both

while [ $# -gt 0 ]; do
  case "$1" in
    --component) COMPONENT="$2"; shift 2 ;;
    --version)   VERSION="$2"; shift 2 ;;
    --bin-dir)   INSTALL_DIR="$2"; shift 2 ;;
    --repo)      REPO="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

err() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$os" = "linux" ] || err "only linux is supported by the prebuilt binaries (got: $os)"

case "$(uname -m)" in
  x86_64|amd64)   arch="amd64" ;;
  aarch64|arm64)  arch="arm64" ;;
  armv7l|armv7)   arch="armv7" ;;
  *) err "unsupported architecture: $(uname -m)" ;;
esac

# Resolve the release we're installing from.
if [ "$VERSION" = "latest" ]; then
  api="https://api.github.com/repos/${REPO}/releases/latest"
else
  api="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi
info "fetching release metadata (${VERSION}) for ${REPO}"
release_json="$(curl -fsSL "$api")" || err "could not fetch release metadata"

# sudo only if we can't write to the target dir ourselves.
SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else err "cannot write to ${INSTALL_DIR} and sudo not found"; fi
fi
$SUDO mkdir -p "$INSTALL_DIR"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

install_component() {
  comp="$1"
  # Match the GoReleaser asset: <comp>_<version>_linux_<arch>.tar.gz
  url="$(printf '%s' "$release_json" \
    | grep -o '"browser_download_url": *"[^"]*"' \
    | sed -E 's/.*"(https[^"]*)".*/\1/' \
    | grep -E "/${comp}_[^/]*_linux_${arch}\.tar\.gz$" \
    | head -n1)"
  [ -n "$url" ] || err "no ${comp} asset found for linux/${arch} in this release"

  info "downloading ${comp} (${arch})"
  curl -fsSL "$url" -o "${tmp}/${comp}.tar.gz" || err "download failed: $url"
  tar -xzf "${tmp}/${comp}.tar.gz" -C "$tmp" "$comp" || err "could not extract ${comp} from archive"

  info "installing ${comp} -> ${INSTALL_DIR}/${comp}"
  $SUDO install -m 0755 "${tmp}/${comp}" "${INSTALL_DIR}/${comp}"
}

case "$COMPONENT" in
  orchestrator) install_component "nurproxy" ;;
  agent)        install_component "nurproxy-agent" ;;
  both)         install_component "nurproxy"; install_component "nurproxy-agent" ;;
  *) err "invalid --component: ${COMPONENT} (orchestrator|agent|both)" ;;
esac

echo
info "done. Next steps:"
case "$COMPONENT" in
  orchestrator|both) echo "  sudo ${INSTALL_DIR}/nurproxy install --port 8080" ;;
esac
case "$COMPONENT" in
  agent|both) echo "  sudo ${INSTALL_DIR}/nurproxy-agent install --orchestrator <URL> --fqdn <host.zone>" ;;
esac

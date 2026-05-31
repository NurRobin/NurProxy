#!/bin/sh
#
# NurProxy installer — downloads the latest release binary and, for a single
# component, registers it as a native service (systemd / launchd / OpenRC /
# FreeBSD rc.d) in one shot.
#
# Usage:
#   install.sh [agent|orchestrator|both|binary] [options] [-- service-flags]
#
# Components:
#   agent          install nurproxy-agent + register the service
#   orchestrator   install nurproxy + register the service
#   both           install both binaries only (default; no service)
#   binary         alias for "both" — binaries only, never a service
#
# Any flag the installer does not recognise (e.g. --orchestrator, --fqdn,
# --port, --data-dir, --user) is passed straight through to the binary's own
# `install` subcommand. So the canonical one-liner just works:
#
#   curl -fsSL https://raw.githubusercontent.com/NurRobin/NurProxy/main/scripts/install.sh \
#     | sh -s -- agent --orchestrator https://np.example.com --fqdn edge1.example.com
#
#   curl -fsSL .../install.sh | sh -s -- orchestrator --port 8080
#
# Options:
#   --version <tag>   release to install (default: latest)
#   --bin-dir <dir>   install location (default: /usr/local/bin)
#   --repo <owner/r>  GitHub repo (default: NurRobin/NurProxy)
#   --no-service      install the binary only, skip service registration
#   --component <c>   deprecated alias for the positional component
#   -h, --help        show this help
#
# Env overrides: REPO, VERSION, INSTALL_DIR.

set -eu

REPO="${REPO:-NurRobin/NurProxy}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
COMPONENT=""
NO_SERVICE=0

# PASS holds passthrough service-flags, one per line, so values may contain spaces.
PASS=""
append_pass() {
  if [ -z "$PASS" ]; then PASS="$1"; else PASS="$PASS
$1"; fi
}

err() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
usage() { sed -n '/^#!/d; s/^# \{0,1\}//p' "$0" 2>/dev/null; }

# --- parse args ------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    agent|orchestrator|both|binary)
      if [ -z "$COMPONENT" ]; then COMPONENT="$1"; else append_pass "$1"; fi
      shift ;;
    --component) COMPONENT="${2:-}"; shift 2 ;;
    --component=*) COMPONENT="${1#*=}"; shift ;;
    --version)   VERSION="${2:-}"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --bin-dir)   INSTALL_DIR="${2:-}"; shift 2 ;;
    --bin-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
    --repo)      REPO="${2:-}"; shift 2 ;;
    --repo=*)    REPO="${1#*=}"; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do append_pass "$1"; shift; done ;;
    *) append_pass "$1"; shift ;;
  esac
done

[ -n "$COMPONENT" ] || COMPONENT="both"
if [ "$COMPONENT" = "binary" ]; then COMPONENT="both"; NO_SERVICE=1; fi
case "$COMPONENT" in
  orchestrator|agent|both) : ;;
  *) err "invalid component: ${COMPONENT} (agent|orchestrator|both|binary)" ;;
esac

# --- requirements & platform ----------------------------------------------
command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin|freebsd) : ;;
  msys*|mingw*|cygwin*|windows*) err "Windows is not supported — run NurProxy on Linux, macOS, or FreeBSD (or in WSL2/Docker)" ;;
  *) err "unsupported OS: $os" ;;
esac

case "$(uname -m)" in
  x86_64|amd64)         arch="amd64" ;;
  aarch64|arm64)        arch="arm64" ;;
  armv7l|armv7|armhf)   arch="armv7" ;;
  *) err "unsupported architecture: $(uname -m)" ;;
esac

# --- resolve release -------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  api="https://api.github.com/repos/${REPO}/releases/latest"
else
  api="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi
info "fetching release metadata (${VERSION}) for ${REPO}"
release_json="$(curl -fsSL "$api")" || err "could not fetch release metadata"

# sudo for writing INSTALL_DIR if we can't ourselves.
SUDO=""
if [ ! -w "$INSTALL_DIR" ] && [ ! -w "$(dirname "$INSTALL_DIR")" ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else err "cannot write to ${INSTALL_DIR} and sudo not found"; fi
fi
$SUDO mkdir -p "$INSTALL_DIR"

# sudo for the (root-only) service install step.
RUNROOT=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then RUNROOT="sudo"; fi
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# install_binary <comp-asset-name> — downloads and installs that binary.
install_binary() {
  comp="$1"
  url="$(printf '%s' "$release_json" \
    | grep -o '"browser_download_url": *"[^"]*"' \
    | sed -E 's/.*"(https[^"]*)".*/\1/' \
    | grep -E "/${comp}_[^/]*_${os}_${arch}\.tar\.gz$" \
    | head -n1)"
  [ -n "$url" ] || err "no ${comp} asset for ${os}/${arch} in release ${VERSION}"

  info "downloading ${comp} (${os}/${arch})"
  curl -fsSL "$url" -o "${tmp}/${comp}.tar.gz" || err "download failed: $url"
  tar -xzf "${tmp}/${comp}.tar.gz" -C "$tmp" "$comp" || err "could not extract ${comp}"

  info "installing ${comp} -> ${INSTALL_DIR}/${comp}"
  $SUDO install -m 0755 "${tmp}/${comp}" "${INSTALL_DIR}/${comp}"
}

# run_service_install <binary> — runs `<binary> install <passthrough>` as root.
run_service_install() {
  bin="${INSTALL_DIR}/$1"
  info "registering service: ${bin} install"
  # Split PASS on newlines only so flag values keep their spaces.
  oldifs="$IFS"; IFS='
'
  # shellcheck disable=SC2086
  set -- $PASS
  IFS="$oldifs"
  $RUNROOT "$bin" install "$@"
}

case "$COMPONENT" in
  orchestrator)
    install_binary "nurproxy"
    [ "$NO_SERVICE" -eq 1 ] || run_service_install "nurproxy"
    ;;
  agent)
    install_binary "nurproxy-agent"
    [ "$NO_SERVICE" -eq 1 ] || run_service_install "nurproxy-agent"
    ;;
  both)
    install_binary "nurproxy"
    install_binary "nurproxy-agent"
    ;;
esac

echo
info "done."
if [ "$COMPONENT" = "both" ]; then
  echo "  Binaries installed to ${INSTALL_DIR}. Register a service with, e.g.:"
  echo "    sudo ${INSTALL_DIR}/nurproxy install --port 8080"
  echo "    sudo ${INSTALL_DIR}/nurproxy-agent install --orchestrator <URL> --fqdn <host.zone>"
fi

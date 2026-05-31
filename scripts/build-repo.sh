#!/usr/bin/env bash
#
# Build a signed APT + YUM repository from a directory of .deb/.rpm packages.
# Output is a static site (GitHub Pages / Cloudflare Pages / any web host).
#
# Usage:
#   scripts/build-repo.sh <packages-dir> <output-dir>
#
# Required env:
#   GPG_KEY_ID        signing key id/email (must be importable by gpg)
# Optional env:
#   GPG_PASSPHRASE    passphrase for the key (loopback pinentry)
#   REPO_BASE_URL     public URL the repo is served at (used in generated docs)
set -euo pipefail

PKG_DIR="${1:?usage: build-repo.sh <packages-dir> <output-dir>}"
OUT="${2:?usage: build-repo.sh <packages-dir> <output-dir>}"
BASE_URL="${REPO_BASE_URL:-https://nurrobin.github.io/NurProxy}"
: "${GPG_KEY_ID:?set GPG_KEY_ID to the signing key id/email}"

# gpg invocation that works unattended in CI.
gpg_sign() {
  local args=(gpg --batch --yes --pinentry-mode loopback --default-key "$GPG_KEY_ID")
  [ -n "${GPG_PASSPHRASE:-}" ] && args+=(--passphrase "$GPG_PASSPHRASE")
  "${args[@]}" "$@"
}

mkdir -p "$OUT"

# --- public key (both armored and dearmored for apt's signed-by) -------------
gpg --armor --export "$GPG_KEY_ID" > "$OUT/nurproxy.asc"
gpg --export "$GPG_KEY_ID"          > "$OUT/nurproxy.gpg"

# --- APT repo ----------------------------------------------------------------
apt_root="$OUT/apt"
mkdir -p "$apt_root/pool/main"
cp "$PKG_DIR"/*.deb "$apt_root/pool/main/" 2>/dev/null || true

if ls "$apt_root"/pool/main/*.deb >/dev/null 2>&1; then
  echo "==> building APT repo"
  (
    cd "$apt_root"
    arches="$(for f in pool/main/*.deb; do dpkg-deb -f "$f" Architecture; done | sort -u)"
    for arch in $arches; do
      mkdir -p "dists/stable/main/binary-$arch"
      dpkg-scanpackages -a "$arch" -m pool/main > "dists/stable/main/binary-$arch/Packages" 2>/dev/null
      gzip -9kf "dists/stable/main/binary-$arch/Packages"
    done
    # apt-ftparchive does NOT auto-populate Date; modern apt rejects a Release
    # without it. Valid-Until is deliberately omitted so a long gap between
    # releases never expires the repo.
    apt-ftparchive \
      -o APT::FTPArchive::Release::Origin=NurProxy \
      -o APT::FTPArchive::Release::Label=NurProxy \
      -o APT::FTPArchive::Release::Suite=stable \
      -o APT::FTPArchive::Release::Codename=stable \
      -o APT::FTPArchive::Release::Components=main \
      -o "APT::FTPArchive::Release::Architectures=$arches" \
      -o "APT::FTPArchive::Release::Date=$(date -Ru)" \
      release dists/stable > dists/stable/Release
    gpg_sign -abs -o dists/stable/Release.gpg dists/stable/Release
    gpg_sign --clearsign -o dists/stable/InRelease dists/stable/Release
  )
fi

# --- YUM repo ----------------------------------------------------------------
yum_root="$OUT/rpm"
mkdir -p "$yum_root"
cp "$PKG_DIR"/*.rpm "$yum_root/" 2>/dev/null || true

if ls "$yum_root"/*.rpm >/dev/null 2>&1; then
  echo "==> building YUM repo"
  # The generated .repo enables gpgcheck=1 + repo_gpgcheck=1, so unsigned RPMs
  # would fail on the client. Sign mandatorily and fail loudly otherwise.
  command -v rpmsign >/dev/null 2>&1 || { echo "error: rpmsign not found (install the 'rpm' package)"; exit 1; }
  rpmsign --define "_gpg_name $GPG_KEY_ID" --addsign "$yum_root"/*.rpm
  createrepo_c "$yum_root"
  gpg_sign --detach-sign --armor "$yum_root/repodata/repomd.xml"
fi

# --- client helpers ----------------------------------------------------------
cat > "$OUT/nurproxy.repo" <<EOF
[nurproxy]
name=NurProxy
baseurl=$BASE_URL/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$BASE_URL/nurproxy.asc
EOF

cat > "$OUT/index.html" <<EOF
<!doctype html><meta charset=utf-8><title>NurProxy packages</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}code,pre{background:#f4f4f4;border-radius:4px}pre{padding:1rem;overflow:auto}h2{margin-top:2rem}</style>
<h1>NurProxy package repositories</h1>

<h2>Debian / Ubuntu (APT)</h2>
<pre>curl -fsSL $BASE_URL/nurproxy.gpg | sudo tee /usr/share/keyrings/nurproxy.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nurproxy.gpg] $BASE_URL/apt stable main" \\
  | sudo tee /etc/apt/sources.list.d/nurproxy.list
sudo apt update
sudo apt install nurproxy          # or: nurproxy-agent</pre>

<h2>Fedora / RHEL (DNF/YUM)</h2>
<pre>sudo curl -fsSL $BASE_URL/nurproxy.repo -o /etc/yum.repos.d/nurproxy.repo
sudo dnf install nurproxy          # or: nurproxy-agent</pre>

<p>Other platforms and the one-line installer:
<a href="https://github.com/NurRobin/NurProxy#installation">github.com/NurRobin/NurProxy</a>.</p>
EOF

echo "==> repo built at $OUT"

#!/usr/bin/env bash
#
# MikiSSh installer.
#
#   curl -fsSL https://github.com/Francis261/MikiSSh/releases/latest/download/install.sh | bash
#
# Or, equivalently, straight from the repository:
#
#   curl -fsSL https://raw.githubusercontent.com/Francis261/MikiSSh/main/install.sh | bash
#
# Everything the gateway serves is compiled into the binary, so this installs
# exactly one file. No runtime, no package manager, nothing to reinstall.
#
# Environment overrides:
#   MIKISSH_VERSION      release tag to install      (default: latest)
#   MIKISSH_INSTALL_DIR  destination directory       (default: /usr/local/bin,
#                                                     falling back to ~/.local/bin)
#   MIKISSH_REPO         GitHub repository           (default: Francis261/MikiSSh)
#   MIKISSH_BASE_URL     asset base URL              (default: derived from REPO;
#                                                     point it at a local mirror
#                                                     to test)
#   MIKISSH_SKIP_VERIFY  set to 1 to skip the checksum check
set -euo pipefail

REPO="${MIKISSH_REPO:-Francis261/MikiSSh}"
VERSION="${MIKISSH_VERSION:-latest}"
SKIP_VERIFY="${MIKISSH_SKIP_VERIFY:-}"

say() { printf '%s\n' "$*"; }
warn() { printf 'install: %s\n' "$*" >&2; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but was not found"; }

# ---------------------------------------------------------------- platform
need curl
need tar
need uname

raw_os="$(uname -s)"
case "$raw_os" in
  Linux)                 os="linux" ;;
  Darwin)                os="darwin" ;;
  FreeBSD)               os="freebsd" ;;
  MINGW*|MSYS*|CYGWIN*)  os="windows" ;;
  *) die "unsupported operating system: $raw_os" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)          arch="amd64" ;;
  aarch64|arm64)         arch="arm64" ;;
  armv6l|armv7l|arm)     arch="arm" ;;
  i386|i486|i586|i686)   arch="386" ;;
  *) die "unsupported architecture: $arch" ;;
esac

if [ "$os" = "windows" ]; then
  binname="mikissh.exe"
else
  binname="mikissh"
fi
asset="mikissh_${os}_${arch}.tar.gz"

# ---------------------------------------------------------------- download
if [ -n "${MIKISSH_BASE_URL:-}" ]; then
  base="$MIKISSH_BASE_URL"
elif [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "installing MikiSSh (${asset}) from ${base}"

curl -fsSL -o "$tmp/$asset" "$base/$asset" \
  || die "could not download $base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
  || die "could not download the checksum manifest"

# ---------------------------------------------------------------- verify
if [ -n "$SKIP_VERIFY" ]; then
  warn "checksum verification skipped (MIKISSH_SKIP_VERIFY is set)"
else
  # Written as separate statements: `a && b || c && d || e` would evaluate
  # left-to-right with equal precedence and clobber have_sum.
  have_sum=""
  if command -v sha256sum >/dev/null 2>&1; then
    have_sum="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    have_sum="shasum"
  else
    die "neither 'sha256sum' nor 'shasum' is available"
  fi

  want="$(grep -E "[[:space:]](\\./)?${asset}\$" "$tmp/SHA256SUMS" | awk '{print $1}' | head -n1 || true)"
  [ -n "$want" ] || die "no checksum entry for $asset in SHA256SUMS"

  if [ "$have_sum" = "sha256sum" ]; then
    got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
  fi

  [ "$got" = "$want" ] \
    || die "checksum mismatch for $asset
  expected $want
  got      $got"
  say "checksum verified"
fi

# ---------------------------------------------------------------- extract
tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/$binname" ] || die "archive did not contain $binname"
chmod 0755 "$tmp/$binname"

# ---------------------------------------------------------------- install
if [ -z "${MIKISSH_INSTALL_DIR:-}" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    install_dir="/usr/local/bin"
  else
    home="${HOME:-}"
    [ -n "$home" ] || die "cannot determine a writable install directory; set MIKISSH_INSTALL_DIR"
    install_dir="$home/.local/bin"
  fi
else
  install_dir="$MIKISSH_INSTALL_DIR"
fi

mkdir -p "$install_dir" 2>/dev/null \
  || die "cannot create $install_dir (set MIKISSH_INSTALL_DIR to somewhere else)"
[ -w "$install_dir" ] \
  || die "$install_dir is not writable — set MIKISSH_INSTALL_DIR, or re-run with sudo"

cp "$tmp/$binname" "$install_dir/mikissh" || die "failed to write $install_dir/mikissh"
chmod 0755 "$install_dir/mikissh"

# ---------------------------------------------------------------- report
version="$("$install_dir/mikissh" version 2>/dev/null || echo unknown)"
say "installed $version -> $install_dir/mikissh"

case ":${PATH:-}:" in
  *":$install_dir:"*) ;;
  *)
    warn "$install_dir is not on your PATH; add it with:"
    warn "  export PATH=\"$install_dir:\$PATH\""
    ;;
esac

say ""
say "Try:"
say "  mikissh gen-token                 # mint an access token"
say "  mikissh server --config cfg.json  # run the gateway"
say "  mikissh help                      # everything else"

#!/usr/bin/env bash
#
# Build and publish a MikiSSh release.
#
#   GH_TOKEN=github_pat_... ./scripts/release.sh v0.1.0
#
# Produces dist/, containing one tarball per platform plus SHA256SUMS and a
# copy of install.sh, then attaches them all to a GitHub release. The tag is
# created on GitHub pointing at the current HEAD; fetch it afterwards with
# `git fetch --tags`.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REPO="Francis261/MikiSSh"
VERSION="${1:-}"

# --build-only stops after staging dist/: useful for inspecting the artifacts
# (and for exercising the script) without needing publish credentials.
BUILD_ONLY=""
if [ "${2:-}" = "--build-only" ]; then
  BUILD_ONLY=1
fi
if [ -n "${MIKISSH_BUILD_ONLY:-}" ]; then
  BUILD_ONLY=1
fi

if [ -z "$VERSION" ]; then
  echo "usage: scripts/release.sh <tag> [--build-only]   e.g. scripts/release.sh v0.1.0" >&2
  exit 2
fi
case "$VERSION" in
  v*) ;;
  *) echo "release: tag must start with 'v' (got: $VERSION)" >&2; exit 2 ;;
esac

TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 freebsd/amd64 windows/amd64"

die() { echo "release: $*" >&2; exit 1; }

for tool in go git tar; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is required"
done
if [ -z "$BUILD_ONLY" ]; then
  command -v gh >/dev/null 2>&1 || die "'gh' is required to publish"
  [ -n "${GH_TOKEN:-}" ] || die "GH_TOKEN must be set (gh needs it to publish)"
fi
git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"

# ------------------------------------------------------------- preconditions
echo "==> verifying the tree"

unformatted="$(gofmt -l cmd internal public)"
[ -z "$unformatted" ] || die "gofmt would rewrite:
$unformatted"

go vet ./...
go test ./...

git fetch origin main --quiet || die "could not fetch origin/main"
head="$(git rev-parse HEAD)"
remote="$(git rev-parse origin/main)"
[ "$head" = "$remote" ] || die "HEAD ($head) is ahead of origin/main ($remote) — push first"

[ -z "$(git status --porcelain)" ] || die "working tree is dirty — commit first"

if [ -z "$BUILD_ONLY" ] && gh release view "$VERSION" --repo "$REPO" >/dev/null 2>&1; then
  die "release $VERSION already exists on GitHub"
fi

# --------------------------------------------------------------------- build
# The tag is v0.1.0; the binary reports the bare 0.1.0 so it matches
# `mikissh version` on a dev build.
VERSION_STR="${VERSION#v}"
LDFLAGS="-s -w -X github.com/Francis261/MikiSSh/internal/gateway.Version=${VERSION_STR}"

echo "==> building $TARGETS"
rm -rf dist
mkdir -p dist/staging

for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="mikissh_${goos}_${goarch}"
  if [ "$goos" = "windows" ]; then bin="mikissh.exe"; else bin="mikissh"; fi

  stage="dist/staging/$name"
  mkdir -p "$stage"
  echo "    $name"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$stage/$bin" ./cmd/mikissh \
    || die "build failed for $target"

  # The archive holds the binary at its top level: install.sh extracts
  # straight from it with no path guessing.
  tar -czf "dist/$name.tar.gz" -C "$stage" "$bin"
  rm -r "$stage"
done
rmdir dist/staging 2>/dev/null || true

cp install.sh dist/install.sh

echo "==> checksums"
(
  cd dist
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.tar.gz | sed 's|\./||'
  else
    shasum -a 256 ./*.tar.gz | sed 's|\./||'
  fi
) > dist/SHA256SUMS

# --------------------------------------------------------------- release notes
{
  echo "## MikiSSh ${VERSION}"
  echo
  echo "Secure SSH over WebSocket — a single statically-linked binary. The web"
  echo "UI, the xterm terminal and the SSH bridge are all compiled in, so there"
  echo "is no runtime and nothing to reinstall."
  echo
  echo '```bash'
  echo "curl -fsSL https://github.com/${REPO}/releases/download/${VERSION}/install.sh | bash"
  echo '```'
  echo
  echo "The installer detects your OS and architecture, verifies the download"
  echo "against \`SHA256SUMS\`, and writes one file:"
  echo
  echo "| Platform | Archive |"
  echo "| --- | --- |"
  for f in dist/*.tar.gz; do
    echo "| ${f#dist/} | \`${f#dist/}\` |"
  done
  echo
  echo "### Verify manually"
  echo
  echo '```bash'
  echo "curl -fsSLO https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"
  echo "sha256sum --check --ignore-missing SHA256SUMS"
  echo '```'
  echo
  echo "### From source"
  echo
  echo '```bash'
  echo "go install github.com/${REPO}/cmd/mikissh@${VERSION}"
  echo '```'
} > dist/NOTES.md

if [ -n "$BUILD_ONLY" ]; then
  echo "==> build-only: artifacts staged in dist/, nothing published"
  ls -la dist | sed 's/^/    /'
  exit 0
fi

# ------------------------------------------------------------------- publish
echo "==> publishing $VERSION"
gh release create "$VERSION" \
  --repo "$REPO" \
  --target "$head" \
  --title "MikiSSh ${VERSION}" \
  --notes-file dist/NOTES.md \
  dist/*.tar.gz dist/SHA256SUMS dist/install.sh \
  || die "gh release create failed"

echo "==> done"
echo "    https://github.com/${REPO}/releases/tag/${VERSION}"
echo "    curl -fsSL https://github.com/${REPO}/releases/latest/download/install.sh | bash"

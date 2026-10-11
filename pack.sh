#!/usr/bin/env bash
# pack.sh — build the release bundle that install.sh distributes.
#
# Produces dist/nebula-linux-x86_64.tar.gz containing:
#   nebula                 (GUI binary)
#   libnebula_hook.so      (injected hook)
#   nebula-attach          (headless attach helper)
#
# Usage: ./pack.sh
#   Then: create a GitHub release tagged v0.1.0 and attach the tarball
#         (or use the included GitHub Actions workflow).
set -euo pipefail

cd "$(dirname "$0")"

echo "==> building release…"
cargo build --release --workspace

OUT="dist"
mkdir -p "$OUT/nebula-linux-x86_64"

cp target/release/nebula             "$OUT/nebula-linux-x86_64/"
cp target/release/libnebula_hook.so  "$OUT/nebula-linux-x86_64/"
cp nebula-attach                     "$OUT/nebula-linux-x86_64/"

echo "==> stripping binaries…"
strip -s "$OUT/nebula-linux-x86_64/nebula" "$OUT/nebula-linux-x86_64/libnebula_hook.so" 2>/dev/null || true

echo "==> packaging…"
tar -czf "$OUT/nebula-linux-x86_64.tar.gz" -C "$OUT" nebula-linux-x86_64

echo
echo "✦ done:"
ls -la "$OUT/nebula-linux-x86_64.tar.gz"
echo
echo "Next steps:"
echo "  1. Push this repo to github.com/ethancroissants/nebula"
echo "  2. Attach dist/nebula-linux-x86_64.tar.gz to a release (tag v0.1.0)"
echo "  3. Users install with:"
echo "       curl -fsSL https://raw.githubusercontent.com/ethancroissants/nebula/main/install.sh | sh"

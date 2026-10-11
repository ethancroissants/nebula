#!/usr/bin/env bash
# ==============================================================================
#  Nebula installer — one-line install for any x86-64 Linux distro
#
#    curl -fsSL https://nebula.rs/install.sh | sh
#
#  What it does:
#    1. Detects distro and installs the runtime deps (flatpak, libgtk3)
#    2. Downloads the prebuilt Nebula bundle (GUI + hook .so)
#    3. Installs to ~/.local/lib/nebula + symlinks the launcher
#    4. Verifies Sober is present (and offers to install it if not)
#
#  The script never needs root except for the distro package install,
#  and uses sudo only if already available.
# ==============================================================================
set -euo pipefail

REPO_URL="${NEBULA_REPO_URL:-https://github.com/ethancroissants/nebula}"
INSTALL_DIR="${NEBULA_INSTALL_DIR:-$HOME/.local/lib/nebula}"
BIN_DIR="${NEBULA_BIN_DIR:-$HOME/.local/bin}"

log()  { printf '\033[1;35m[nebula]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[nebula]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[nebula]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 1. distro ---
# shellcheck disable=SC2034
detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="$ID"
    else
        case "$(uname -s)" in
            Linux) DISTRO="unknown" ;;
        esac
    fi
    log "detected distro: ${DISTRO:-unknown}"
}

# Install system packages. Each distro gets the minimum needed:
#   flatpak        — to run & sandbox-override Sober
#   libgtk-3       — the GUI's Vulkan/GL windowing backend (via winit)
install_deps() {
    case "$DISTRO" in
        ubuntu|debian|pop|neon|mx|zorin)
            if command -v apt-get >/dev/null; then
                [ "$(id -u)" = 0 ] || SUDO="sudo"
                $SUDO apt-get update -qq || warn "apt update failed (continuing)"
                $SUDO apt-get install -y flatpak libgtk-3-0 curl ca-certificates
            fi
            ;;
        fedora|rhel|rocky|almalinux|nobara)
            if command -v dnf >/dev/null; then
                [ "$(id -u)" = 0 ] || SUDO="sudo"
                $SUDO dnf install -y flatpak gtk3 curl ca-certificates
            fi
            ;;
        arch|endeavouros|manjaro)
            if command -v pacman >/dev/null; then
                [ "$(id -u)" = 0 ] || SUDO="sudo"
                $SUDO pacman -S --noconfirm --needed flatpak gtk3 curl ca-certificates
            fi
            ;;
        opensuse-tumbleweed|opensuse-leap)
            if command -v zypper >/dev/null; then
                [ "$(id -u)" = 0 ] || SUDO="sudo"
                $SUDO zypper install -y flatpak gtk3 curl ca-certificates
            fi
            ;;
        alpine)
            if command -v apk >/dev/null; then
                [ "$(id -u)" = 0 ] || SUDO="sudo"
                $SUDO apk add --no-progress flatpak gtk+3.0 curl ca-certificates
            fi
            ;;
        *)
            warn "unrecognized distro — assuming flatpak + gtk3 are installed"
            ;;
    esac
}

# ------------------------------------------------------------- 2. download ---
# Resolve the newest release tag from the GitHub API, then pull the bundle.
# If no release asset exists yet, fall back to building from source.
download_bundle() {
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    log "fetching latest release…"
    if command -v curl >/dev/null; then
        # Follow the latest-release redirect to discover the tag.
        TAG="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest" 2>/dev/null \
            | grep -oE 'tag/v[0-9]+\.[0-9]+\.[0-9]+' | cut -d/ -f2 || true)"
        [ -n "$TAG" ] || TAG="v0.1.0"
        URL="$REPO_URL/releases/download/$TAG/nebula-linux-x86_64.tar.gz"
        if curl -fsSL --proto '=https' -o "$TMP/nebula.tar.gz" "$URL" 2>/dev/null; then
            log "unpacking…"
            mkdir -p "$INSTALL_DIR"
            tar -xzf "$TMP/nebula.tar.gz" -C "$INSTALL_DIR"
            return 0
        fi
        warn "no prebuilt release found at $URL"
    else
        die "curl not found"
    fi

    build_from_source "$TMP"
}

# ------------------------------------------------------- 2b. source build ---
# Fallback used when no release asset is published yet: clone the repo and
# run the same build the release workflow runs.
build_from_source() {
    local TMP="$1"
    command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust from https://rustup.rs"

    log "building from source…"
    git clone --depth 1 "$REPO_URL" "$TMP/src" \
        || die "clone failed ($REPO_URL)"
    ( cd "$TMP/src" && cargo build --release --workspace ) \
        || die "build failed — see the cargo output above"

    mkdir -p "$INSTALL_DIR"
    cp "$TMP/src/target/release/nebula" "$INSTALL_DIR/"
    cp "$TMP/src/target/release/libnebula_hook.so" "$INSTALL_DIR/"
    cp "$TMP/src/nebula-attach" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/nebula" "$INSTALL_DIR/nebula-attach"
}

# ---------------------------------------------------------------- 3. links ---
install_links() {
    mkdir -p "$BIN_DIR"
    for bin_name in nebula nebula-attach; do
        if [ -f "$INSTALL_DIR/$bin_name" ]; then
            chmod +x "$INSTALL_DIR/$bin_name"
            ln -sf "$INSTALL_DIR/$bin_name" "$BIN_DIR/$bin_name"
        fi
    done
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *) warn "$BIN_DIR is not on your PATH — add it to your shell profile." ;;
    esac
}

# ---------------------------------------------------------------- 4. sober ---
check_sober() {
    if flatpak info --user org.vinegarhq.Sober >/dev/null 2>&1 \
        || flatpak info org.vinegarhq.Sober >/dev/null 2>&1; then
        log "Sober is installed ✓"
    else
        log "Sober not found — installing it for you…"
        flatpak remote-add --if-not-exists flathub \
            https://dl.flathub.org/repo/flathub.flatpakrepo || true
        flatpak install -y --noninteractive flathub org.vinegarhq.Sober \
            || warn "could not auto-install Sober; run:
    flatpak install flathub org.vinegarhq.Sober"
    fi
}

# -------------------------------------------------------------------- main ---
case "$(uname -m)" in
    x86_64) ;;
    *) die "Nebula publishes x86-64 builds only (Sober requires SSE4.1 anyway)."
esac

detect_distro
install_deps
download_bundle
install_links
check_sober

cat <<EOF

  ✦ Nebula installed!

    Launch:        nebula
    Attach:        click "Attach" in the app (or run \`nebula-attach\`)
    Then start:    Roblox via Sober (flatpak run org.vinegarhq.Sober)

  Scripts execute inside the game's Luau VM. Happy exploring.
EOF

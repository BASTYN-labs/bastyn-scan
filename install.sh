#!/bin/sh
# Installs the bastyn CLI from a GitHub Release archive.
# curl -fsSL https://raw.githubusercontent.com/BASTYN-labs/bastyn-scan/main/install.sh | sh
set -eu

REPO="BASTYN-labs/bastyn-scan"
BIN_NAME="bastyn"

log() {
    printf '%s\n' "$*" >&2
}

fail() {
    log "install.sh: error: $*"
    exit 1
}

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux) os_part="unknown-linux-musl" ;;
        Darwin) os_part="apple-darwin" ;;
        *) fail "unsupported OS: $os (this script supports Linux and macOS only; on Windows, download the .zip from https://github.com/$REPO/releases)" ;;
    esac

    case "$arch" in
        x86_64|amd64) arch_part="x86_64" ;;
        arm64|aarch64) arch_part="aarch64" ;;
        *) fail "unsupported architecture: $arch" ;;
    esac

    printf '%s-%s\n' "$arch_part" "$os_part"
}

resolve_version() {
    if [ -n "${BASTYN_VERSION:-}" ]; then
        case "$BASTYN_VERSION" in
            v[0-9]*.[0-9]*.[0-9]*) printf '%s\n' "$BASTYN_VERSION"; return ;;
            *) fail "BASTYN_VERSION must look like vX.Y.Z, got: $BASTYN_VERSION" ;;
        esac
    fi

    location=$(curl -fsSI --proto '=https' --proto-redir '=https' \
        "https://github.com/${REPO}/releases/latest" \
        | tr -d '\r' \
        | awk 'tolower($1) == "location:" { print $2 }' \
        | tail -n1)

    [ -n "$location" ] || fail "could not resolve the latest release (no Location header from GitHub)"

    version=$(printf '%s\n' "$location" | sed -n 's#.*/releases/tag/\(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$#\1#p')
    [ -n "$version" ] || fail "could not parse a version out of redirect target: $location"

    printf '%s\n' "$version"
}

checksum_verify() {
    archive="$1"
    checksum_file="$2"

    if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum_file")" >/dev/null ) \
            || fail "checksum verification failed for $(basename "$archive")"
    elif command -v shasum >/dev/null 2>&1; then
        ( cd "$(dirname "$archive")" && shasum -a 256 -c "$(basename "$checksum_file")" >/dev/null ) \
            || fail "checksum verification failed for $(basename "$archive")"
    else
        fail "neither sha256sum nor shasum is available; refusing to install an unverified binary"
    fi
}

main() {
    target=$(detect_target)
    version=$(resolve_version)

    install_dir="${BASTYN_INSTALL_DIR:-$HOME/.local/bin}"
    archive_name="${BIN_NAME}-${version}-${target}.tar.gz"
    # The release pipeline publishes checksum files named after the archive's
    # base name (bin-version-target), not the full archive filename — i.e.
    # "bastyn-v0.1.4-aarch64-apple-darwin.sha256", not "....tar.gz.sha256".
    checksum_name="${BIN_NAME}-${version}-${target}.sha256"
    base_url="https://github.com/${REPO}/releases/download/${version}"

    workdir=$(mktemp -d) || fail "could not create a temporary directory"
    trap 'rm -rf "$workdir"' EXIT INT TERM

    log "Downloading ${archive_name} (${version})..."
    curl -fsSL --proto '=https' --proto-redir '=https' \
        -o "$workdir/$archive_name" \
        "$base_url/$archive_name" \
        || fail "download failed: $base_url/$archive_name"
    curl -fsSL --proto '=https' --proto-redir '=https' \
        -o "$workdir/$archive_name.sha256" \
        "$base_url/$checksum_name" \
        || fail "checksum download failed: $base_url/$checksum_name"

    checksum_verify "$workdir/$archive_name" "$workdir/$archive_name.sha256"

    tar -xzf "$workdir/$archive_name" -C "$workdir" \
        || fail "failed to extract $archive_name"

    [ -f "$workdir/$BIN_NAME" ] || fail "extracted archive did not contain a '$BIN_NAME' binary"

    mkdir -p "$install_dir"
    chmod +x "$workdir/$BIN_NAME"
    mv "$workdir/$BIN_NAME" "$install_dir/$BIN_NAME"

    log "Installed $BIN_NAME $version to $install_dir/$BIN_NAME"

    case ":$PATH:" in
        *":$install_dir:"*) : ;;
        *) log "Note: $install_dir is not on your PATH. Add it, e.g.: export PATH=\"$install_dir:\$PATH\"" ;;
    esac
}

main "$@"

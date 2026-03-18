#!/bin/bash
# generate_bundle.sh - Generate diagnostic bundle for support
# Creates a tarball with system and smart card diagnostic information

set -euo pipefail

BUNDLE_DIR=$(mktemp -d /tmp/smartcard-diagnostic-XXXXXX)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BUNDLE_NAME="smartcard-diagnostic-${TIMESTAMP}"

generate_bundle() {
    local output_dir="${1:-/tmp}"

    echo "Collecting smart card diagnostic information..."

    # System info
    {
        echo "=== System Information ==="
        uname -a
        echo ""
        lsb_release -a 2>/dev/null || cat /etc/os-release
        echo ""
        echo "=== Ubuntu Pro Status ==="
        pro status 2>/dev/null || echo "pro client not available"
    } > "${BUNDLE_DIR}/system-info.txt" 2>&1

    # Smart card reader info
    {
        echo "=== Smart Card Readers ==="
        opensc-tool --list-readers 2>/dev/null || echo "opensc-tool not available"
        echo ""
        echo "=== PC/SC Status ==="
        systemctl status pcscd 2>/dev/null || echo "pcscd service status unavailable"
    } > "${BUNDLE_DIR}/reader-info.txt" 2>&1

    # Card info
    {
        echo "=== Card ATR ==="
        opensc-tool --atr 2>/dev/null || echo "No card detected"
        echo ""
        echo "=== PKCS#15 Info ==="
        pkcs15-tool --list-info 2>/dev/null || echo "pkcs15-tool not available or no card"
        echo ""
        echo "=== Certificate List ==="
        pkcs15-tool --list-certificates 2>/dev/null || echo "No certificates found"
    } > "${BUNDLE_DIR}/card-info.txt" 2>&1

    # FIPS info
    {
        echo "=== FIPS Status ==="
        cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "FIPS status unavailable"
        echo ""
        echo "=== OpenSSL Version ==="
        openssl version 2>/dev/null || echo "openssl not available"
    } > "${BUNDLE_DIR}/fips-info.txt" 2>&1

    # Package info
    {
        echo "=== Installed Smart Card Packages ==="
        dpkg -l | grep -iE "opensc|pcsc|pcscd|coolkey|cac|piv|pkcs" 2>/dev/null || echo "No packages found"
    } > "${BUNDLE_DIR}/packages.txt" 2>&1

    # Create tarball
    local bundle_path="${output_dir}/${BUNDLE_NAME}.tar.gz"
    tar -czf "$bundle_path" -C /tmp "$(basename "$BUNDLE_DIR")" 2>/dev/null

    # Clean up
    rm -rf "$BUNDLE_DIR"

    echo "{\"success\": true, \"bundle_path\": \"$bundle_path\"}"
}

generate_bundle "$@"

#!/bin/bash
# validate_fips.sh - Validate FIPS 140-2/140-3 compliance
# Returns JSON with FIPS validation status

set -euo pipefail

validate_fips() {
    local fips_enabled=false
    local kernel_fips=false
    local openssl_fips=false
    local fips_mode=""

    # Check kernel FIPS mode
    if [ -f /proc/sys/crypto/fips_enabled ]; then
        local fips_val
        fips_val=$(cat /proc/sys/crypto/fips_enabled)
        if [ "$fips_val" = "1" ]; then
            kernel_fips=true
        fi
    fi

    # Check OpenSSL FIPS
    if openssl version 2>/dev/null | grep -qi "fips"; then
        openssl_fips=true
    fi

    # Check Ubuntu Pro FIPS status
    if command -v pro &>/dev/null; then
        fips_mode=$(pro status 2>/dev/null | grep -i "fips" | head -1 || echo "unknown")
    fi

    if [ "$kernel_fips" = true ] && [ "$openssl_fips" = true ]; then
        fips_enabled=true
    fi

    echo "{\"fips_enabled\": $fips_enabled, \"kernel_fips\": $kernel_fips, \"openssl_fips\": $openssl_fips, \"pro_fips_status\": \"$(echo "$fips_mode" | tr '"' "'")\"}"
}

validate_fips

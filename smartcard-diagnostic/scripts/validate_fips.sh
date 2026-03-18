#!/bin/bash
# Check FIPS mode status
set -e

FIPS_ENABLED=0

# Check kernel FIPS mode
if [ -f /proc/sys/crypto/fips_enabled ]; then
    FIPS_ENABLED=$(cat /proc/sys/crypto/fips_enabled)
fi

if [ "$FIPS_ENABLED" = "1" ]; then
    echo "FIPS_ENABLED"

    # Check for FIPS packages
    if dpkg -l | grep -q "ubuntu-fips"; then
        echo "FIPS_PACKAGES_INSTALLED"
    fi

    # Check OpenSC FIPS build
    if opensc-tool --version 2>&1 | grep -qi "fips"; then
        echo "OPENSC_FIPS_BUILD"
    fi

    exit 0
else
    echo "FIPS_DISABLED"
    exit 1
fi

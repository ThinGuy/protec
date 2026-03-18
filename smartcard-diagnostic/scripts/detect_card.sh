#!/bin/bash
# Detect smart card presence
set -e

OUTPUT=$(opensc-tool -l 2>&1)

if echo "$OUTPUT" | grep -q "Card present"; then
    echo "CARD_PRESENT"
    exit 0
else
    echo "NO_CARD"
    exit 1
fi

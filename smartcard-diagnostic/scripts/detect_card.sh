#!/bin/bash
# detect_card.sh - Detect inserted smart cards and read ATR
# Returns JSON with card information

set -euo pipefail

detect_card() {
    if ! command -v opensc-tool &>/dev/null; then
        echo '{"inserted": false, "error": "opensc-tool not found"}'
        return
    fi

    local atr
    atr=$(opensc-tool --atr 2>/dev/null || true)

    if [ -n "$atr" ]; then
        local atr_hex
        atr_hex=$(echo "$atr" | head -1 | sed 's/.*: //')

        local card_name=""
        if command -v pkcs15-tool &>/dev/null; then
            card_name=$(pkcs15-tool --list-info 2>/dev/null | grep "Card name" | sed 's/.*: //' || true)
        fi

        echo "{\"inserted\": true, \"atr\": \"$atr_hex\", \"card_name\": \"$card_name\"}"
    else
        echo '{"inserted": false}'
    fi
}

detect_card

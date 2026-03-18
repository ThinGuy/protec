#!/bin/bash
# detect_reader.sh - Detect connected smart card readers
# Returns JSON with reader information

set -euo pipefail

detect_readers() {
    if command -v opensc-tool &>/dev/null; then
        local reader_list
        reader_list=$(opensc-tool --list-readers 2>/dev/null || true)

        if [ -n "$reader_list" ]; then
            local count
            count=$(echo "$reader_list" | grep -c "Nr\." || echo "0")
            echo "{\"detected\": true, \"count\": $count, \"output\": \"$(echo "$reader_list" | tr '"' "'" | tr '\n' ' ')\"}"
        else
            echo '{"detected": false, "count": 0, "output": ""}'
        fi
    else
        echo '{"detected": false, "count": 0, "error": "opensc-tool not found"}'
    fi
}

detect_readers

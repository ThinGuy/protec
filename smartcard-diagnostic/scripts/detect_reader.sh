#!/bin/bash
# Detect smart card reader using opensc-tool
set -e

OUTPUT=$(opensc-tool -l 2>&1)

if echo "$OUTPUT" | grep -q "No smart card readers found"; then
    echo "NO_READER"
    exit 1
fi

# Extract reader name
READER=$(echo "$OUTPUT" | grep -i "reader" | head -1 | sed 's/.*Reader //' | cut -d: -f1)

if [ -n "$READER" ]; then
    echo "READER_FOUND: $READER"
    exit 0
else
    echo "READER_DETECTED_BUT_NO_NAME"
    exit 0
fi

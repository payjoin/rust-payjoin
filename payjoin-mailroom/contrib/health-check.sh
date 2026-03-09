#!/bin/bash

set -uo pipefail

TIMEOUT=10
DIRECTORIES=(
    "https://payjo.in"
    "https://lets.payjo.in"
)
FAILED_DIRS=()

for dir in "${DIRECTORIES[@]}"; do
    if ! curl -sf --max-time "$TIMEOUT" "${dir}/health" >/dev/null 2>&1; then
        FAILED_DIRS+=("$dir")
    fi
done

if [ ${#FAILED_DIRS[@]} -gt 0 ]; then
    echo "/health check failed for the following directories:" >&2
    for dir in "${FAILED_DIRS[@]}"; do
        echo "  - ${dir}" >&2
    done
    exit 1
fi

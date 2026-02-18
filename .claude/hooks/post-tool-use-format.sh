#!/usr/bin/env bash
# PostToolUse hook: auto-format .rs files after Edit/Write/MultiEdit
# Extracts file_path from stdin JSON; runs rustfmt if it's a .rs file.

set -euo pipefail

input=$(cat)
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')

# Nothing to do if no file_path or not a .rs file
if [[ -z "$file_path" || "$file_path" != *.rs ]]; then
  exit 0
fi

# Only format if the file actually exists (guard against deletes)
if [[ -f "$file_path" ]]; then
  rustfmt "$file_path" 2>&1
fi

exit 0

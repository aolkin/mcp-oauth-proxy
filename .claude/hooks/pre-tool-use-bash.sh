#!/usr/bin/env bash
# PreToolUse hook for Bash: blocks --no-verify and runs CI checks before git commit.
# Combined into one script so we only parse stdin once per Bash invocation.

set -euo pipefail

input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // empty')

# ── Fast path: not a git commit → allow immediately ──
if ! echo "$command" | grep -q 'git commit'; then
  exit 0
fi

# ── Block --no-verify ──
if echo "$command" | grep -q -- '--no-verify'; then
  echo "BLOCKED: --no-verify is not allowed. Commit hooks must not be skipped." >&2
  exit 2
fi

# ── Pre-commit CI checks ──
echo "Running pre-commit CI checks..." >&2

echo "=> cargo fmt --all --check" >&2
if ! cargo fmt --all --check 2>&1 >&2; then
  echo "FAILED: cargo fmt --all --check. Run 'cargo fmt --all' to fix formatting." >&2
  exit 2
fi

echo "=> cargo clippy --workspace --all-targets --all-features -- -D warnings" >&2
if ! cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 >&2; then
  echo "FAILED: cargo clippy found warnings or errors." >&2
  exit 2
fi

echo "=> cargo test --workspace" >&2
if ! cargo test --workspace 2>&1 >&2; then
  echo "FAILED: cargo test had failures." >&2
  exit 2
fi

echo "All CI checks passed." >&2
exit 0

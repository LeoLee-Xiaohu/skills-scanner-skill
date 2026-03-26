#!/usr/bin/env bash
# scan.sh — Skills Scanner wrapper script
# Usage: bash scan.sh <target_skill_path> [--no-llm] [--threshold LEVEL] [--layers LIST]
# Exit codes: 0=PASS, 1=WARN, 2=FAIL, 3=setup error

set -euo pipefail

# ── Locate this skill's own directory ─────────────────────────────────────────
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse arguments ────────────────────────────────────────────────────────────
TARGET_PATH=""
EXTRA_ARGS=()

for arg in "$@"; do
    if [[ -z "$TARGET_PATH" && "$arg" != --* ]]; then
        TARGET_PATH="$arg"
    else
        EXTRA_ARGS+=("$arg")
    fi
done

if [[ -z "$TARGET_PATH" ]]; then
    echo '{"error": "Usage: scan.sh <target_skill_path> [--no-llm] [--threshold LEVEL]"}' >&2
    exit 3
fi

# ── Check target exists ────────────────────────────────────────────────────────
if [[ ! -e "$TARGET_PATH" ]]; then
    echo "{\"error\": \"Target path does not exist: $TARGET_PATH\"}" >&2
    exit 3
fi

# ── Ensure uv is available ────────────────────────────────────────────────────
if ! command -v uv &>/dev/null; then
    echo '{"error": "uv is not installed. Run: curl -Lsf https://astral.sh/uv/install.sh | sh"}' >&2
    exit 3
fi

# ── Sync dependencies (fast no-op if already installed) ───────────────────────
cd "$SKILL_DIR"
uv sync --quiet 2>/dev/null || {
    echo '{"error": "Dependency installation failed. Run: cd '"$SKILL_DIR"' && uv sync"}' >&2
    exit 3
}

# ── Run the scanner ────────────────────────────────────────────────────────────
# Run main.py directly (avoids entry-point path resolution issues across environments)
uv run python main.py scan "$TARGET_PATH" --json "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
EXIT_CODE=$?

exit $EXIT_CODE

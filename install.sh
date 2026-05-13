#!/usr/bin/env bash
#
# Sentinel MCP — install script
#
# Creates a Python virtual environment in ./.venv and installs the mcp[cli]
# package. Safe to re-run.
#
# Requirements: Python 3.10 or higher.

set -euo pipefail

# Resolve script directory so install.sh works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "▸ Sentinel MCP installer"
echo "  Working directory: $SCRIPT_DIR"
echo

# --- Step 1: verify Python ---
if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ python3 not found on PATH."
  echo
  echo "  Install Python 3.10 or higher and re-run this script."
  echo "  macOS:   brew install python@3.12"
  echo "  Ubuntu:  sudo apt install python3 python3-venv"
  echo "  Windows: download from https://python.org"
  exit 1
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="$(python3 -c 'import sys; print(sys.version_info.major)')"
PYTHON_MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]; }; then
  echo "✗ Python 3.10 or higher required. Found: $PYTHON_VERSION"
  echo
  echo "  macOS:   brew install python@3.12"
  echo "  Ubuntu:  sudo apt install python3.12 python3.12-venv"
  exit 1
fi

echo "✓ Python $PYTHON_VERSION detected"

# --- Step 2: create / reuse virtual environment ---
if [ -d ".venv" ]; then
  echo "✓ Virtual environment .venv/ already exists (reusing)"
else
  echo "▸ Creating virtual environment in .venv/"
  python3 -m venv .venv
  echo "✓ Virtual environment created"
fi

# --- Step 3: install dependencies ---
echo "▸ Installing dependencies into .venv/"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
echo "✓ Dependencies installed"

# --- Step 4: smoke test ---
echo "▸ Smoke-testing import"
if .venv/bin/python -c "import sentinel_mcp; print('✓ sentinel_mcp imports cleanly')" 2>/dev/null; then
  :
else
  echo "✗ Smoke test failed — sentinel_mcp.py could not be imported."
  echo "  Check that sentinel_mcp.py exists in $SCRIPT_DIR and is not corrupted."
  exit 1
fi

# --- Done ---
cat <<EOF

Installation complete.

Next steps:
  1. Register Sentinel with your MCP client (Cursor, Claude Desktop, etc.).
     For Cursor, edit ~/.cursor/mcp.json and add:

     {
       "mcpServers": {
         "sentinel": {
           "command": "$SCRIPT_DIR/.venv/bin/python",
           "args": ["$SCRIPT_DIR/sentinel_mcp.py"]
         }
       }
     }

     See examples/mcp.json.example for the full snippet.

  2. Fully quit and reopen your MCP client.

  3. In an Agent-mode chat, say: "Run Sentinel on /path/to/my/project"

If this is the first audit on the project, Sentinel will detect that and
offer to initialize project-context.md and the audits/ folder.

EOF

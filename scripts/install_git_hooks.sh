#!/usr/bin/env bash
# ==============================================================================
# Keynova Git Hooks Installer
# Installs local air-gapped pre-push hook to prevent pushing vulnerable
# cryptographic implementations to remote repositories.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_DIR="$REPO_ROOT/.git/hooks"
HOOK_FILE="$HOOK_DIR/pre-push"

if [ ! -d "$REPO_ROOT/.git" ]; then
    echo "[ERROR] .git directory not found at $REPO_ROOT. Initialize git first." >&2
    exit 1
fi

mkdir -p "$HOOK_DIR"

echo "[KEYNOVA] Installing pre-push security hook into $HOOK_FILE..."

cat <<'EOF' > "$HOOK_FILE"
#!/usr/bin/env bash
# Keynova Pre-Push Cryptographic Gate
# Runs 100% offline and air-gapped before commits leave the local machine.

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Resolve Python interpreter
if [ -f "$REPO_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON_BIN="$(command -v python3)"
elif command -v python &>/dev/null; then
    PYTHON_BIN="$(command -v python)"
else
    echo "[KEYNOVA HOOK ERROR] Python 3 not found. Cannot evaluate cryptographic gate." >&2
    exit 1
fi

echo "======================================================================"
echo " [KEYNOVA] Evaluating Local Post-Quantum Cryptographic Readiness Gate"
echo " Running air-gapped local AST inspection with zero network egress..."
echo "======================================================================"

export PYTHONPATH="$REPO_ROOT/backend"

if "$PYTHON_BIN" -m keynova.cli . --min-score 80 --block-hndl; then
    echo "======================================================================"
    echo " [KEYNOVA] Gate PASSED. All cryptographic policies satisfied."
    echo "======================================================================"
    exit 0
else
    echo "======================================================================"
    echo " [KEYNOVA] Gate FAILED! Cryptographic policy violations detected."
    echo " Push rejected by local pre-push hook."
    echo " Remediate classical vulnerabilities or run Keynova locally to inspect."
    echo "======================================================================"
    exit 1
fi
EOF

chmod +x "$HOOK_FILE"

echo "[KEYNOVA] Pre-push hook successfully installed and configured with executable permissions."
echo "[KEYNOVA] Location: $HOOK_FILE"

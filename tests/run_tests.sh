#!/usr/bin/env bash
# Run test-idp integration tests
# Usage: ./run_tests.sh [pytest args...]
#
# Examples:
#   ./run_tests.sh                    # Run all tests
#   ./run_tests.sh -v                 # Verbose
#   ./run_tests.sh test_idpcore.py    # Specific file
#   ./run_tests.sh -k "login"         # Keyword filter

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON="/root/miniconda3/envs/test-idp/bin/python"

cd "$SCRIPT_DIR"

echo "=== Test IdP Integration Tests ==="
echo "Project: $PROJECT_DIR"
echo "Python:  $PYTHON"
echo ""

exec "$PYTHON" -m pytest "$@" --tb=short -q

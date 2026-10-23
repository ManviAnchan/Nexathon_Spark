#!/usr/bin/env bash
set -e
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=========================================================="
echo " Starting Keynova Autonomous PQC Readiness Desktop App..."
echo "=========================================================="

cd "$ROOT_DIR/frontend"
npm run desktop:dev

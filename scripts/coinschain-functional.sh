#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo run --bin coinschain-functional -- \
  --url "${URL:-http://127.0.0.1:18545}" \
  --timeout-secs "${TIMEOUT_SECS:-60}"

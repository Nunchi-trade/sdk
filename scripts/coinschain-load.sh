#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo run --bin coinschain-load -- \
  --url "${URL:-http://127.0.0.1:18545}" \
  --transactions "${TRANSACTIONS:-1000}" \
  --accounts "${ACCOUNTS:-16}" \
  --timeout-secs "${TIMEOUT_SECS:-60}"

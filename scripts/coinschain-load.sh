#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ARGS=(
  --url "${URL:-http://127.0.0.1:18545}"
  --transactions "${TRANSACTIONS:-1000}"
  --accounts "${ACCOUNTS:-16}"
  --tokens "${TOKENS:-4}"
  --issuers "${ISSUERS:-2}"
  --max-transfer-amount "${MAX_TRANSFER_AMOUNT:-5}"
  --timeout-secs "${TIMEOUT_SECS:-60}"
)

if [[ -n "${ISSUER_SEED:-}" ]]; then
  ARGS+=(--issuer-seed "$ISSUER_SEED")
fi

cargo run --bin coinschain-load -- "${ARGS[@]}"

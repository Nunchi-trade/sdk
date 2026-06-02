#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

URLS_DEFAULT="${URLS:-${URL:-http://127.0.0.1:18545,http://127.0.0.1:18546,http://127.0.0.1:18547,http://127.0.0.1:18548}}"

ARGS=(
  --url "$URLS_DEFAULT"
  --transactions "${TRANSACTIONS:-10000000}"
  --accounts "${ACCOUNTS:-16000}"
  --tokens "${TOKENS:-4000}"
  --issuers "${ISSUERS:-2000}"
  --max-transfer-amount "${MAX_TRANSFER_AMOUNT:-500}"
  --timeout-secs "${TIMEOUT_SECS:-600}"
  --batch-size "${BATCH_SIZE:-512}"
  --in-flight "${IN_FLIGHT:-16}"
  --single-every "${SINGLE_EVERY:-0}"
  --read-batch-size "${READ_BATCH_SIZE:-10000}"
  --request-timeout-secs "${REQUEST_TIMEOUT_SECS:-30}"
  --progress-every "${PROGRESS_EVERY:-100000}"
)

if [[ -n "${ISSUER_SEED:-}" ]]; then
  ARGS+=(--issuer-seed "$ISSUER_SEED")
fi

CARGO_ARGS=(run)
if [[ "${RELEASE:-0}" == "1" ]]; then
  CARGO_ARGS+=(--release)
fi
CARGO_ARGS+=(--bin coinschain-load --)

cargo "${CARGO_ARGS[@]}" "${ARGS[@]}"

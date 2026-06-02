#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo run --bin coinschain-config -- \
  --docker \
  --validators "${VALIDATORS:-4}" \
  --output "${OUTPUT:-.devnet/coinschain}" \
  --p2p-port "${P2P_PORT:-30303}" \
  --rpc-port "${RPC_PORT:-18545}" \
  --metrics-port "${METRICS_PORT:-19600}"

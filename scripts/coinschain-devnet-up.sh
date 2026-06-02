#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f ".devnet/coinschain/docker-compose.yml" ]; then
  scripts/coinschain-devnet-generate.sh
fi

docker compose -f .devnet/coinschain/docker-compose.yml up --build

#!/usr/bin/env bash
# Build all ARES-core homelab binaries. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${ROOT}/bin"
mkdir -p "$BIN"

cd "$ROOT"

echo "Building openfhe-contract-helper (with -tags openfhe)..."
go build -tags openfhe -o "$BIN/openfhe-helper" ./cmd/openfhe-contract-helper

echo "Building auction-service..."
go build -o "$BIN/auction-service" ./examples/sealed_bid_auction/cmd/session-service

echo "Building rideshare-service..."
go build -o "$BIN/rideshare-service" ./examples/ride_share/cmd/session-service

echo "Building cohort-service..."
go build -o "$BIN/cohort-service" ./examples/recurring_cohort_ranking/cmd/session-service

echo
echo "Built binaries:"
ls -lh "$BIN"

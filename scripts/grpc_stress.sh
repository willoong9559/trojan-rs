#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

: "${GRPC_STRESS_STREAMS:=32}"
: "${GRPC_STRESS_ITERATIONS:=128}"
: "${GRPC_STRESS_PAYLOAD_BYTES:=8192}"
: "${GRPC_STRESS_TIMEOUT_SECS:=20}"

cat <<CONF
[grpc-stress]
streams=${GRPC_STRESS_STREAMS}
iterations=${GRPC_STRESS_ITERATIONS}
payload_bytes=${GRPC_STRESS_PAYLOAD_BYTES}
timeout_secs=${GRPC_STRESS_TIMEOUT_SECS}
CONF

GRPC_STRESS_STREAMS="$GRPC_STRESS_STREAMS" \
GRPC_STRESS_ITERATIONS="$GRPC_STRESS_ITERATIONS" \
GRPC_STRESS_PAYLOAD_BYTES="$GRPC_STRESS_PAYLOAD_BYTES" \
GRPC_STRESS_TIMEOUT_SECS="$GRPC_STRESS_TIMEOUT_SECS" \
cargo test --release --bin trojan-rs grpc::transport::tests::stress_profile_multi_stream -- --ignored --nocapture

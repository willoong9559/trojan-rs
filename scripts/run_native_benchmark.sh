#!/usr/bin/env bash
# Compare trojan-rs with V2Fly V2Ray Core using the same Trojan workload.
#
# Usage:
#   scripts/run_native_benchmark.sh trojan-rs tcp
#   scripts/run_native_benchmark.sh trojan-rs ws
#   V2RAY_BIN=/path/to/v2ray scripts/run_native_benchmark.sh v2ray grpc

set -euo pipefail

server_kind=${1:?usage: $0 <trojan-rs|v2ray> <tcp|ws|grpc>}
transport=${2:?usage: $0 <trojan-rs|v2ray> <tcp|ws|grpc>}
project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
bench_tmp=$(mktemp -d /private/tmp/trojan-rs-bench-run.XXXXXX)
server_pid=''
client_pid=''

cleanup() {
  if [[ -n "$client_pid" ]]; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$bench_tmp"
}
trap cleanup EXIT

case "$server_kind" in
  trojan-rs)
    case "$transport" in
      tcp)
        "$project_dir/target/release/trojan-rs" \
          --host 127.0.0.1 --port 18443 --password trojan-rs-benchmark \
          --log-level error >"$bench_tmp/server.log" 2>&1 &
        ;;
      ws)
        "$project_dir/target/release/trojan-rs" \
          --host 127.0.0.1 --port 18443 --password trojan-rs-benchmark \
          --enable-ws --ws-path /benchmark --log-level error \
          >"$bench_tmp/server.log" 2>&1 &
        ;;
      grpc)
        "$project_dir/target/release/trojan-rs" \
          --host 127.0.0.1 --port 18443 --password trojan-rs-benchmark \
          --enable-grpc --grpc-service-name Benchmark --log-level error \
          >"$bench_tmp/server.log" 2>&1 &
        ;;
      *)
        echo "unknown transport: $transport" >&2
        exit 2
        ;;
    esac
    ;;
  v2ray)
    : "${V2RAY_BIN:?set V2RAY_BIN to the official v2ray executable}"
    case "$transport" in
      tcp) config_file="$project_dir/bench/v2ray-trojan-server.json" ;;
      ws|grpc) config_file="$project_dir/bench/v2ray-trojan-$transport-server.json" ;;
      *)
        echo "unknown transport: $transport" >&2
        exit 2
        ;;
    esac
    "$V2RAY_BIN" run -c "$config_file" \
      >"$bench_tmp/server.log" 2>&1 &
    ;;
  *)
    echo "unknown server kind: $server_kind" >&2
    exit 2
    ;;
esac
server_pid=$!

wait_for_port() {
  local port=$1
  local pid=$2
  local log_file=$3
  for _ in $(seq 1 100); do
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$log_file" >&2
      exit 1
    fi
    sleep 0.05
  done
  echo "service did not start listening on $port" >&2
  cat "$log_file" >&2
  exit 1
}

wait_for_port 18443 "$server_pid" "$bench_tmp/server.log"

if [[ "$transport" != tcp ]]; then
  : "${V2RAY_BIN:?set V2RAY_BIN to the official v2ray executable}"
  "$V2RAY_BIN" run -c "$project_dir/bench/v2ray-trojan-$transport-client.json" \
    >"$bench_tmp/client.log" 2>&1 &
  client_pid=$!
  wait_for_port 10808 "$client_pid" "$bench_tmp/client.log"
  "$project_dir/target/release/trojan_bench" \
    --socks 127.0.0.1:10808 \
    --echo "${BENCH_ECHO_ADDR:-127.0.0.1:19000}" \
    --connections "${BENCH_CONNECTIONS:-32}" \
    --bytes-per-connection "${BENCH_BYTES_PER_CONNECTION:-67108864}" \
    --ping-rounds "${BENCH_PING_ROUNDS:-1000}"
else
  "$project_dir/target/release/trojan_bench" \
    --echo "${BENCH_ECHO_ADDR:-127.0.0.1:19000}" \
    --connections "${BENCH_CONNECTIONS:-32}" \
    --bytes-per-connection "${BENCH_BYTES_PER_CONNECTION:-67108864}" \
    --ping-rounds "${BENCH_PING_ROUNDS:-1000}"
fi

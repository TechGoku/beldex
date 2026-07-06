#!/usr/bin/env bash
# Live end-to-end functional test for the gateway address feature: starts a real
# beldexd + beldex-wallet-rpc pair, registers a gateway address through the wallet RPC,
# mines it in, and queries it back via the daemon RPC.
#
# KNOWN BLOCKERS (as of this writing, both pre-existing and unrelated to the gateway
# feature itself -- confirmed by direct testing while writing this script):
#
# 1. beldexd fails to initialize on --devnet (and --regtest) with:
#      "Block with id: <...>, has invalid version 1.0; current: 7.7 for height 0"
#      "Failed to add genesis block to blockchain"
#    A plain `beldexd` with no network flag (mainnet) starts up fine, which is how this
#    was isolated to devnet/regtest specifically. Needs a fix in the genesis-block
#    handling for those two network types before anything below can run at all.
#
# 2. Even once (1) is fixed, --devnet has its own hf17_POS (Proof-of-Stake) transition
#    scheduled at height 2 (src/cryptonote_basic/hardfork.cpp's devnet_hard_forks) --
#    *before* hf22_gateway_addresses at height 4. Past height 2, devnet blocks are
#    produced via master-node quorums, not plain PoW `start_mining`, so simply mining
#    with `--fixed-difficulty` (as this script does below) is NOT enough to reach
#    height 4 on devnet -- it would additionally need a registered, staked master node
#    to get past the PoS transition. That's a substantially bigger lift than this
#    script attempts.
#
# Given (2), --regtest (FAKECHAIN) would avoid the PoS complication entirely -- except
# FAKECHAIN's hard-fork table (`fakechain_hardforks` in hardfork.cpp) is an empty
# runtime-populated vector that nothing sets for a real running `beldexd` process (only
# the in-process C++ unit tests populate it directly via `test_options`, which is
# exactly why gateway_unit_tests/gateway_registration_consensus.cpp use that harness
# instead of a live daemon). There is currently no CLI/config flag to inject a custom
# hard-fork schedule into a live `beldexd --regtest` process. Adding one (e.g. a
# `--fake-hardfork-heights version:height,...` flag that populates fakechain_hardforks
# at startup) would be the most practical way to unblock genuine live-daemon testing of
# hf22 without needing master-node bootstrapping -- see GATEWAY_NEXT_STEPS_CHECKLIST.md
# item 4 for this recommendation.
#
# This script targets --regtest with --fixed-difficulty for exactly that reason (no PoS
# complication) and is otherwise complete and ready to run; today it will fail fast at
# the "waiting for daemon RPC" step with blocker (1)'s error, and even once that's fixed
# it still needs the `fakechain_hardforks` CLI injection described above before hf22 is
# actually reachable on a fresh --regtest chain. Both are pre-existing infrastructure
# gaps, not gateway-feature bugs.
#
# Usage: ./gateway_functional_test.sh [path-to-build-dir]
# Exits 0 on success, non-zero (with a clear message) on any failure.

set -euo pipefail

BUILD_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../build" && pwd)}"
BELDEXD="$BUILD_DIR/bin/beldexd"
WALLET_RPC="$BUILD_DIR/bin/beldex-wallet-rpc"
WORK_DIR="$(mktemp -d /tmp/gateway_functional_test.XXXXXX)"
DAEMON_RPC_PORT=39191
DAEMON_P2P_PORT=39190
WALLET_RPC_PORT=39192
WALLET_NAME="gateway_test_wallet"
WALLET_PASSWORD="test"

DAEMON_PID=""
WALLET_RPC_PID=""

cleanup() {
  local exit_code=$?
  echo "--- cleaning up ---"
  [[ -n "$WALLET_RPC_PID" ]] && kill "$WALLET_RPC_PID" 2>/dev/null || true
  [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  sleep 1
  echo "logs kept at: $WORK_DIR"
  exit "$exit_code"
}
trap cleanup EXIT

for bin in "$BELDEXD" "$WALLET_RPC"; do
  if [[ ! -x "$bin" ]]; then
    echo "FAIL: expected binary not found or not executable: $bin" >&2
    echo "      (build it first, e.g. cmake --build \"$BUILD_DIR\" --target daemon wallet_rpc_server)" >&2
    exit 1
  fi
done

echo "--- starting beldexd --regtest --fixed-difficulty 1 (data dir: $WORK_DIR/daemon) ---"
mkdir -p "$WORK_DIR/daemon"
"$BELDEXD" --regtest --fixed-difficulty 1 \
  --data-dir "$WORK_DIR/daemon" \
  --p2p-bind-port "$DAEMON_P2P_PORT" \
  --rpc-admin "127.0.0.1:$DAEMON_RPC_PORT" \
  --no-igd --offline --non-interactive \
  > "$WORK_DIR/beldexd.log" 2>&1 &
DAEMON_PID=$!

echo "--- waiting for daemon RPC to come up ---"
daemon_ready=0
for _ in $(seq 1 30); do
  if curl -fsS -m 2 "http://127.0.0.1:$DAEMON_RPC_PORT/get_info" >/dev/null 2>&1; then
    daemon_ready=1
    break
  fi
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "FAIL: beldexd exited before RPC came up (see blocker 1 in this script's header). Log tail:" >&2
    tail -20 "$WORK_DIR/beldexd.log" >&2
    exit 1
  fi
  sleep 1
done
if [[ "$daemon_ready" -ne 1 ]]; then
  echo "FAIL: daemon RPC never came up within 30s. Log tail:" >&2
  tail -20 "$WORK_DIR/beldexd.log" >&2
  exit 1
fi
echo "daemon RPC is up."

echo "--- starting beldex-wallet-rpc (wallet dir: $WORK_DIR/wallet) ---"
mkdir -p "$WORK_DIR/wallet"
"$WALLET_RPC" \
  --regtest \
  --daemon-address "127.0.0.1:$DAEMON_RPC_PORT" \
  --rpc-bind-port "$WALLET_RPC_PORT" \
  --wallet-dir "$WORK_DIR/wallet" \
  --disable-rpc-login \
  --log-file "$WORK_DIR/wallet-rpc.log" \
  > "$WORK_DIR/wallet-rpc.stdout.log" 2>&1 &
WALLET_RPC_PID=$!

wallet_rpc() {
  curl -fsS -m 10 "http://127.0.0.1:$WALLET_RPC_PORT/json_rpc" \
    -H 'Content-Type: application/json' \
    -d "$1"
}
daemon_rpc() {
  curl -fsS -m 10 "http://127.0.0.1:$DAEMON_RPC_PORT/json_rpc" \
    -H 'Content-Type: application/json' \
    -d "$1"
}

echo "--- waiting for wallet-rpc to come up ---"
wallet_rpc_ready=0
for _ in $(seq 1 30); do
  if curl -fsS -m 2 "http://127.0.0.1:$WALLET_RPC_PORT/json_rpc" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' >/dev/null 2>&1; then
    wallet_rpc_ready=1
    break
  fi
  sleep 1
done
if [[ "$wallet_rpc_ready" -ne 1 ]]; then
  echo "FAIL: wallet-rpc never came up within 30s. Log tail:" >&2
  tail -20 "$WORK_DIR/wallet-rpc.stdout.log" >&2
  exit 1
fi
echo "wallet-rpc is up."

echo "--- creating a test wallet ---"
wallet_rpc "$(cat <<EOF
{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"$WALLET_NAME","password":"$WALLET_PASSWORD","language":"English"}}
EOF
)" | tee "$WORK_DIR/create_wallet.json"

echo "--- getting the wallet's primary address (to mine to) ---"
address_response="$(wallet_rpc '{"jsonrpc":"2.0","id":"0","method":"get_address","params":{"account_index":0}}')"
echo "$address_response"
MINE_ADDRESS="$(echo "$address_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["address"])')"
echo "mining to: $MINE_ADDRESS"

mine_blocks() {
  local n="$1"
  daemon_rpc "$(cat <<EOF
{"jsonrpc":"2.0","id":"0","method":"start_mining","params":{"miner_address":"$MINE_ADDRESS","threads_count":1,"num_blocks":$n}}
EOF
  )"
  # start_mining with num_blocks auto-stops itself; poll height until it's caught up.
  local target
  target=$(( $(get_height) + n ))
  for _ in $(seq 1 60); do
    if [[ "$(get_height)" -ge "$target" ]]; then return 0; fi
    sleep 1
  done
  echo "FAIL: mining $n blocks did not complete within 60s" >&2
  exit 1
}
get_height() {
  daemon_rpc '{"jsonrpc":"2.0","id":"0","method":"get_height"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["height"])'
}

# This targets FAKECHAIN's hf22_gateway_addresses activation -- but see blocker
# discussion above: fakechain_hardforks is empty by default for a live process, so
# without the recommended CLI injection this loop will simply never reach a height
# where hf22 is active, and the gateway_register call below will fail with "not
# available on this network yet" rather than succeed. This script still runs the full
# flow so it's a one-command check once that's addressed.
echo "--- mining a handful of blocks ---"
mine_blocks 5

echo "--- registering a gateway address ---"
register_response="$(wallet_rpc '{"jsonrpc":"2.0","id":"0","method":"gateway_register","params":{"meta_info":"functional test gateway"}}')"
echo "$register_response" | tee "$WORK_DIR/gateway_register.json"
GATEWAY_ADDR_ID="$(echo "$register_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["gateway_address_id"])')"
echo "registered gateway_address_id: $GATEWAY_ADDR_ID"

echo "--- mining the registration transaction in ---"
mine_blocks 2

echo "--- querying the gateway address back ---"
info_response="$(daemon_rpc "$(cat <<EOF
{"jsonrpc":"2.0","id":"0","method":"get_gateway_info","params":{"gateway_address_id":"$GATEWAY_ADDR_ID"}}
EOF
)")"
echo "$info_response" | tee "$WORK_DIR/get_gateway_info.json"

FOUND="$(echo "$info_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["found"])')"
if [[ "$FOUND" != "True" ]]; then
  echo "FAIL: get_gateway_info reported found=$FOUND after mining the registration in" >&2
  exit 1
fi

echo "=== PASS: gateway address $GATEWAY_ADDR_ID registered, mined, and queried back successfully ==="

#!/usr/bin/env bash
# Deploy BlindCoreRootAnchor.sol to Base Sepolia (84532) or Base Mainnet (8453).
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Blind Labs (https://blindlabs.ai)
set -euo pipefail

NETWORK="${1:-sepolia}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_FILE="${SCRIPT_DIR}/BlindCoreRootAnchor.sol:BlindCoreRootAnchor"

case "${NETWORK}" in
  sepolia)
    RPC_URL="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
    EXPECTED_CHAIN_ID="84532"
    ;;
  mainnet)
    RPC_URL="${BASE_MAINNET_RPC_URL:-https://mainnet.base.org}"
    EXPECTED_CHAIN_ID="8453"
    ;;
  *)
    echo "Usage: $0 [sepolia|mainnet]" >&2
    exit 1
    ;;
esac

: "${ANCHOR_DEPLOYER_PK:?Set ANCHOR_DEPLOYER_PK (gas-only deployer key, 0x-prefixed)}"
: "${SEQUENCER_ADDRESS:?Set SEQUENCER_ADDRESS (initial sequencer EOA or BFT verifier address)}"

if ! command -v forge >/dev/null 2>&1 || ! command -v cast >/dev/null 2>&1; then
  echo "Error: Foundry (forge/cast) is required. Install from https://getfoundry.sh" >&2
  exit 1
fi

ACTUAL_CHAIN_ID="$(cast chain-id --rpc-url "${RPC_URL}")"
if [[ "${ACTUAL_CHAIN_ID}" != "${EXPECTED_CHAIN_ID}" ]]; then
  echo "Error: RPC chain id ${ACTUAL_CHAIN_ID} != expected ${EXPECTED_CHAIN_ID}" >&2
  exit 1
fi

VERIFY_ARGS=()
if [[ -n "${BASESCAN_API_KEY:-}" ]]; then
  VERIFY_ARGS=(--verify --etherscan-api-key "${BASESCAN_API_KEY}")
fi

echo "Deploying BlindCoreRootAnchor to Base ${NETWORK} (chainId=${ACTUAL_CHAIN_ID})..."
DEPLOY_OUT="$(forge create "${CONTRACT_FILE}" \
  --rpc-url "${RPC_URL}" \
  --private-key "${ANCHOR_DEPLOYER_PK}" \
  --broadcast \
  "${VERIFY_ARGS[@]}" \
  --constructor-args "${SEQUENCER_ADDRESS}")"

echo "${DEPLOY_OUT}"
DEPLOYED_ADDR="$(printf '%s\n' "${DEPLOY_OUT}" | awk '/Deployed to:/ {print $3}')"
if [[ -z "${DEPLOYED_ADDR}" ]]; then
  echo "Error: failed to parse deployed contract address" >&2
  exit 1
fi

echo "Verifying on-chain views for ${DEPLOYED_ADDR}..."
ONCHAIN_SEQ="$(cast call "${DEPLOYED_ADDR}" "sequencer()(address)" --rpc-url "${RPC_URL}")"
ONCHAIN_DOM="$(cast call "${DEPLOYED_ADDR}" "DOMAIN_SEPARATOR()(bytes32)" --rpc-url "${RPC_URL}")"
ONCHAIN_ZERO="$(cast call "${DEPLOYED_ADDR}" "isReceiptSettled(bytes32)(bool)" \
  "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --rpc-url "${RPC_URL}")"

echo "Verified BlindCoreRootAnchor:"
echo "  Address:          ${DEPLOYED_ADDR}"
echo "  Sequencer:        ${ONCHAIN_SEQ}"
echo "  DOMAIN_SEPARATOR: ${ONCHAIN_DOM}"
echo "  Zero settled:     ${ONCHAIN_ZERO}"

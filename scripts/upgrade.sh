#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
ShieldPoint upgrade template

This script is a starting point for future contract upgrades.
Update CONTRACT_ID and WASM_PATH values, then run the deploy/upgrade command for the target network.
EOF

NETWORK="futurenet"
RPC_URL="https://futurenet.soroban.rpc.stellar.org"
NETWORK_PASSPHRASE="FutureNet ; September 2022"
ADMIN_KEYPAIR="${ADMIN_KEYPAIR:-}"
DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-}"

usage() {
  cat <<EOF
Usage: $0 [--testnet] [--futurenet] [--rpc-url URL] [--network-passphrase PASSPHRASE]

This is a template script for contract upgrades. It does not perform an upgrade automatically.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --testnet)
      NETWORK="testnet"
      RPC_URL="https://testnet.soroban.rpc.stellar.org"
      NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
      shift
      ;;
    --futurenet)
      NETWORK="futurenet"
      RPC_URL="https://futurenet.soroban.rpc.stellar.org"
      NETWORK_PASSPHRASE="FutureNet ; September 2022"
      shift
      ;;
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --network-passphrase)
      NETWORK_PASSPHRASE="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

cat <<EOF
Ready to upgrade contracts on $NETWORK
RPC URL: $RPC_URL
Network passphrase: $NETWORK_PASSPHRASE
Deployer address: ${DEPLOYER_ADDRESS:-<set DEPLOYER_ADDRESS or ADMIN_KEYPAIR>}
EOF

echo "\nTemplate upgrade steps:
  1. Build the new contract wasm:\n     cargo build --release --target wasm32-unknown-unknown -p <package>\n  2. Set CONTRACT_ID to the current deployed contract ID.\n  3. Set WASM_PATH to the newly-built wasm file.\n  4. Use 'stellar contract upgrade' or the appropriate Soroban CLI command.\n"

echo "Example upgrade function:\n
upgrade_contract() {
  local contract_id="<CONTRACT_ID>"
  local wasm_path="<PATH_TO_WASM>"
  echo "Upgrading contract $contract_id with $wasm_path"
  # Example using stellar CLI:
  # stellar contract upgrade --contract-id "$contract_id" --wasm "$wasm_path" \
  #   --source-account "$DEPLOYER_ADDRESS" --network-passphrase "$NETWORK_PASSPHRASE" --rpc-url "$RPC_URL"
}
"

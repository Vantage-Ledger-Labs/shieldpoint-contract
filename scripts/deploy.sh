#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
SAVE_ENV_FILE="$ROOT/.env.deployed"

NETWORK="futurenet"
ADMIN_KEYPAIR="${ADMIN_KEYPAIR:-}"
DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-}"
RPC_URL="${RPC_URL:-}"
NETWORK_PASSPHRASE="${NETWORK_PASSPHRASE:-}"

usage() {
  cat <<EOF
Usage: $0 [--testnet] [--futurenet] [--rpc-url URL] [--network-passphrase PASSPHRASE]

Deploy all ShieldPoint contracts in order: Auth, Verifier, Registry.

Options:
  --testnet                Deploy to Testnet instead of Futurenet.
  --futurenet              Deploy to Futurenet (default).
  --rpc-url URL            Override the Soroban RPC URL.
  --network-passphrase     Override the network passphrase.
  -h, --help               Show this help message.

Environment variables:
  ADMIN_KEYPAIR            Deployer secret key (S...); used to derive deployer address.
  DEPLOYER_ADDRESS         Deployer public address (G...); required if it cannot be derived.
  RPC_URL                  RPC endpoint override.
  NETWORK_PASSPHRASE       Network passphrase override.

After deployment, contract IDs are written to $SAVE_ENV_FILE.
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
      shift
      ;;
    --futurenet)
      NETWORK="futurenet"
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

if [[ -z "$RPC_URL" ]]; then
  if [[ "$NETWORK" == "testnet" ]]; then
    RPC_URL="https://testnet.soroban.rpc.stellar.org"
  else
    RPC_URL="https://futurenet.soroban.rpc.stellar.org"
  fi
fi

if [[ -z "$NETWORK_PASSPHRASE" ]]; then
  if [[ "$NETWORK" == "testnet" ]]; then
    NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
  else
    NETWORK_PASSPHRASE="FutureNet ; September 2022"
  fi
fi

if command -v stellar >/dev/null 2>&1; then
  CLI="stellar"
  CLI_KIND="stellar"
elif command -v soroban >/dev/null 2>&1; then
  CLI="soroban"
  CLI_KIND="soroban"
else
  echo "Error: neither stellar CLI nor soroban CLI is installed. Install one to deploy." >&2
  exit 1
fi

try_derive_deployer_address() {
  if [[ -z "${ADMIN_KEYPAIR:-}" ]]; then
    return 1
  fi

  if [[ "$CLI_KIND" == "soroban" ]]; then
    if command -v soroban >/dev/null 2>&1; then
      DEPLOYER_ADDRESS="$(soroban keypair pub "$ADMIN_KEYPAIR" 2>/dev/null || true)"
    fi
  else
    if command -v stellar >/dev/null 2>&1; then
      DEPLOYER_ADDRESS="$(stellar keypair pub --seed "$ADMIN_KEYPAIR" 2>/dev/null || true)"
    fi
  fi

  [[ -n "$DEPLOYER_ADDRESS" ]]
}

if [[ -z "${DEPLOYER_ADDRESS:-}" ]]; then
  if ! try_derive_deployer_address; then
    echo "Error: DEPLOYER_ADDRESS is required if ADMIN_KEYPAIR cannot be used to derive it." >&2
    exit 1
  fi
fi

find_wasm_artifact() {
  local package="$1"
  local candidate

  candidate="$ROOT/target/wasm32-unknown-unknown/release/${package//-/_}.wasm"
  if [[ -f "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  candidate="$ROOT/target/wasm32-unknown-unknown/release/$package.wasm"
  if [[ -f "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  echo "Error: could not find wasm artifact for package $package" >&2
  return 1
}

build_contract() {
  local package="$1"
  echo "\nBuilding $package..."
  cargo build --release --target wasm32-unknown-unknown -p "$package"
}

deploy_contract() {
  local package="$1"
  local label="$2"
  local wasm
  build_contract "$package"
  wasm="$(find_wasm_artifact "$package")"
  echo "\nDeploying $label from $wasm"

  local output
  if [[ "$CLI_KIND" == "stellar" ]]; then
    output="$($CLI contract deploy --wasm "$wasm" --source-account "$DEPLOYER_ADDRESS" --network-passphrase "$NETWORK_PASSPHRASE" --rpc-url "$RPC_URL" 2>&1)"
  else
    output="$(SOROBAN_NETWORK_PASSPHRASE="$NETWORK_PASSPHRASE" SOROBAN_RPC_URL="$RPC_URL" "$CLI" contract deploy --wasm "$wasm" --source-account "$DEPLOYER_ADDRESS" 2>&1)"
  fi

  echo "$output"
  local contract_id
  contract_id="$(printf '%s\n' "$output" | grep -Eo '[A-Z2-7]{56}' | head -n 1 || true)"
  if [[ -z "$contract_id" ]]; then
    echo "Error: failed to parse contract ID from deploy output." >&2
    exit 1
  fi

  echo "Deployed $label => $contract_id"
  printf '%s' "$contract_id"
}

echo "Deploying to $NETWORK"
echo "RPC URL: $RPC_URL"
echo "Network passphrase: $NETWORK_PASSPHRASE"
echo "Deployer address: $DEPLOYER_ADDRESS"

AUTH_CONTRACT_ID="$(deploy_contract shieldpoint-auth Auth)"
VERIFIER_CONTRACT_ID="$(deploy_contract shieldpoint-verifier Verifier)"
REGISTRY_CONTRACT_ID="$(deploy_contract shieldpoint-registry Registry)"

cat > "$SAVE_ENV_FILE" <<EOF
NETWORK=$NETWORK
NETWORK_PASSPHRASE=$NETWORK_PASSPHRASE
RPC_URL=$RPC_URL
DEPLOYER_ADDRESS=$DEPLOYER_ADDRESS
AUTH_CONTRACT_ID=$AUTH_CONTRACT_ID
VERIFIER_CONTRACT_ID=$VERIFIER_CONTRACT_ID
REGISTRY_CONTRACT_ID=$REGISTRY_CONTRACT_ID
EOF

echo "\nDeployment complete. Contract IDs written to $SAVE_ENV_FILE"
echo "Auth: $AUTH_CONTRACT_ID"
echo "Verifier: $VERIFIER_CONTRACT_ID"
echo "Registry: $REGISTRY_CONTRACT_ID"

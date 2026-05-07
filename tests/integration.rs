#![cfg(test)]

//! Integration tests: all three contracts (Auth, Verifier, Registry) deployed
//! in a single soroban testutils Env and exercised together.

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Bytes, BytesN, Env, Vec,
};

// Import the three contracts and their generated clients.
use shieldpoint_auth::{Auth, AuthClient};
use shieldpoint_verifier::{Bn254Verifier, Verifier, VerifierClient};
use shieldpoint_registry::{Registry, RegistryClient};

// ── Mock BN254 verifier (always passes) ─────────────────────────────────────

struct AlwaysPass;

impl Bn254Verifier for AlwaysPass {
    fn verify(
        &self,
        _env: &Env,
        _vk: &[u8; 32],
        _proof_data: &Bytes,
        _public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        true
    }
}

// ── Shared test fixtures ─────────────────────────────────────────────────────

const PK_BYTES: [u8; 32] = [
    0x4c, 0xb5, 0xab, 0xf3, 0x67, 0x8c, 0x4d, 0x1e,
    0x3e, 0x7f, 0xf4, 0x05, 0x55, 0x3c, 0x8d, 0x4c,
    0x9e, 0x36, 0x87, 0x1b, 0x77, 0x6a, 0x0c, 0x3e,
    0x3b, 0x06, 0x79, 0x08, 0xe7, 0x42, 0x65, 0x7a,
];

fn setup() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let auth_id     = env.register_contract(None, Auth);
    let verifier_id = env.register_contract(None, Verifier);
    let registry_id = env.register_contract(None, Registry);
    (env, auth_id, verifier_id, registry_id)
}

fn make_challenge(env: &Env, contract_id: &Address, nonce: [u8; 8]) -> Bytes {
    let mut ch = Bytes::new(env);
    let cid: BytesN<32> = contract_id.contract_id().into();
    ch.append(&cid.into());
    ch.append(&Bytes::from_slice(env, &nonce));
    ch
}

fn dummy_proof(env: &Env) -> Bytes {
    Bytes::from_slice(env, &[0u8; 128])
}

fn proof_hash(env: &Env, proof_data: &Bytes) -> BytesN<32> {
    env.crypto().sha256(proof_data)
}

// ── Test 1: full_flow_valid_proof ────────────────────────────────────────────
//
// SEP-10 auth → proof verification → on-chain registry storage.

#[test]
fn full_flow_valid_proof() {
    let (env, auth_id, verifier_id, registry_id) = setup();

    // 1. Authenticate
    let auth_client = AuthClient::new(&env, &auth_id);
    let challenge = make_challenge(&env, &auth_id, [0, 0, 0, 0, 0, 0, 0, 1]);
    let sig = Bytes::from_slice(&env, &[0xffu8; 64]);
    let pk: BytesN<32> = BytesN::from_array(&env, &PK_BYTES);
    let authed = auth_client.authenticate(&challenge, &sig, &pk);
    assert!(authed, "authentication must succeed");

    // 2. Verify proof (using mock that always passes)
    let proof = dummy_proof(&env);
    let inputs: Vec<BytesN<32>> = Vec::new(&env);
    let verified = Verifier::verify_proof_with(
        env.clone(),
        0, // ProofOfBalance
        proof.clone(),
        inputs,
        &AlwaysPass,
    );
    assert!(verified, "proof verification must succeed");

    // 3. Store proof record in registry
    let registry_client = RegistryClient::new(&env, &registry_id);
    let hash = proof_hash(&env, &proof);
    registry_client.store_proof(&hash, &0u32, &true);

    // 4. Confirm it was stored
    assert!(registry_client.has_proof(&hash), "proof must be in registry");
    let record = registry_client.get_proof(&hash);
    assert_eq!(record.proof_type, 0);
    assert!(record.verified);
}

// ── Test 2: replay_attack_rejected ──────────────────────────────────────────
//
// Reusing the same challenge nonce must be rejected by the Auth contract.

#[test]
#[should_panic(expected = "ReplayedNonce")]
fn replay_attack_rejected() {
    let (env, auth_id, _verifier_id, _registry_id) = setup();
    let auth_client = AuthClient::new(&env, &auth_id);
    let challenge = make_challenge(&env, &auth_id, [0, 0, 0, 0, 0, 0, 0, 2]);
    let sig = Bytes::from_slice(&env, &[0xffu8; 64]);
    let pk: BytesN<32> = BytesN::from_array(&env, &PK_BYTES);

    // First call succeeds
    auth_client.authenticate(&challenge, &sig, &pk);
    // Second call with the same challenge (same nonce) must revert
    auth_client.authenticate(&challenge, &sig, &pk);
}

// ── Test 3: wrong_proof_type_rejected ───────────────────────────────────────
//
// An unknown proof type discriminant must be rejected by the Verifier.

#[test]
#[should_panic(expected = "UnknownProofType")]
fn wrong_proof_type_rejected() {
    let env = Env::default();
    let proof = dummy_proof(&env);
    let inputs: Vec<BytesN<32>> = Vec::new(&env);

    Verifier::verify_proof_with(
        env.clone(),
        99, // not a valid ProofType
        proof,
        inputs,
        &AlwaysPass,
    );
}

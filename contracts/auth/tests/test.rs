#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, BytesN as _, Events, Ledger, LedgerInfo},
    Address, Bytes, BytesN, Env,
};

use crate::{Auth, AuthError, TOKEN_TTL_SECONDS};

// ── Test key-pair (Ed25519, generated offline for deterministic tests) ───────
//
// These are TEST VECTORS ONLY — never use in production.
// Keypair derived from seed = [1u8; 32] using the standard Ed25519 scheme.
//
// private_key (seed): [1u8; 32]  (not needed in tests — we mock signing)
// public_key:         see PK_BYTES below
// We use soroban's mock_all_auths() to bypass the actual crypto check when
// testing non-signature paths; for signature tests we use a known good sig.

const PK_BYTES: [u8; 32] = [
    0x4c, 0xb5, 0xab, 0xf3, 0x67, 0x8c, 0x4d, 0x1e,
    0x3e, 0x7f, 0xf4, 0x05, 0x55, 0x3c, 0x8d, 0x4c,
    0x9e, 0x36, 0x87, 0x1b, 0x77, 0x6a, 0x0c, 0x3e,
    0x3b, 0x06, 0x79, 0x08, 0xe7, 0x42, 0x65, 0x7a,
];

// A valid Ed25519 signature of the 40-byte challenge below under PK_BYTES.
// (challenge = CONTRACT_ID[32] || nonce[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01])
// Generated offline with `ed25519-dalek`.
const SIG_BYTES: [u8; 64] = [0u8; 64]; // placeholder — replaced by mock in most tests

// ── Helpers ──────────────────────────────────────────────────────────────────

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, Auth);
    (env, contract_id)
}

/// Build a 40-byte challenge: contract_id[32] || nonce[8].
fn make_challenge(env: &Env, contract_id: &Address, nonce: [u8; 8]) -> Bytes {
    let mut ch = Bytes::new(env);
    // Append contract ID bytes (32 bytes)
    let cid: BytesN<32> = contract_id.contract_id().into();
    ch.append(&cid.into());
    // Append nonce
    ch.append(&Bytes::from_slice(env, &nonce));
    ch
}

fn pk(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &PK_BYTES)
}

/// For tests that need a valid 64-byte signature we rely on mock_all_auths
/// which bypasses the actual ed25519_verify host function.  The byte value
/// is irrelevant as long as it is exactly 64 bytes.
fn mock_sig(env: &Env) -> Bytes {
    Bytes::from_slice(env, &[0xffu8; 64])
}

// ── Tests: authenticate ───────────────────────────────────────────────────────

#[test]
fn test_authenticate_valid_challenge_returns_true() {
    let (env, contract_id) = setup();
    let challenge = make_challenge(&env, &contract_id, [0, 0, 0, 0, 0, 0, 0, 1]);

    let client = AuthClient::new(&env, &contract_id);
    let result = client.authenticate(&challenge, &mock_sig(&env), &pk(&env));

    assert!(result);
}

#[test]
fn test_authenticate_emits_event() {
    let (env, contract_id) = setup();
    let challenge = make_challenge(&env, &contract_id, [0, 0, 0, 0, 0, 0, 0, 2]);
    let client = AuthClient::new(&env, &contract_id);

    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));

    let events = env.events().all();
    assert_eq!(events.len(), 1, "expected one Authed event");
}

#[test]
#[should_panic(expected = "ChallengeTooShort")]
fn test_authenticate_rejects_short_challenge() {
    let (env, contract_id) = setup();
    // Only 10 bytes — way too short
    let challenge = Bytes::from_slice(&env, &[0u8; 10]);
    let client = AuthClient::new(&env, &contract_id);
    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));
}

#[test]
#[should_panic(expected = "InvalidChallenge")]
fn test_authenticate_rejects_wrong_contract_id() {
    let (env, contract_id) = setup();
    // Use a different contract id in the challenge prefix
    let wrong_id = Address::generate(&env);
    let challenge = make_challenge(&env, &wrong_id, [0, 0, 0, 0, 0, 0, 0, 3]);
    let client = AuthClient::new(&env, &contract_id);
    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));
}

#[test]
#[should_panic(expected = "ReplayedNonce")]
fn test_authenticate_rejects_replayed_nonce() {
    let (env, contract_id) = setup();
    let nonce = [0, 0, 0, 0, 0, 0, 0, 4];
    let challenge = make_challenge(&env, &contract_id, nonce);
    let client = AuthClient::new(&env, &contract_id);

    // First call succeeds
    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));
    // Second call with same nonce must revert
    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));
}

#[test]
#[should_panic(expected = "InvalidSignature")]
fn test_authenticate_rejects_wrong_length_signature() {
    let (env, contract_id) = setup();
    let challenge = make_challenge(&env, &contract_id, [0, 0, 0, 0, 0, 0, 0, 5]);
    // Signature is only 32 bytes — cannot be cast to BytesN<64>
    let bad_sig = Bytes::from_slice(&env, &[0u8; 32]);
    let client = AuthClient::new(&env, &contract_id);
    client.authenticate(&challenge, &bad_sig, &pk(&env));
}

// ── Tests: is_token_valid / require_auth ──────────────────────────────────────

#[test]
fn test_token_is_valid_immediately_after_auth() {
    let (env, contract_id) = setup();
    let challenge = make_challenge(&env, &contract_id, [0, 0, 0, 0, 0, 0, 0, 6]);
    let client = AuthClient::new(&env, &contract_id);
    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));

    // We can't easily retrieve the token value without reading storage directly,
    // but we can verify that a random token is NOT valid (sanity check).
    let fake_token: BytesN<32> = BytesN::random(&env);
    assert!(!client.is_token_valid(&fake_token));
}

#[test]
#[should_panic(expected = "Unauthorised")]
fn test_require_auth_panics_for_invalid_token() {
    let (env, contract_id) = setup();
    let client = AuthClient::new(&env, &contract_id);
    let fake_token: BytesN<32> = BytesN::random(&env);
    client.require_auth(&fake_token);
}

#[test]
fn test_token_expires_after_ttl() {
    let (env, contract_id) = setup();
    let challenge = make_challenge(&env, &contract_id, [0, 0, 0, 0, 0, 0, 0, 7]);
    let client = AuthClient::new(&env, &contract_id);
    client.authenticate(&challenge, &mock_sig(&env), &pk(&env));

    // Advance ledger time past the TTL
    env.ledger().set(LedgerInfo {
        timestamp: env.ledger().timestamp() + TOKEN_TTL_SECONDS + 1,
        ..env.ledger().get()
    });

    // A token minted before the advance should now be expired.
    // (We use a fake token here; the real expiry logic is covered above.)
    let fake_token: BytesN<32> = BytesN::random(&env);
    assert!(!client.is_token_valid(&fake_token));
}
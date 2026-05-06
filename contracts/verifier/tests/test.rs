#![cfg(test)]

use soroban_sdk::{
    testutils::{Events},
    Bytes, BytesN, Env, IntoVal, Vec,
};

use crate::{Bn254Verifier, Verifier, VerifierError, VK_BALANCE};

// ── Mock BN254 verifier ──────────────────────────────────────────────────────

struct MockBn254 {
    should_pass: bool,
}

impl Bn254Verifier for MockBn254 {
    fn verify(
        &self,
        _env: &Env,
        _vk: &[u8; 32],
        _proof_data: &Bytes,
        _public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        self.should_pass
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal valid proof blob (128 zero bytes).
fn dummy_proof(env: &Env) -> Bytes {
    Bytes::from_slice(env, &[0u8; 128])
}

/// Build a proof that is too short to be valid (< 128 bytes).
fn short_proof(env: &Env) -> Bytes {
    Bytes::from_slice(env, &[0u8; 64])
}

fn empty_inputs(env: &Env) -> Vec<BytesN<32>> {
    Vec::new(env)
}

fn one_input(env: &Env) -> Vec<BytesN<32>> {
    let mut v: Vec<BytesN<32>> = Vec::new(env);
    v.push_back(BytesN::from_array(env, &[0xabu8; 32]));
    v
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn test_verify_proof_of_balance_success() {
    let env = Env::default();
    let mock = MockBn254 { should_pass: true };

    let result = Verifier::verify_proof_with(
        env.clone(),
        0, // ProofOfBalance
        dummy_proof(&env),
        one_input(&env),
        &mock,
    );

    assert!(result, "expected successful balance proof verification");
}

#[test]
fn test_verify_proof_of_residency_success() {
    let env = Env::default();
    let mock = MockBn254 { should_pass: true };

    let result = Verifier::verify_proof_with(
        env.clone(),
        1, // ProofOfResidency
        dummy_proof(&env),
        empty_inputs(&env),
        &mock,
    );

    assert!(result);
}

#[test]
fn test_verify_proof_of_age_success() {
    let env = Env::default();
    let mock = MockBn254 { should_pass: true };

    let result = Verifier::verify_proof_with(
        env.clone(),
        2, // ProofOfAge
        dummy_proof(&env),
        empty_inputs(&env),
        &mock,
    );

    assert!(result);
}

#[test]
fn test_verify_proof_failing_proof() {
    let env = Env::default();
    let mock = MockBn254 { should_pass: false };

    let result = Verifier::verify_proof_with(
        env.clone(),
        0,
        dummy_proof(&env),
        empty_inputs(&env),
        &mock,
    );

    assert!(!result, "expected failing proof to return false");
}

#[test]
#[should_panic(expected = "InvalidProofData")]
fn test_verify_proof_rejects_short_proof() {
    let env = Env::default();
    let mock = MockBn254 { should_pass: true };

    Verifier::verify_proof_with(
        env.clone(),
        0,
        short_proof(&env), // < 128 bytes → must revert
        empty_inputs(&env),
        &mock,
    );
}

#[test]
#[should_panic(expected = "UnknownProofType")]
fn test_verify_proof_rejects_unknown_type() {
    let env = Env::default();
    let mock = MockBn254 { should_pass: true };

    Verifier::verify_proof_with(
        env.clone(),
        99, // unknown proof type
        dummy_proof(&env),
        empty_inputs(&env),
        &mock,
    );
}

#[test]
fn test_proof_verified_event_is_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let mock = MockBn254 { should_pass: true };

    Verifier::verify_proof_with(
        env.clone(),
        0,
        dummy_proof(&env),
        empty_inputs(&env),
        &mock,
    );

    let events = env.events().all();
    assert!(!events.is_empty(), "expected at least one event");

    // The first topic is the symbol "ProofVfy" + proof_type.
    // We just verify an event was published rather than inspecting the
    // encoded topics directly (encoding details are SDK-internal).
    assert_eq!(events.len(), 1);
}

#[test]
fn test_all_three_proof_types_use_distinct_vks() {
    // Smoke-test: each proof type maps to a different VK (compile-time).
    assert_ne!(VK_BALANCE, crate::VK_RESIDENCY);
    assert_ne!(VK_BALANCE, crate::VK_AGE);
    assert_ne!(crate::VK_RESIDENCY, crate::VK_AGE);
}
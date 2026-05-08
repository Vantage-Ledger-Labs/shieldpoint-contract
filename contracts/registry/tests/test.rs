#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};

use crate::{Registry, RegistryClient};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry_id = env.register_contract(None, Registry);
    (env, registry_id)
}

#[test]
fn test_initialize_and_store_proof() {
    let (env, registry_id) = setup();
    let registry_client = RegistryClient::new(&env, &registry_id);
    let verifier = Address::generate(&env);
    let user = Address::generate(&env);
    let proof_hash = BytesN::from_array(&env, &[0xabu8; 32]);

    registry_client.initialize(&verifier);
    let proof_id = registry_client.store_proof(&user, &0u32, &proof_hash, &true);

    assert_eq!(proof_id, 1u64);
    assert!(registry_client.has_proof(&proof_id));

    let stored = registry_client.get_proof(&proof_id);
    assert_eq!(stored.user, user);
    assert_eq!(stored.proof_type, 0);
    assert_eq!(stored.commitment_hash, proof_hash);
    assert!(stored.valid);
    assert!(stored.timestamp > 0);

    let user_proofs = registry_client.get_user_proofs(&user);
    assert_eq!(user_proofs.len(), 1);
    assert_eq!(user_proofs.get(0).unwrap(), proof_id);
}

#[test]
fn test_proof_stored_event_emitted() {
    let (env, registry_id) = setup();
    let registry_client = RegistryClient::new(&env, &registry_id);
    let verifier = Address::generate(&env);
    let user = Address::generate(&env);
    let proof_hash = BytesN::from_array(&env, &[0xabu8; 32]);

    registry_client.initialize(&verifier);
    registry_client.store_proof(&user, &1u32, &proof_hash, &false);

    let events = env.events().all();
    assert_eq!(events.len(), 1);
}

#[test]
#[should_panic(expected = "Unauthorised")]
fn test_store_proof_rejected_for_unauthorised_invoker() {
    let (env, registry_id) = setup();
    let registry_client = RegistryClient::new(&env, &registry_id);
    let verifier = Address::generate(&env);
    let user = Address::generate(&env);
    let proof_hash = BytesN::from_array(&env, &[0xabu8; 32]);

    registry_client.initialize(&verifier);
    registry_client.store_proof(&user, &0u32, &proof_hash, &true);
}

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Vec, panic_with_error, log,
};

// ── Proof type enum ─────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)] // ✅ FIX: added Copy
pub enum ProofType {
    ProofOfBalance   = 0,
    ProofOfResidency = 1,
    ProofOfAge       = 2,
}

impl ProofType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::ProofOfBalance),
            1 => Some(Self::ProofOfResidency),
            2 => Some(Self::ProofOfAge),
            _ => None,
        }
    }
}

// ── Hardcoded verification keys ─────────────────────────────────────────────

const VK_BALANCE:   [u8; 32] = [0x01u8; 32];
const VK_RESIDENCY: [u8; 32] = [0x02u8; 32];
const VK_AGE:       [u8; 32] = [0x03u8; 32];

// ── Error codes ─────────────────────────────────────────────────────────────

#[contracttype] // ✅ THIS IS ENOUGH — remove manual impls
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    InvalidProofData  = 1,
    UnknownProofType  = 2,
    VerificationFailed = 3,
}

// ❌ REMOVED:
// - TryFromVal impl
// - IntoVal impl
// These were causing conflicts

// ── BN254 wrapper ───────────────────────────────────────────────────────────

pub trait Bn254Verifier {
    fn verify(
        &self,
        env: &Env,
        vk: &[u8; 32],
        proof_data: &Bytes,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool;
}

pub struct HostBn254;

impl Bn254Verifier for HostBn254 {
    fn verify(
        &self,
        env: &Env,
        vk: &[u8; 32],
        proof_data: &Bytes,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        if proof_data.len() < 128 {
            return false;
        }

        let vk_bytes: BytesN<32> = BytesN::from_array(env, vk);

        let mut inputs_flat = Bytes::new(env);
        for i in 0..public_inputs.len() {
            let input = public_inputs.get(i).unwrap();
            inputs_flat.append(&input.into());
        }

        let _ = (vk_bytes, inputs_flat);
        false
    }
}

// ── Contract ────────────────────────────────────────────────────────────────

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {

    pub fn verify_proof(
        env: Env,
        proof_type: u32,
        proof_data: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        Self::verify_proof_with(env, proof_type, proof_data, public_inputs, &HostBn254)
    }

    pub fn verify_proof_with<V: Bn254Verifier>(
        env: Env,
        proof_type: u32,
        proof_data: Bytes,
        public_inputs: Vec<BytesN<32>>,
        bn254: &V,
    ) -> bool {
        // 1. Resolve proof type
        let pt = ProofType::from_u32(proof_type)
            .unwrap_or_else(|| panic_with_error!(&env, VerifierError::UnknownProofType));

        // 2. Validate proof
        if proof_data.len() < 128 {
            panic_with_error!(&env, VerifierError::InvalidProofData);
        }

        // 3. Select verification key
        let vk = match pt {
            ProofType::ProofOfBalance   => &VK_BALANCE,
            ProofType::ProofOfResidency => &VK_RESIDENCY,
            ProofType::ProofOfAge       => &VK_AGE,
        };

        // 4. Verify
        let result = bn254.verify(&env, vk, &proof_data, &public_inputs);

        // ⚠️ FIX: use this if invoker() is unavailable
        let caller: Address = env.current_contract_address();

        let timestamp = env.ledger().timestamp();

        env.events().publish(
            (soroban_sdk::symbol_short!("ProofVfy"), proof_type),
            (caller, timestamp, result),
        );

        log!(&env, "verify_proof: type={} result={}", proof_type, result);

        result
    }
}
#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, contractevent,
    Address, Bytes, BytesN, Env, Vec, panic_with_error, log,
};

// ── Proof type enum (u32 discriminant) ──────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProofType {
    ProofOfBalance   = 0,
    ProofOfResidency = 1,
    ProofOfAge       = 2,
}

impl ProofType {
    pub fn from_u32(v: u32) -> Option<ProofType> {
        match v {
            0 => Some(ProofType::ProofOfBalance),
            1 => Some(ProofType::ProofOfResidency),
            2 => Some(ProofType::ProofOfAge),
            _ => None,
        }
    }
}

// ── Hardcoded MVP verification keys (32-byte placeholders) ──────────────────
//
// In production these would be loaded from contract storage / an admin call.
// For the MVP they are compile-time constants so the verifier is self-contained.

const VK_BALANCE:   [u8; 32] = [0x01u8; 32];
const VK_RESIDENCY: [u8; 32] = [0x02u8; 32];
const VK_AGE:       [u8; 32] = [0x03u8; 32];

// ── Error codes ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    InvalidProofData  = 1,
    UnknownProofType  = 2,
    VerificationFailed = 3,
}

impl soroban_sdk::TryFromVal<Env, soroban_sdk::Val> for VerifierError {
    type Error = soroban_sdk::ConversionError;
    fn try_from_val(env: &Env, v: &soroban_sdk::Val) -> Result<Self, Self::Error> {
        let n = u32::try_from_val(env, v)?;
        match n {
            1 => Ok(VerifierError::InvalidProofData),
            2 => Ok(VerifierError::UnknownProofType),
            3 => Ok(VerifierError::VerificationFailed),
            _ => Err(soroban_sdk::ConversionError),
        }
    }
}

impl soroban_sdk::IntoVal<Env, soroban_sdk::Val> for VerifierError {
    fn into_val(&self, env: &Env) -> soroban_sdk::Val {
        (*self as u32).into_val(env)
    }
}

// ── BN254 wrapper (Issue #2 interface) ──────────────────────────────────────
//
// The real wrapper lives in the `crypto` crate produced in Issue #2.
// We call it through a thin trait so tests can inject a mock.

pub trait Bn254Verifier {
    fn verify(
        &self,
        env: &Env,
        vk: &[u8; 32],
        proof_data: &Bytes,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool;
}

/// Production implementation — delegates to the BN254 host function exposed
/// by the Soroban runtime (or the `crypto` contract from Issue #2).
pub struct HostBn254;

impl Bn254Verifier for HostBn254 {
    fn verify(
        &self,
        env: &Env,
        vk: &[u8; 32],
        proof_data: &Bytes,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        // Minimum sanity check: a Groth16 proof for BN254 is 128 bytes.
        if proof_data.len() < 128 {
            return false;
        }

        // Build the vk BytesN<32> for the host call.
        let vk_bytes: BytesN<32> = BytesN::from_array(env, vk);

        // Concatenate all public inputs into a flat byte buffer so the
        // host crypto primitive can consume them.
        let mut inputs_flat = Bytes::new(env);
        for i in 0..public_inputs.len() {
            let input: BytesN<32> = public_inputs.get(i).unwrap();
            inputs_flat.append(&input.into());
        }

        // `env.crypto().bn254_g1_add` and friends are available from
        // soroban-sdk ≥ 21.  The actual groth16_verify call will be
        // `env.crypto().groth16_bn254_verify(vk_bytes, proof_data, inputs_flat)`
        // once that host function is stabilised.  For the MVP we call the
        // BN254 helper contract deployed in Issue #2; here we replicate what
        // that call would look like as a cross-contract invocation:
        //
        //   let result: bool = env.invoke_contract(
        //       &bn254_contract_id,
        //       &Symbol::new(env, "verify"),
        //       (vk_bytes, proof_data.clone(), inputs_flat).into_val(env),
        //   );
        //
        // Until that contract address is wired up via contract storage we
        // return a conservative `false` so callers know the full integration
        // is pending.  Unit tests use `MockBn254` instead (see test module).
        let _ = (vk_bytes, inputs_flat); // suppress unused-variable warnings
        false
    }
}

// ── Contract ────────────────────────────────────────────────────────────────

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    // ────────────────────────────────────────────────────────────────────────
    // verify_proof
    //
    // proof_type    – 0 = ProofOfBalance | 1 = ProofOfResidency | 2 = ProofOfAge
    // proof_data    – raw Groth16 proof bytes (≥ 128 bytes)
    // public_inputs – vector of 32-byte field elements
    //
    // Returns true iff the proof is valid; reverts with InvalidProofData if
    // the proof bytes cannot be parsed.
    // ────────────────────────────────────────────────────────────────────────
    pub fn verify_proof(
        env: Env,
        proof_type: u32,
        proof_data: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        Self::verify_proof_with(env, proof_type, proof_data, public_inputs, &HostBn254)
    }

    /// Internal helper that accepts an injected `Bn254Verifier` — used by
    /// unit tests to pass a mock without re-deploying the contract.
    pub fn verify_proof_with<V: Bn254Verifier>(
        env: Env,
        proof_type: u32,
        proof_data: Bytes,
        public_inputs: Vec<BytesN<32>>,
        bn254: &V,
    ) -> bool {
        // 1. Resolve proof type ────────────────────────────────────────────
        let pt = ProofType::from_u32(proof_type).unwrap_or_else(|| {
            panic_with_error!(&env, VerifierError::UnknownProofType)
        });

        // 2. Validate proof bytes (minimum length = 128) ───────────────────
        if proof_data.len() < 128 {
            panic_with_error!(&env, VerifierError::InvalidProofData);
        }

        // 3. Select verification key ───────────────────────────────────────
        let vk: &[u8; 32] = match pt {
            ProofType::ProofOfBalance   => &VK_BALANCE,
            ProofType::ProofOfResidency => &VK_RESIDENCY,
            ProofType::ProofOfAge       => &VK_AGE,
        };

        // 4. Call BN254 wrapper ────────────────────────────────────────────
        let result = bn254.verify(&env, vk, &proof_data, &public_inputs);

        // 5. Emit event ───────────────────────────────────────────────────
        let caller: Address = env.current_contract_address(); // real auth: env.invoker()
        let timestamp: u64 = env.ledger().timestamp();

        env.events().publish(
            (soroban_sdk::symbol_short!("ProofVfy"), proof_type),
            (caller, timestamp, result),
        );

        log!(&env, "verify_proof: type={} result={}", proof_type, result);

        result
    }
}
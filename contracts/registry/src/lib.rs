#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, BytesN, Env, Map};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Map<BytesN<32>, ProofRecord> — keyed by proof hash
    Records,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ProofRecord {
    /// 0 = ProofOfBalance | 1 = ProofOfResidency | 2 = ProofOfAge
    pub proof_type: u32,
    /// Ledger timestamp when the proof was stored
    pub timestamp: u64,
    /// Whether the proof was verified successfully
    pub verified: bool,
}

#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyRegistered = 1,
    NotFound = 2,
}

impl soroban_sdk::TryFromVal<Env, soroban_sdk::Val> for RegistryError {
    type Error = soroban_sdk::ConversionError;
    fn try_from_val(env: &Env, v: &soroban_sdk::Val) -> Result<Self, Self::Error> {
        let n = u32::try_from_val(env, v)?;
        match n {
            1 => Ok(RegistryError::AlreadyRegistered),
            2 => Ok(RegistryError::NotFound),
            _ => Err(soroban_sdk::ConversionError),
        }
    }
}

impl soroban_sdk::IntoVal<Env, soroban_sdk::Val> for RegistryError {
    fn into_val(&self, env: &Env) -> soroban_sdk::Val {
        (*self as u32).into_val(env)
    }
}

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    /// Store a proof record keyed by its hash.
    /// Reverts with AlreadyRegistered if the hash was already stored.
    pub fn store_proof(
        env: Env,
        proof_hash: BytesN<32>,
        proof_type: u32,
        verified: bool,
    ) {
        let mut records: Map<BytesN<32>, ProofRecord> = env
            .storage()
            .instance()
            .get(&DataKey::Records)
            .unwrap_or_else(|| Map::new(&env));

        if records.contains_key(proof_hash.clone()) {
            soroban_sdk::panic_with_error!(&env, RegistryError::AlreadyRegistered);
        }

        records.set(
            proof_hash,
            ProofRecord {
                proof_type,
                timestamp: env.ledger().timestamp(),
                verified,
            },
        );
        env.storage().instance().set(&DataKey::Records, &records);
    }

    /// Look up a stored proof record by its hash.
    pub fn get_proof(env: Env, proof_hash: BytesN<32>) -> ProofRecord {
        let records: Map<BytesN<32>, ProofRecord> = env
            .storage()
            .instance()
            .get(&DataKey::Records)
            .unwrap_or_else(|| Map::new(&env));

        records.get(proof_hash).unwrap_or_else(|| {
            soroban_sdk::panic_with_error!(&env, RegistryError::NotFound)
        })
    }

    /// Returns true if a proof hash has been registered.
    pub fn has_proof(env: Env, proof_hash: BytesN<32>) -> bool {
        let records: Map<BytesN<32>, ProofRecord> = env
            .storage()
            .instance()
            .get(&DataKey::Records)
            .unwrap_or_else(|| Map::new(&env));
        records.contains_key(proof_hash)
    }
}

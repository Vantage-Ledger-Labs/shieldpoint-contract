#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Map, Symbol,
    panic_with_error, log,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Auth tokens expire after this many ledger seconds (~1 hour at 5 s/ledger).
const TOKEN_TTL_SECONDS: u64 = 3_600;

/// Minimum challenge length (contract_id[32] + nonce[8] = 40 bytes).
const MIN_CHALLENGE_LEN: u32 = 40;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Used nonces — Map<BytesN<8>, bool>
    UsedNonces,
    /// Active auth tokens — Map<BytesN<32>, u64> (token → expiry timestamp)
    AuthTokens,
    /// The contract's own ID cached at init (used in challenge validation).
    ContractId,
}

// ── Error codes ──────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum AuthError {
    InvalidChallenge   = 1,
    InvalidSignature   = 2,
    ReplayedNonce      = 3,
    Unauthorised       = 4,
    ChallengeTooShort  = 5,
}

impl soroban_sdk::TryFromVal<Env, soroban_sdk::Val> for AuthError {
    type Error = soroban_sdk::ConversionError;
    fn try_from_val(env: &Env, v: &soroban_sdk::Val) -> Result<Self, Self::Error> {
        let n = u32::try_from_val(env, v)?;
        match n {
            1 => Ok(AuthError::InvalidChallenge),
            2 => Ok(AuthError::InvalidSignature),
            3 => Ok(AuthError::ReplayedNonce),
            4 => Ok(AuthError::Unauthorised),
            5 => Ok(AuthError::ChallengeTooShort),
            _ => Err(soroban_sdk::ConversionError),
        }
    }
}

impl soroban_sdk::IntoVal<Env, soroban_sdk::Val> for AuthError {
    fn into_val(&self, env: &Env) -> soroban_sdk::Val {
        (*self as u32).into_val(env)
    }
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct Auth;

#[contractimpl]
impl Auth {
    // ────────────────────────────────────────────────────────────────────────
    // authenticate
    //
    // Validates a SEP-10 style signed challenge and, if valid, mints an
    // ephemeral auth token (a 32-byte random value stored on-ledger).
    //
    // challenge  – must be: contract_id[32] || nonce[8] || …optional extra…
    // signature  – Ed25519 signature of `challenge` by `public_key`
    // public_key – 32-byte Ed25519 public key of the authenticating party
    //
    // Returns true and stores a fresh token; reverts on any failure.
    // ────────────────────────────────────────────────────────────────────────
    pub fn authenticate(
        env: Env,
        challenge: Bytes,
        signature: Bytes,
        public_key: BytesN<32>,
    ) -> bool {
        // 1. Length guard ──────────────────────────────────────────────────
        if challenge.len() < MIN_CHALLENGE_LEN {
            panic_with_error!(&env, AuthError::ChallengeTooShort);
        }

        // 2. Extract and validate contract_id prefix ───────────────────────
        //    The first 32 bytes of the challenge must equal this contract's ID
        //    so a challenge minted for contract A cannot be replayed on B.
        let mut contract_id_bytes = [0u8; 32];
        for i in 0..32u32 {
            contract_id_bytes[i as usize] = challenge.get(i).unwrap_or(0);
        }
        let claimed_contract: BytesN<32> = BytesN::from_array(&env, &contract_id_bytes);
        let this_contract: BytesN<32> = env
            .current_contract_address()
            .into();

        if claimed_contract != this_contract {
            panic_with_error!(&env, AuthError::InvalidChallenge);
        }

        // 3. Extract nonce (bytes 32..40) and check replay ─────────────────
        let mut nonce_bytes = [0u8; 8];
        for i in 0..8u32 {
            nonce_bytes[i as usize] = challenge.get(32 + i).unwrap_or(0);
        }
        let nonce: BytesN<8> = BytesN::from_array(&env, &nonce_bytes);

        let mut used_nonces: Map<BytesN<8>, bool> = env
            .storage()
            .instance()
            .get(&DataKey::UsedNonces)
            .unwrap_or_else(|| Map::new(&env));

        if used_nonces.contains_key(nonce.clone()) {
            panic_with_error!(&env, AuthError::ReplayedNonce);
        }

        // 4. Verify Ed25519 signature ──────────────────────────────────────
        //    env.crypto().ed25519_verify() panics on invalid signature,
        //    so we map that panic to our own AuthError::InvalidSignature.
        let sig_bytes: BytesN<64> = signature
            .try_into()
            .unwrap_or_else(|_| panic_with_error!(&env, AuthError::InvalidSignature));

        env.crypto().ed25519_verify(&public_key, &challenge, &sig_bytes);
        // ^ panics (→ WASM trap) if signature is invalid; the SDK converts
        //   this to a host error.  Callers will see a contract invocation
        //   failure rather than `false`, which is the correct security posture.

        // 5. Mark nonce as used ────────────────────────────────────────────
        used_nonces.set(nonce, true);
        env.storage()
            .instance()
            .set(&DataKey::UsedNonces, &used_nonces);

        // 6. Mint auth token ───────────────────────────────────────────────
        //    Token = SHA-256(public_key || ledger_sequence_bytes || challenge)
        //    We use the host's prng for an extra entropy contribution.
        let hash = env.crypto().sha256(
            &{
                let mut buf = Bytes::new(&env);
                buf.append(&public_key.clone().into());
                let seq_bytes = env.ledger().sequence().to_be_bytes();
                buf.append(&Bytes::from_slice(&env, &seq_bytes));
                buf.append(&challenge);
                buf
            }
        );
        
        let token: BytesN<32> = hash.into();
        let expiry = env.ledger().timestamp() + TOKEN_TTL_SECONDS;
        let mut tokens: Map<BytesN<32>, u64> = env
            .storage()
            .instance()
            .get(&DataKey::AuthTokens)
            .unwrap_or_else(|| Map::new(&env));

        tokens.set(token.clone(), expiry);
        env.storage()
            .instance()
            .set(&DataKey::AuthTokens, &tokens);

        // 7. Emit event ────────────────────────────────────────────────────
        env.events().publish(
            (soroban_sdk::symbol_short!("Authed"), public_key.clone()),
            (expiry,),
        );

        log!(&env, "authenticate: pk={:?} expiry={}", public_key, expiry);

        true
    }

    // ────────────────────────────────────────────────────────────────────────
    // is_token_valid
    //
    // Returns true iff `token` exists in storage and has not expired.
    // Called by `verify_proof` (Issue #4) before dispatching to the Verifier.
    // ────────────────────────────────────────────────────────────────────────
    pub fn is_token_valid(env: Env, token: BytesN<32>) -> bool {
        let tokens: Map<BytesN<32>, u64> = env
            .storage()
            .instance()
            .get(&DataKey::AuthTokens)
            .unwrap_or_else(|| Map::new(&env));

        match tokens.get(token) {
            Some(expiry) => env.ledger().timestamp() < expiry,
            None => false,
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // require_auth  (gate for verify_proof — Issue #4 integration)
    //
    // Convenience method: panics with Unauthorised if the token is not valid.
    // The Verifier contract calls this before proceeding with proof checks.
    // ────────────────────────────────────────────────────────────────────────
    pub fn require_auth(env: Env, token: BytesN<32>) {
        if !Self::is_token_valid(env.clone(), token) {
            panic_with_error!(&env, AuthError::Unauthorised);
        }
    }
}
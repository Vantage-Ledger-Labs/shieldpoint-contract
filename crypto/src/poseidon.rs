#![no_std]

use soroban_sdk::{log, Bytes, BytesN, Env, Vec};

const MAX_POSEIDON_INPUTS: usize = 8;
const POSEIDON_SALT: [u8; 16] = *b"poseidon-hash-v1";

/// Computes a hash for up to 8 inputs using Soroban crypto primitives.
///
/// If a native Poseidon primitive is available in the host, it will be used.
/// Otherwise the function falls back to SHA-256 and logs a warning.
pub fn poseidon_hash(inputs: Vec<[u8; 32]>) -> [u8; 32] {
    let env = Env::default();
    poseidon_hash_with_env(&env, inputs)
}

/// Internal helper that takes an explicit environment reference.
pub fn poseidon_hash_with_env(env: &Env, inputs: Vec<[u8; 32]>) -> [u8; 32] {
    if inputs.len() > MAX_POSEIDON_INPUTS {
        panic!("poseidon_hash supports up to {MAX_POSEIDON_INPUTS} inputs");
    }

    try_native_poseidon_hash(env, &inputs).unwrap_or_else(|| {
        log!(&env, "Poseidon native hash unavailable, falling back to SHA256");
        sha256_fallback(env, &inputs)
    })
}

fn try_native_poseidon_hash(_env: &Env, _inputs: &Vec<[u8; 32]>) -> Option<[u8; 32]> {
    // No native Poseidon client is available on this SDK version.
    // Future Soroban SDK versions may expose a native Poseidon primitive.
    None
}

fn sha256_fallback(env: &Env, inputs: &Vec<[u8; 32]>) -> [u8; 32] {
    let mut data = Bytes::from_array(env, &POSEIDON_SALT);
    data.extend_from_array(&[inputs.len() as u8]);
    for input in inputs.iter() {
        data.extend_from_array(input);
    }
    let digest: BytesN<32> = env.crypto().sha256(&data);
    digest.to_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn sample_input(first: u8, second: u8) -> Vec<[u8; 32]> {
        let a = [first; 32];
        let b = [second; 32];
        Vec::from_array(&Env::default(), [a, b])
    }

    #[test]
    fn deterministic_output_is_stable() {
        let env = Env::default();
        let inputs = sample_input(1, 2);
        let first_hash = poseidon_hash_with_env(&env, inputs.clone());
        let second_hash = poseidon_hash_with_env(&env, inputs);
        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let env = Env::default();
        let a = poseidon_hash_with_env(&env, sample_input(1, 2));
        let b = poseidon_hash_with_env(&env, sample_input(1, 3));
        assert_ne!(a, b);
    }

    #[test]
    fn supports_up_to_eight_inputs() {
        let env = Env::default();
        let inputs = Vec::from_array(
            &env,
            [
                [0u8; 32],
                [1u8; 32],
                [2u8; 32],
                [3u8; 32],
                [4u8; 32],
                [5u8; 32],
                [6u8; 32],
                [7u8; 32],
            ],
        );
        let digest = poseidon_hash_with_env(&env, inputs);
        assert_ne!(digest, [0u8; 32]);
    }
}

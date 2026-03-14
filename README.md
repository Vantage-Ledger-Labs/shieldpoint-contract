# 🛡️ ShieldPoint: Soroban Smart Contracts

This repository contains the on-chain logic for **ShieldPoint**, the privacy middleware for the Stellar Network. It leverages **Protocol 25 (X-Ray)** host functions to verify Zero-Knowledge Proofs (ZKP) natively.

## 🚀 Technical Highlights
- **ZK-Verification:** Uses `env.crypto().bn254_multi_pairing_check()` for efficient proof validation.
- **Poseidon Hashing:** Implements gas-optimized hashing for on-chain state commitments.
- **Modular Proofs:** Supports multiple circuit types (Proof of Balance, Proof of Residency, Proof of Age).

## 🛠 Installation & Testing
1. Install [Stellar CLI](https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup).
2. Clone the repo: `git clone https://github.com/aura-protocol/shieldpoint-contract`
3. Build: `stellar contract build`
4. Test: `cargo test`

## Milestones
- [ ] Implement BN254 Pairing Wrapper.
- [ ] Deploy Verifier Contract to Testnet.
- [ ] Integrate with SEP-10 Auth.

//! ZK verification module using Solana-native Groth16 verifier
//! This module provides clean, simple ZK proof verification using groth16-solana

pub mod solana_verifier;
pub mod types;

// Re-export parsing functions
pub use solana_verifier::{
    parse_proof_bytes,
    parse_public_signals_exact,
    extract_public_input,
    verify_deposit,
    verify_transfer,
    verify_withdraw,
    verify_deposit_payload,
    verify_transfer_payload,
    verify_withdraw_payload,
};

// Re-export constants
pub use solana_verifier::{
    BYTES_G1,
    BYTES_G2,
    BYTES_PROOF,
    BYTES_F,
    MAX_IC,
    DEPOSIT_N_PUBLIC,
    TRANSFER_N_PUBLIC,
    WITHDRAW_N_PUBLIC,
};

// Re-export types
pub use types::{ZkProof, ZkPublicInputs};



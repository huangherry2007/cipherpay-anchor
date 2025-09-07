// types.rs - Central location for ZK proof type definitions
// This module defines types for Solana-native ZK verification

// Use Vec<u8> for Anchor compatibility with the Solana-native verifier
pub type ZkProof = Vec<u8>;
pub type ZkPublicInputs = Vec<u8>;

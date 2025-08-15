// types.rs - Central location for all ZK proof type definitions
// This module defines types only once to avoid IDL duplication

// Always use Vec<u8> for Anchor compatibility
// The complex ZK types are completely hidden from Anchor's IDL generator
pub type DepositGroth16Proof = Vec<u8>;
pub type TransferGroth16Proof = Vec<u8>;
pub type WithdrawGroth16Proof = Vec<u8>;

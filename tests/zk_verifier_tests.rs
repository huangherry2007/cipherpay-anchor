//! Tests for ZK verifier functions and proof parsing

#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(dead_code)]

use cipherpay_anchor::{
    zk_verifier::solana_verifier::*,
    error::CipherPayError,
    constants::*,
};

#[test]
fn test_parse_proof_bytes_valid() {
    // Create a valid proof byte array (256 bytes)
    let mut proof_bytes = vec![0u8; BYTES_PROOF];
    
    // Set some test values
    proof_bytes[0] = 1; // A[0]
    proof_bytes[64] = 2; // B[0]
    proof_bytes[192] = 3; // C[0]
    
    let result = parse_proof_bytes(&proof_bytes);
    assert!(result.is_ok());
    
    let (a, b, c) = result.unwrap();
    assert_eq!(a.len(), BYTES_G1);
    assert_eq!(b.len(), BYTES_G2);
    assert_eq!(c.len(), BYTES_G1);
    assert_eq!(a[0], 1);
    assert_eq!(b[0], 2);
    assert_eq!(c[0], 3);
}

#[test]
fn test_parse_proof_bytes_invalid_length() {
    // Test with wrong length
    let short_bytes = vec![0u8; 255];
    let result = parse_proof_bytes(&short_bytes);
    assert!(result.is_err());
    
    let long_bytes = vec![0u8; 257];
    let result = parse_proof_bytes(&long_bytes);
    assert!(result.is_err());
}

#[test]
fn test_parse_public_signals_exact_valid() {
    // Create valid public signals (multiple of 32 bytes)
    let mut signals = vec![0u8; 3 * BYTES_F];
    signals[0] = 1;
    signals[32] = 2;
    signals[64] = 3;
    
    let result = parse_public_signals_exact(&signals);
    assert!(result.is_ok());
    
    let parsed = result.unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0][0], 1);
    assert_eq!(parsed[1][0], 2);
    assert_eq!(parsed[2][0], 3);
}

#[test]
fn test_parse_public_signals_exact_invalid_length() {
    // Test with length not multiple of 32
    let invalid_signals = vec![0u8; 31];
    let result = parse_public_signals_exact(&invalid_signals);
    assert!(result.is_err());
    
    let invalid_signals2 = vec![0u8; 33];
    let result = parse_public_signals_exact(&invalid_signals2);
    assert!(result.is_err());
}

#[test]
fn test_parse_public_inputs_valid() {
    let signals = vec![0u8; 6 * BYTES_F]; // 6 public inputs for deposit
    let result = parse_public_inputs(&signals, 6);
    assert!(result.is_ok());
    
    let parsed = result.unwrap();
    assert_eq!(parsed.len(), 6);
}

#[test]
fn test_parse_public_inputs_invalid_count() {
    let signals = vec![0u8; 5 * BYTES_F]; // 5 inputs but expecting 6
    let result = parse_public_inputs(&signals, 6);
    assert!(result.is_err());
}

#[test]
fn test_extract_public_input_valid() {
    let inputs = vec![
        [1u8; BYTES_F],
        [2u8; BYTES_F],
        [3u8; BYTES_F],
    ];
    
    let result = extract_public_input(&inputs, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), [1u8; BYTES_F]);
    
    let result = extract_public_input(&inputs, 2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), [3u8; BYTES_F]);
}

#[test]
fn test_extract_public_input_invalid_index() {
    let inputs = vec![
        [1u8; BYTES_F],
        [2u8; BYTES_F],
    ];
    
    let result = extract_public_input(&inputs, 2);
    assert!(result.is_err());
    
    let result = extract_public_input(&inputs, 10);
    assert!(result.is_err());
}

#[test]
fn test_extract_amount_u64() {
    let mut inputs = vec![[0u8; BYTES_F]];
    
    // Test little-endian conversion
    inputs[0][0] = 100;
    inputs[0][1] = 1;
    inputs[0][2] = 2;
    
    let result = extract_amount_u64(&inputs, 0);
    assert!(result.is_ok());
    let expected = 100u64 + (1u64 << 8) + (2u64 << 16);
    assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_extract_amount_u64_zero() {
    let inputs = vec![[0u8; BYTES_F]];
    
    let result = extract_amount_u64(&inputs, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_extract_amount_u64_max() {
    let mut inputs = vec![[0u8; BYTES_F]];
    
    // Set all 8 bytes to 255
    for i in 0..8 {
        inputs[0][i] = 255;
    }
    
    let result = extract_amount_u64(&inputs, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), u64::MAX);
}

#[test]
fn test_verify_groth16_payload_valid_length() {
    // Create a payload with correct length for deposit (6 public inputs)
    let payload = vec![0u8; BYTES_PROOF + DEPOSIT_N_PUBLIC * BYTES_F];
    
    // This should not fail on length check (though it will fail on verification)
    let result = verify_groth16_payload::<{ DEPOSIT_N_PUBLIC }>(&payload, &[]);
    // We expect this to fail on verification, not length
    assert!(result.is_err());
}

#[test]
fn test_verify_groth16_payload_invalid_length() {
    // Test with wrong payload length
    let short_payload = vec![0u8; BYTES_PROOF + DEPOSIT_N_PUBLIC * BYTES_F - 1];
    let result = verify_groth16_payload::<{ DEPOSIT_N_PUBLIC }>(&short_payload, &[]);
    assert!(result.is_err());
    
    let long_payload = vec![0u8; BYTES_PROOF + DEPOSIT_N_PUBLIC * BYTES_F + 1];
    let result = verify_groth16_payload::<{ DEPOSIT_N_PUBLIC }>(&long_payload, &[]);
    assert!(result.is_err());
}

#[test]
fn test_verify_deposit_invalid_length() {
    // Test with wrong public signals length
    let proof_bytes = vec![0u8; BYTES_PROOF];
    let short_signals = vec![0u8; (DEPOSIT_N_PUBLIC - 1) * BYTES_F];
    
    let result = verify_deposit(&proof_bytes, &short_signals);
    assert!(result.is_err());
    
    let long_signals = vec![0u8; (DEPOSIT_N_PUBLIC + 1) * BYTES_F];
    let result = verify_deposit(&proof_bytes, &long_signals);
    assert!(result.is_err());
}

#[test]
fn test_verify_transfer_invalid_length() {
    let proof_bytes = vec![0u8; BYTES_PROOF];
    let short_signals = vec![0u8; (TRANSFER_N_PUBLIC - 1) * BYTES_F];
    
    let result = verify_transfer(&proof_bytes, &short_signals);
    assert!(result.is_err());
}

#[test]
fn test_verify_withdraw_invalid_length() {
    let proof_bytes = vec![0u8; BYTES_PROOF];
    let short_signals = vec![0u8; (WITHDRAW_N_PUBLIC - 1) * BYTES_F];
    
    let result = verify_withdraw(&proof_bytes, &short_signals);
    assert!(result.is_err());
}

#[test]
fn test_public_signal_counts() {
    // Test that our public signal counts match expectations
    assert_eq!(DEPOSIT_N_PUBLIC, 6);
    assert_eq!(TRANSFER_N_PUBLIC, 9);
    assert_eq!(WITHDRAW_N_PUBLIC, 5);
}

#[test]
fn test_deposit_idx_constants() {
    // Test deposit index constants
    assert_eq!(deposit_idx::NEW_COMMITMENT, 0);
    assert_eq!(deposit_idx::OWNER_CIPHERPAY_PUBKEY, 1);
    assert_eq!(deposit_idx::NEW_MERKLE_ROOT, 2);
    assert_eq!(deposit_idx::NEW_NEXT_LEAF_INDEX, 3);
    assert_eq!(deposit_idx::AMOUNT, 4);
    assert_eq!(deposit_idx::DEPOSIT_HASH, 5);
}

#[test]
fn test_transfer_idx_constants() {
    // Test transfer index constants
    assert_eq!(transfer_idx::OUT_COMMITMENT1, 0);
    assert_eq!(transfer_idx::OUT_COMMITMENT2, 1);
    assert_eq!(transfer_idx::NULLIFIER, 2);
    assert_eq!(transfer_idx::MERKLE_ROOT, 3);
    assert_eq!(transfer_idx::NEW_MERKLE_ROOT1, 4);
    assert_eq!(transfer_idx::NEW_MERKLE_ROOT2, 5);
    assert_eq!(transfer_idx::NEW_NEXT_LEAF_IDX, 6);
    assert_eq!(transfer_idx::ENC_NOTE1_HASH, 7);
    assert_eq!(transfer_idx::ENC_NOTE2_HASH, 8);
}

#[test]
fn test_withdraw_idx_constants() {
    // Test withdraw index constants
    assert_eq!(withdraw_idx::NULLIFIER, 0);
    assert_eq!(withdraw_idx::MERKLE_ROOT, 1);
    assert_eq!(withdraw_idx::RECIPIENT_WALLET_PUBKEY, 2);
    assert_eq!(withdraw_idx::AMOUNT, 3);
    assert_eq!(withdraw_idx::TOKEN_ID, 4);
}

#[test]
fn test_byte_constants() {
    // Test byte size constants
    assert_eq!(BYTES_F, 32);
    assert_eq!(BYTES_G1, 64);
    assert_eq!(BYTES_G2, 128);
    assert_eq!(BYTES_PROOF, 256);
}

#[test]
fn test_parse_verifying_key_invalid_length() {
    // Test with too short VK
    let short_vk = vec![0u8; 100];
    let result = parse_verifying_key(&short_vk);
    assert!(result.is_err());
    
    // Test with length not multiple of G1
    let invalid_vk = vec![0u8; 449]; // 448 + 1
    let result = parse_verifying_key(&invalid_vk);
    assert!(result.is_err());
}

#[test]
fn test_parse_verifying_key_zero_ic() {
    // Test with zero IC count (should fail)
    let mut vk = vec![0u8; 448]; // Fixed parts only, no IC
    let result = parse_verifying_key(&vk);
    assert!(result.is_err());
}

#[test]
fn test_parse_verifying_key_too_many_ic() {
    // Test with too many IC entries
    let mut vk = vec![0u8; 448 + (MAX_IC + 1) * BYTES_G1];
    let result = parse_verifying_key(&vk);
    assert!(result.is_err());
}

#[test]
fn test_verify_groth16_proof_invalid_vk() {
    // Test with invalid VK
    let proof_a = [0u8; BYTES_G1];
    let proof_b = [0u8; BYTES_G2];
    let proof_c = [0u8; BYTES_G1];
    let public_inputs = [[0u8; BYTES_F]; 1];
    let invalid_vk = vec![0u8; 100];
    
    let result = verify_groth16_proof::<1>(&proof_a, &proof_b, &proof_c, &public_inputs, &invalid_vk);
    assert!(result.is_err());
}

#[test]
fn test_verify_deposit_payload_wrapper() {
    // Test the wrapper function
    let payload = vec![0u8; BYTES_PROOF + DEPOSIT_N_PUBLIC * BYTES_F];
    let result = verify_deposit_payload(&payload);
    // Should fail on verification but not on length
    assert!(result.is_err());
}

#[test]
fn test_verify_transfer_payload_wrapper() {
    let payload = vec![0u8; BYTES_PROOF + TRANSFER_N_PUBLIC * BYTES_F];
    let result = verify_transfer_payload(&payload);
    assert!(result.is_err());
}

#[test]
fn test_verify_withdraw_payload_wrapper() {
    let payload = vec![0u8; BYTES_PROOF + WITHDRAW_N_PUBLIC * BYTES_F];
    let result = verify_withdraw_payload(&payload);
    assert!(result.is_err());
}

#[test]
fn test_public_signals_parsing_edge_cases() {
    // Test empty input
    let empty = vec![];
    let result = parse_public_signals_exact(&empty);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
    
    // Test single field element
    let single = vec![0u8; BYTES_F];
    let result = parse_public_signals_exact(&single);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn test_proof_parsing_edge_cases() {
    // Test with all zeros
    let zero_proof = vec![0u8; BYTES_PROOF];
    let result = parse_proof_bytes(&zero_proof);
    assert!(result.is_ok());
    
    let (a, b, c) = result.unwrap();
    assert_eq!(a, [0u8; BYTES_G1]);
    assert_eq!(b, [0u8; BYTES_G2]);
    assert_eq!(c, [0u8; BYTES_G1]);
}

#[test]
fn test_amount_extraction_edge_cases() {
    let mut inputs = vec![[0u8; BYTES_F]];
    
    // Test with only first byte set
    inputs[0][0] = 42;
    let result = extract_amount_u64(&inputs, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
    
    // Test with only last byte of first 8 bytes set
    inputs[0] = [0u8; BYTES_F];
    inputs[0][7] = 1;
    let result = extract_amount_u64(&inputs, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1 << 56);
}

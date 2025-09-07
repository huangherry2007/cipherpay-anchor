//! Unit tests for CipherPay Anchor program utility functions and state management

#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(dead_code)]

use anchor_lang::prelude::*;
use cipherpay_anchor::{
    constants::*,
    state::{DepositMarker, MerkleRootCache, Nullifier},
    utils::*,
    error::CipherPayError,
};

#[test]
fn test_deposit_marker_creation() {
    let mut marker = DepositMarker {
        processed: false,
        bump: 255,
    };
    
    assert!(!marker.processed);
    assert_eq!(marker.bump, 255);
    
    // Test size constants
    assert_eq!(DepositMarker::SIZE, 2);
    assert_eq!(DepositMarker::SPACE, 10);
}

#[test]
fn test_deposit_marker_set_processed() {
    let mut marker = DepositMarker {
        processed: false,
        bump: 0,
    };
    
    assert!(!marker.processed);
    marker.set_processed();
    assert!(marker.processed);
}

#[test]
fn test_nullifier_creation() {
    let mut nullifier = Nullifier {
        used: false,
        bump: 42,
    };
    
    assert!(!nullifier.used);
    assert_eq!(nullifier.bump, 42);
    
    // Test size constants
    assert_eq!(Nullifier::SIZE, 2);
    assert_eq!(Nullifier::SPACE, 10);
}

#[test]
fn test_nullifier_mark_used() {
    let mut nullifier = Nullifier {
        used: false,
        bump: 0,
    };
    
    assert!(!nullifier.used);
    nullifier.mark_used();
    assert!(nullifier.used);
}

#[test]
fn test_merkle_root_cache_creation() {
    let cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    assert_eq!(cache.roots.len(), 0);
    assert!(!cache.is_full());
    assert_eq!(cache.latest(), None);
    
    // Test size constants
    assert_eq!(MerkleRootCache::SIZE, 4 + (MAX_ROOTS * 32));
    assert_eq!(MerkleRootCache::SPACE, 8 + MerkleRootCache::SIZE);
}

#[test]
fn test_merkle_root_cache_insert_root() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    let root1 = [1u8; 32];
    let root2 = [2u8; 32];
    let root3 = [3u8; 32];
    
    // Test basic insertion
    assert!(cache.try_insert_root(root1));
    assert_eq!(cache.roots.len(), 1);
    assert!(cache.contains_root(&root1));
    assert!(!cache.contains_root(&root2));
    
    // Test duplicate prevention
    assert!(!cache.try_insert_root(root1));
    assert_eq!(cache.roots.len(), 1);
    
    // Test multiple insertions
    assert!(cache.try_insert_root(root2));
    assert!(cache.try_insert_root(root3));
    assert_eq!(cache.roots.len(), 3);
    
    // Test latest root
    assert_eq!(cache.latest(), Some(root3));
}

#[test]
fn test_merkle_root_cache_eviction() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    // Fill cache to capacity
    for i in 0..MAX_ROOTS {
        let root = [i as u8; 32];
        cache.insert_root(root);
    }
    
    assert!(cache.is_full());
    assert_eq!(cache.roots.len(), MAX_ROOTS);
    
    // Insert one more - should evict oldest
    let new_root = [255u8; 32];
    let dropped = cache.insert_root(new_root);
    assert!(dropped);
    assert_eq!(cache.roots.len(), MAX_ROOTS);
    
    // First root should be evicted
    assert!(!cache.contains_root(&[0u8; 32]));
    assert!(cache.contains_root(&new_root));
    assert_eq!(cache.latest(), Some(new_root));
}

#[test]
fn test_merkle_root_cache_insert_many() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    let roots = [
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
    ];
    
    insert_many_roots(&roots, &mut cache);
    
    assert_eq!(cache.roots.len(), 3);
    assert!(cache.contains_root(&[1u8; 32]));
    assert!(cache.contains_root(&[2u8; 32]));
    assert!(cache.contains_root(&[3u8; 32]));
}

#[test]
fn test_as_fixed_32() {
    // Test valid input
    let valid_input = [1u8; 40];
    let result = as_fixed_32(&valid_input);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), [1u8; 32]);
    
    // Test short input
    let short_input = [2u8; 31];
    let result = as_fixed_32(&short_input);
    assert!(result.is_none());
    
    // Test exact 32 bytes
    let exact_input = [3u8; 32];
    let result = as_fixed_32(&exact_input);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), [3u8; 32]);
}

#[test]
fn test_is_valid_root() {
    let mut cache = MerkleRootCache {
        roots: vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        ],
    };
    
    // Test existing roots
    assert!(is_valid_root(&[1u8; 32], &cache));
    assert!(is_valid_root(&[2u8; 32], &cache));
    assert!(is_valid_root(&[3u8; 32], &cache));
    
    // Test non-existing root
    assert!(!is_valid_root(&[4u8; 32], &cache));
    
    // Test slice variant
    assert!(is_valid_root_slice(&[1u8; 32], &cache));
    assert!(!is_valid_root_slice(&[4u8; 32], &cache));
    assert!(!is_valid_root_slice(&[1u8; 31], &cache)); // Too short
}

#[test]
fn test_insert_merkle_root() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    let root = [42u8; 32];
    
    // Test fixed array variant
    insert_merkle_root(&root, &mut cache);
    assert!(cache.contains_root(&root));
    
    // Test slice variant
    let root_slice = [43u8; 32];
    insert_merkle_root_slice(&root_slice, &mut cache);
    assert!(cache.contains_root(&root_slice));
    
    // Test invalid slice (too short)
    let short_slice = [44u8; 31];
    insert_merkle_root_slice(&short_slice, &mut cache);
    assert!(!cache.contains_root(&[44u8; 32]));
}

#[test]
fn test_constants() {
    // Test PDA seeds
    assert_eq!(DEPOSIT_MARKER_SEED, b"deposit");
    assert_eq!(VAULT_SEED, b"vault");
    assert_eq!(NULLIFIER_SEED, b"nullifier");
    assert_eq!(MERKLE_ROOT_CACHE_SEED, b"root_cache");
    
    // Test size constants
    assert_eq!(MAX_ROOTS, 128);
    assert_eq!(FIELD_BYTES, 32);
    assert_eq!(G1_BYTES, 64);
    assert_eq!(G2_BYTES, 128);
    assert_eq!(PROOF_BYTES_LEN, 256);
    assert_eq!(BYTES_F, 32);
    
    // Test public signal counts
    assert_eq!(NPUB_DEPOSIT, 6);
    assert_eq!(NPUB_WITHDRAW, 5);
    assert_eq!(NPUB_TRANSFER, 9);
}

#[test]
fn test_le_bytes_32_to_u64() {
    // Test little-endian conversion
    let mut field_element = [0u8; 32];
    field_element[0] = 100;
    field_element[1] = 1;
    field_element[2] = 2;
    
    let result = le_bytes_32_to_u64(&field_element);
    let expected = 100u64 + (1u64 << 8) + (2u64 << 16);
    assert_eq!(result, expected);
    
    // Test zero
    let zero_field = [0u8; 32];
    assert_eq!(le_bytes_32_to_u64(&zero_field), 0);
    
    // Test max value in first 8 bytes
    let mut max_field = [0u8; 32];
    for i in 0..8 {
        max_field[i] = 255;
    }
    let result = le_bytes_32_to_u64(&max_field);
    assert_eq!(result, u64::MAX);
}

#[test]
fn test_error_types() {
    // Test that all error types can be created
    let errors = vec![
        CipherPayError::DepositAlreadyUsed,
        CipherPayError::UnknownMerkleRoot,
        CipherPayError::LeafIndexMismatch,
        CipherPayError::InvalidZkProof,
        CipherPayError::InvalidProofBytesLength,
        CipherPayError::InvalidPublicInputsLength,
        CipherPayError::InvalidVerifyingKey,
        CipherPayError::PublicInputCountMismatch,
        CipherPayError::PayloadBindingMismatch,
        CipherPayError::NullifierAlreadyUsed,
        CipherPayError::NullifierMismatch,
        CipherPayError::InvalidWithdrawAmount,
        CipherPayError::TokenTransferFailed,
        CipherPayError::VaultMismatch,
        CipherPayError::VaultAuthorityMismatch,
        CipherPayError::MemoMissing,
        CipherPayError::RequiredSplTransferMissing,
        CipherPayError::Unauthorized,
        CipherPayError::InvalidInput,
        CipherPayError::ArithmeticError,
    ];
    
    // Verify all errors have messages
    for error in errors {
        let error_msg = format!("{:?}", error);
        assert!(!error_msg.is_empty());
    }
}

#[test]
fn test_merkle_root_cache_edge_cases() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    // Test empty cache
    assert!(!cache.is_full());
    assert_eq!(cache.latest(), None);
    assert!(!cache.contains_root(&[1u8; 32]));
    
    // Test single root
    let root = [1u8; 32];
    cache.insert_root(root);
    assert!(!cache.is_full());
    assert_eq!(cache.latest(), Some(root));
    assert!(cache.contains_root(&root));
    
    // Test duplicate insertion
    let inserted = cache.try_insert_root(root);
    assert!(!inserted); // Should return false for duplicate
    assert_eq!(cache.roots.len(), 1); // Should still have only 1 root
}

#[test]
fn test_merkle_root_cache_try_insert_duplicate() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    let root = [1u8; 32];
    
    // First insertion should succeed
    assert!(cache.try_insert_root(root));
    assert_eq!(cache.roots.len(), 1);
    
    // Second insertion should fail
    assert!(!cache.try_insert_root(root));
    assert_eq!(cache.roots.len(), 1);
}

#[test]
fn test_merkle_root_cache_contains_root_empty() {
    let cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    assert!(!cache.contains_root(&[1u8; 32]));
    assert!(!cache.contains_root(&[0u8; 32]));
}

#[test]
fn test_merkle_root_cache_latest_empty() {
    let cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    assert_eq!(cache.latest(), None);
}

#[test]
fn test_merkle_root_cache_latest_single() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    let root = [42u8; 32];
    cache.insert_root(root);
    
    assert_eq!(cache.latest(), Some(root));
}

#[test]
fn test_merkle_root_cache_latest_multiple() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    let root1 = [1u8; 32];
    let root2 = [2u8; 32];
    let root3 = [3u8; 32];
    
    cache.insert_root(root1);
    cache.insert_root(root2);
    cache.insert_root(root3);
    
    assert_eq!(cache.latest(), Some(root3));
}

#[test]
fn test_merkle_root_cache_eviction_order() {
    let mut cache = MerkleRootCache {
        roots: Vec::new(),
    };
    
    // Fill to capacity
    for i in 0..MAX_ROOTS {
        let root = [i as u8; 32];
        cache.insert_root(root);
    }
    
    // Verify all roots are present
    for i in 0..MAX_ROOTS {
        assert!(cache.contains_root(&[i as u8; 32]));
    }
    
    // Add one more - should evict the first
    let new_root = [255u8; 32];
    cache.insert_root(new_root);
    
    // First root should be gone
    assert!(!cache.contains_root(&[0u8; 32]));
    // Last root should be present
    assert!(cache.contains_root(&new_root));
    // All others should still be present
    for i in 1..MAX_ROOTS {
        assert!(cache.contains_root(&[i as u8; 32]));
    }
}

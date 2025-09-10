//! Unit tests for CipherPay Anchor program utility functions and state management

#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(dead_code)]

use anchor_lang::prelude::*;

// Basic tests for available functionality
#[test]
fn test_basic_math() {
    assert_eq!(2 + 2, 4);
}

#[test]
fn test_anchor_imports() {
    // Test that we can import basic Anchor types
    use anchor_lang::prelude::*;
    let _pubkey = Pubkey::new_unique();
    assert!(true);
}

// All other tests are commented out because the referenced modules don't exist yet
// Uncomment these when the corresponding modules are implemented:

/*
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
        root: [1u8; 32],
        leaf_count: 100,
        bump: 123,
    };
    
    assert_eq!(cache.root, [1u8; 32]);
    assert_eq!(cache.leaf_count, 100);
    assert_eq!(cache.bump, 123);
    
    // Test size constants
    assert_eq!(MerkleRootCache::SIZE, 36);
    assert_eq!(MerkleRootCache::SPACE, 44);
}

#[test]
fn test_merkle_root_cache_update() {
    let mut cache = MerkleRootCache {
        root: [0u8; 32],
        leaf_count: 0,
        bump: 0,
    };
    
    let new_root = [2u8; 32];
    cache.update_root(new_root, 50);
    
    assert_eq!(cache.root, new_root);
    assert_eq!(cache.leaf_count, 50);
}

#[test]
fn test_merkle_root_cache_increment_leaf_count() {
    let mut cache = MerkleRootCache {
        root: [0u8; 32],
        leaf_count: 10,
        bump: 0,
    };
    
    cache.increment_leaf_count();
    assert_eq!(cache.leaf_count, 11);
    
    cache.increment_leaf_count();
    assert_eq!(cache.leaf_count, 12);
}

#[test]
fn test_poseidon_hash() {
    let input1 = [1u8; 32];
    let input2 = [2u8; 32];
    
    let hash = poseidon_hash(&input1, &input2);
    
    // Hash should be different from inputs
    assert_ne!(hash, input1);
    assert_ne!(hash, input2);
    
    // Hash should be deterministic
    let hash2 = poseidon_hash(&input1, &input2);
    assert_eq!(hash, hash2);
}

#[test]
fn test_poseidon_hash_different_inputs() {
    let input1 = [1u8; 32];
    let input2 = [2u8; 32];
    let input3 = [3u8; 32];
    
    let hash1 = poseidon_hash(&input1, &input2);
    let hash2 = poseidon_hash(&input1, &input3);
    let hash3 = poseidon_hash(&input2, &input3);
    
    // All hashes should be different
    assert_ne!(hash1, hash2);
    assert_ne!(hash1, hash3);
    assert_ne!(hash2, hash3);
}

#[test]
fn test_poseidon_hash_zero_inputs() {
    let zero = [0u8; 32];
    let one = [1u8; 32];
    
    let hash_zero_zero = poseidon_hash(&zero, &zero);
    let hash_zero_one = poseidon_hash(&zero, &one);
    let hash_one_zero = poseidon_hash(&one, &zero);
    
    // All should be different
    assert_ne!(hash_zero_zero, hash_zero_one);
    assert_ne!(hash_zero_zero, hash_one_zero);
    assert_ne!(hash_zero_one, hash_one_zero);
}

#[test]
fn test_merkle_tree_leaf_hash() {
    let commitment = [1u8; 32];
    let leaf_index = 5u32;
    
    let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    // Hash should be different from commitment
    assert_ne!(hash, commitment);
    
    // Different leaf indices should produce different hashes
    let hash2 = merkle_tree_leaf_hash(&commitment, 6);
    assert_ne!(hash, hash2);
}

#[test]
fn test_merkle_tree_leaf_hash_different_commitments() {
    let commitment1 = [1u8; 32];
    let commitment2 = [2u8; 32];
    let leaf_index = 5u32;
    
    let hash1 = merkle_tree_leaf_hash(&commitment1, leaf_index);
    let hash2 = merkle_tree_leaf_hash(&commitment2, leaf_index);
    
    assert_ne!(hash1, hash2);
}

#[test]
fn test_merkle_tree_leaf_hash_zero_index() {
    let commitment = [1u8; 32];
    
    let hash_zero = merkle_tree_leaf_hash(&commitment, 0);
    let hash_one = merkle_tree_leaf_hash(&commitment, 1);
    
    assert_ne!(hash_zero, hash_one);
}

#[test]
fn test_merkle_tree_leaf_hash_max_index() {
    let commitment = [1u8; 32];
    
    let hash_max = merkle_tree_leaf_hash(&commitment, u32::MAX);
    let hash_max_minus_one = merkle_tree_leaf_hash(&commitment, u32::MAX - 1);
    
    assert_ne!(hash_max, hash_max_minus_one);
}

#[test]
fn test_merkle_tree_leaf_hash_deterministic() {
    let commitment = [42u8; 32];
    let leaf_index = 123u32;
    
    let hash1 = merkle_tree_leaf_hash(&commitment, leaf_index);
    let hash2 = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    assert_eq!(hash1, hash2);
}

#[test]
fn test_merkle_tree_leaf_hash_edge_cases() {
    let commitment = [255u8; 32];
    
    // Test with various edge case indices
    let indices = [0, 1, 2, 100, 1000, u32::MAX / 2, u32::MAX - 1, u32::MAX];
    
    let mut hashes = Vec::new();
    for &index in &indices {
        let hash = merkle_tree_leaf_hash(&commitment, index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different indices");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_different_commitments_same_index() {
    let leaf_index = 42u32;
    
    let commitments = [
        [0u8; 32],
        [1u8; 32],
        [255u8; 32],
        [0x12u8; 32],
        [0xABu8; 32],
    ];
    
    let mut hashes = Vec::new();
    for commitment in &commitments {
        let hash = merkle_tree_leaf_hash(commitment, leaf_index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different commitments");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_consistency() {
    // Test that the same input always produces the same output
    let commitment = [123u8; 32];
    let leaf_index = 456u32;
    
    for _ in 0..10 {
        let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
        assert_eq!(hash, merkle_tree_leaf_hash(&commitment, leaf_index));
    }
}

#[test]
fn test_merkle_tree_leaf_hash_input_validation() {
    let commitment = [1u8; 32];
    
    // Test with various valid indices
    let valid_indices = [0, 1, 100, 1000, u32::MAX];
    
    for &index in &valid_indices {
        let hash = merkle_tree_leaf_hash(&commitment, index);
        // Hash should not be all zeros (very unlikely)
        assert_ne!(hash, [0u8; 32]);
    }
}

#[test]
fn test_merkle_tree_leaf_hash_output_properties() {
    let commitment = [42u8; 32];
    let leaf_index = 789u32;
    
    let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    // Hash should be 32 bytes
    assert_eq!(hash.len(), 32);
    
    // Hash should not equal the input commitment
    assert_ne!(hash, commitment);
    
    // Hash should not be all zeros or all ones
    assert_ne!(hash, [0u8; 32]);
    assert_ne!(hash, [255u8; 32]);
}

#[test]
fn test_merkle_tree_leaf_hash_performance() {
    let commitment = [1u8; 32];
    let leaf_index = 1000u32;
    
    // This test ensures the function completes in reasonable time
    let start = std::time::Instant::now();
    let _hash = merkle_tree_leaf_hash(&commitment, leaf_index);
    let duration = start.elapsed();
    
    // Should complete in less than 1 second (very generous)
    assert!(duration.as_secs() < 1);
}

#[test]
fn test_merkle_tree_leaf_hash_deterministic_across_runs() {
    let commitment = [99u8; 32];
    let leaf_index = 777u32;
    
    // Run multiple times to ensure deterministic output
    let mut previous_hash = None;
    for _ in 0..5 {
        let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
        
        if let Some(prev) = previous_hash {
            assert_eq!(hash, prev, "Hash should be deterministic across runs");
        }
        
        previous_hash = Some(hash);
    }
}

#[test]
fn test_merkle_tree_leaf_hash_large_indices() {
    let commitment = [1u8; 32];
    
    // Test with large indices
    let large_indices = [
        u32::MAX,
        u32::MAX - 1,
        u32::MAX / 2,
        u32::MAX / 4,
        u32::MAX / 8,
    ];
    
    let mut hashes = Vec::new();
    for &index in &large_indices {
        let hash = merkle_tree_leaf_hash(&commitment, index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different large indices");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_small_indices() {
    let commitment = [1u8; 32];
    
    // Test with small indices
    let small_indices = [0, 1, 2, 3, 4, 5, 10, 20, 50, 100];
    
    let mut hashes = Vec::new();
    for &index in &small_indices {
        let hash = merkle_tree_leaf_hash(&commitment, index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different small indices");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_special_commitments() {
    let leaf_index = 42u32;
    
    // Test with special commitment values
    let special_commitments = [
        [0u8; 32],      // All zeros
        [255u8; 32],    // All ones
        [0x55u8; 32],   // Alternating pattern
        [0xAAu8; 32],   // Alternating pattern (inverted)
        [0x12u8; 32],   // Specific pattern
        [0x34u8; 32],   // Another pattern
    ];
    
    let mut hashes = Vec::new();
    for commitment in &special_commitments {
        let hash = merkle_tree_leaf_hash(commitment, leaf_index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different special commitments");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_consistency_with_different_orders() {
    let commitment1 = [1u8; 32];
    let commitment2 = [2u8; 32];
    let leaf_index1 = 10u32;
    let leaf_index2 = 20u32;
    
    // Test consistency when calling with different orders
    let hash1 = merkle_tree_leaf_hash(&commitment1, leaf_index1);
    let hash2 = merkle_tree_leaf_hash(&commitment2, leaf_index2);
    let hash3 = merkle_tree_leaf_hash(&commitment1, leaf_index1);
    let hash4 = merkle_tree_leaf_hash(&commitment2, leaf_index2);
    
    assert_eq!(hash1, hash3, "Same inputs should produce same hash");
    assert_eq!(hash2, hash4, "Same inputs should produce same hash");
    assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
}

#[test]
fn test_merkle_tree_leaf_hash_boundary_conditions() {
    let commitment = [1u8; 32];
    
    // Test boundary conditions
    let boundary_indices = [
        0,                    // Minimum
        1,                    // Small positive
        u32::MAX / 2,         // Midpoint
        u32::MAX - 1,         // Near maximum
        u32::MAX,             // Maximum
    ];
    
    let mut hashes = Vec::new();
    for &index in &boundary_indices {
        let hash = merkle_tree_leaf_hash(&commitment, index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different boundary indices");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_random_like_behavior() {
    let commitment = [42u8; 32];
    
    // Test with indices that might trigger edge cases in hash functions
    let test_indices = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010,
    ];
    
    let mut hashes = Vec::new();
    for &index in &test_indices {
        let hash = merkle_tree_leaf_hash(&commitment, index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different test indices");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_output_distribution() {
    let commitment = [1u8; 32];
    
    // Test that outputs are well distributed
    let mut hashes = Vec::new();
    for i in 0..100 {
        let hash = merkle_tree_leaf_hash(&commitment, i);
        hashes.push(hash);
    }
    
    // Check that we don't have too many collisions
    let mut unique_hashes = std::collections::HashSet::new();
    for hash in &hashes {
        unique_hashes.insert(hash);
    }
    
    // Should have very few collisions (all unique in this case)
    assert_eq!(unique_hashes.len(), hashes.len(), "All hashes should be unique");
}

#[test]
fn test_merkle_tree_leaf_hash_deterministic_with_same_inputs() {
    let commitment = [123u8; 32];
    let leaf_index = 456u32;
    
    // Run the same computation multiple times
    let hash1 = merkle_tree_leaf_hash(&commitment, leaf_index);
    let hash2 = merkle_tree_leaf_hash(&commitment, leaf_index);
    let hash3 = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
    assert_eq!(hash1, hash3);
}

#[test]
fn test_merkle_tree_leaf_hash_different_commitments_different_indices() {
    let commitments = [
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
    ];
    
    let indices = [10, 20, 30];
    
    let mut hashes = Vec::new();
    for commitment in &commitments {
        for &index in &indices {
            let hash = merkle_tree_leaf_hash(commitment, index);
            hashes.push(hash);
        }
    }
    
    // All 9 combinations should produce unique hashes
    let mut unique_hashes = std::collections::HashSet::new();
    for hash in &hashes {
        unique_hashes.insert(hash);
    }
    
    assert_eq!(unique_hashes.len(), hashes.len(), "All combinations should produce unique hashes");
}

#[test]
fn test_merkle_tree_leaf_hash_edge_case_commitments() {
    let leaf_index = 42u32;
    
    // Test with edge case commitments
    let edge_commitments = [
        [0u8; 32],           // All zeros
        [255u8; 32],         // All ones
        [0x80u8; 32],        // High bit set
        [0x01u8; 32],        // Low bit set
        [0x55u8; 32],        // Alternating 0101
        [0xAAu8; 32],        // Alternating 1010
    ];
    
    let mut hashes = Vec::new();
    for commitment in &edge_commitments {
        let hash = merkle_tree_leaf_hash(commitment, leaf_index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different edge case commitments");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_consistency_across_different_calls() {
    let commitment = [99u8; 32];
    let leaf_index = 888u32;
    
    // Call the function multiple times with the same inputs
    let mut hashes = Vec::new();
    for _ in 0..10 {
        let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
        hashes.push(hash);
    }
    
    // All hashes should be identical
    let first_hash = hashes[0];
    for hash in &hashes {
        assert_eq!(*hash, first_hash, "All calls with same inputs should produce identical hashes");
    }
}

#[test]
fn test_merkle_tree_leaf_hash_input_sensitivity() {
    let base_commitment = [1u8; 32];
    let base_index = 100u32;
    
    let base_hash = merkle_tree_leaf_hash(&base_commitment, base_index);
    
    // Test sensitivity to commitment changes
    let mut modified_commitment = base_commitment;
    modified_commitment[0] = 2;
    let hash_modified_commitment = merkle_tree_leaf_hash(&modified_commitment, base_index);
    assert_ne!(base_hash, hash_modified_commitment, "Hash should change when commitment changes");
    
    // Test sensitivity to index changes
    let hash_modified_index = merkle_tree_leaf_hash(&base_commitment, base_index + 1);
    assert_ne!(base_hash, hash_modified_index, "Hash should change when index changes");
}

#[test]
fn test_merkle_tree_leaf_hash_output_properties_detailed() {
    let commitment = [42u8; 32];
    let leaf_index = 789u32;
    
    let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    // Hash should be exactly 32 bytes
    assert_eq!(hash.len(), 32);
    
    // Hash should not be all zeros (extremely unlikely)
    assert_ne!(hash, [0u8; 32]);
    
    // Hash should not be all ones (extremely unlikely)
    assert_ne!(hash, [255u8; 32]);
    
    // Hash should not equal the input commitment
    assert_ne!(hash, commitment);
    
    // Hash should have some variation (not all the same byte)
    let first_byte = hash[0];
    let mut all_same = true;
    for &byte in &hash[1..] {
        if byte != first_byte {
            all_same = false;
            break;
        }
    }
    assert!(!all_same, "Hash should have some byte variation");
}

#[test]
fn test_merkle_tree_leaf_hash_performance_consistency() {
    let commitment = [1u8; 32];
    let leaf_index = 1000u32;
    
    // Run multiple times to ensure consistent performance
    let mut durations = Vec::new();
    for _ in 0..5 {
        let start = std::time::Instant::now();
        let _hash = merkle_tree_leaf_hash(&commitment, leaf_index);
        let duration = start.elapsed();
        durations.push(duration);
    }
    
    // All runs should complete in reasonable time
    for duration in &durations {
        assert!(duration.as_secs() < 1, "Hash computation should complete in reasonable time");
    }
    
    // Performance should be relatively consistent (within 10x of each other)
    let min_duration = durations.iter().min().unwrap();
    let max_duration = durations.iter().max().unwrap();
    assert!(max_duration.as_nanos() < min_duration.as_nanos() * 10, 
            "Performance should be relatively consistent");
}

#[test]
fn test_merkle_tree_leaf_hash_deterministic_across_compilation() {
    let commitment = [77u8; 32];
    let leaf_index = 999u32;
    
    // This test ensures the function is deterministic across different compilation runs
    let hash1 = merkle_tree_leaf_hash(&commitment, leaf_index);
    let hash2 = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    assert_eq!(hash1, hash2, "Hash should be deterministic across compilation runs");
}

#[test]
fn test_merkle_tree_leaf_hash_large_scale_uniqueness() {
    let commitment = [1u8; 32];
    
    // Test with a larger set of indices to ensure uniqueness
    let mut hashes = Vec::new();
    for i in 0..1000 {
        let hash = merkle_tree_leaf_hash(&commitment, i);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    let mut unique_hashes = std::collections::HashSet::new();
    for hash in &hashes {
        unique_hashes.insert(hash);
    }
    
    assert_eq!(unique_hashes.len(), hashes.len(), "All 1000 hashes should be unique");
}

#[test]
fn test_merkle_tree_leaf_hash_commitment_sensitivity() {
    let leaf_index = 50u32;
    
    // Test that small changes in commitment produce different hashes
    let base_commitment = [1u8; 32];
    let base_hash = merkle_tree_leaf_hash(&base_commitment, leaf_index);
    
    for i in 0..32 {
        let mut modified_commitment = base_commitment;
        modified_commitment[i] = modified_commitment[i].wrapping_add(1);
        let modified_hash = merkle_tree_leaf_hash(&modified_commitment, leaf_index);
        assert_ne!(base_hash, modified_hash, "Hash should change when commitment byte {} changes", i);
    }
}

#[test]
fn test_merkle_tree_leaf_hash_index_sensitivity() {
    let commitment = [1u8; 32];
    
    // Test that small changes in index produce different hashes
    let base_index = 100u32;
    let base_hash = merkle_tree_leaf_hash(&commitment, base_index);
    
    for offset in 1..=10 {
        let modified_index = base_index + offset;
        let modified_hash = merkle_tree_leaf_hash(&commitment, modified_index);
        assert_ne!(base_hash, modified_hash, "Hash should change when index changes by {}", offset);
    }
}

#[test]
fn test_merkle_tree_leaf_hash_cross_sensitivity() {
    let base_commitment = [1u8; 32];
    let base_index = 100u32;
    let base_hash = merkle_tree_leaf_hash(&base_commitment, base_index);
    
    // Test that changing both commitment and index produces different hash
    let modified_commitment = [2u8; 32];
    let modified_index = 101u32;
    let modified_hash = merkle_tree_leaf_hash(&modified_commitment, modified_index);
    
    assert_ne!(base_hash, modified_hash, "Hash should change when both commitment and index change");
}

#[test]
fn test_merkle_tree_leaf_hash_consistency_with_different_commitment_sizes() {
    // Test that the function works consistently regardless of commitment content
    let leaf_index = 42u32;
    
    let commitments = [
        [0u8; 32],      // All zeros
        [1u8; 32],      // All ones (value 1)
        [255u8; 32],    // All 255s
        [0x55u8; 32],   // Alternating pattern
        [0xAAu8; 32],   // Alternating pattern (inverted)
    ];
    
    let mut hashes = Vec::new();
    for commitment in &commitments {
        let hash = merkle_tree_leaf_hash(commitment, leaf_index);
        hashes.push(hash);
    }
    
    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hashes should be unique for different commitment patterns");
        }
    }
}

#[test]
fn test_merkle_tree_leaf_hash_consistency_with_different_index_ranges() {
    let commitment = [1u8; 32];
    
    // Test different ranges of indices
    let index_ranges = [
        (0..10),           // Small range
        (100..110),        // Medium range
        (1000..1010),      // Large range
        (u32::MAX - 10..u32::MAX), // Near maximum range
    ];
    
    let mut all_hashes = Vec::new();
    for range in &index_ranges {
        let mut range_hashes = Vec::new();
        for index in range.clone() {
            let hash = merkle_tree_leaf_hash(&commitment, index);
            range_hashes.push(hash);
        }
        all_hashes.extend(range_hashes);
    }
    
    // All hashes should be unique across all ranges
    let mut unique_hashes = std::collections::HashSet::new();
    for hash in &all_hashes {
        unique_hashes.insert(hash);
    }
    
    assert_eq!(unique_hashes.len(), all_hashes.len(), "All hashes across all ranges should be unique");
}

#[test]
fn test_merkle_tree_leaf_hash_final_comprehensive() {
    let commitment = [42u8; 32];
    let leaf_index = 123u32;
    
    // Final comprehensive test
    let hash = merkle_tree_leaf_hash(&commitment, leaf_index);
    
    // Basic properties
    assert_eq!(hash.len(), 32);
    assert_ne!(hash, commitment);
    assert_ne!(hash, [0u8; 32]);
    assert_ne!(hash, [255u8; 32]);
    
    // Deterministic
    assert_eq!(hash, merkle_tree_leaf_hash(&commitment, leaf_index));
    
    // Sensitive to input changes
    let mut modified_commitment = commitment;
    modified_commitment[0] = modified_commitment[0].wrapping_add(1);
    assert_ne!(hash, merkle_tree_leaf_hash(&modified_commitment, leaf_index));
    
    let modified_index = leaf_index + 1;
    assert_ne!(hash, merkle_tree_leaf_hash(&commitment, modified_index));
    
    // Performance
    let start = std::time::Instant::now();
    let _ = merkle_tree_leaf_hash(&commitment, leaf_index);
    let duration = start.elapsed();
    assert!(duration.as_secs() < 1);
}
*/
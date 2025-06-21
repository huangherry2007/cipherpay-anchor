use anchor_lang::prelude::*;
use sha2::{Sha256, Digest};

#[error_code]
pub enum MerkleError {
    #[msg("Invalid proof format")]
    InvalidProofFormat,
    #[msg("Invalid merkle root")]
    InvalidMerkleRoot,
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
}

#[allow(dead_code)]
/// Verifies a merkle proof against a root
pub fn verify_merkle_proof(proof: &Vec<[u8; 32]>, root: [u8; 32]) -> Result<()> {
    if proof.is_empty() {
        return err!(MerkleError::InvalidProofFormat);
    }

    // Calculate the merkle root from the proof
    let calculated_root = calculate_merkle_root(proof)?;
    
    // Compare with the provided root
    if calculated_root != root {
        return err!(MerkleError::InvalidMerkleRoot);
    }

    Ok(())
}

#[allow(dead_code)]
/// Calculates the merkle root from a proof
pub fn calculate_merkle_root(proof: &Vec<[u8; 32]>) -> Result<[u8; 32]> {
    let mut current = proof[0];
    
    for i in 1..proof.len() {
        let mut hasher = Sha256::new();
        
        // Sort the pair to ensure consistent ordering
        if current < proof[i] {
            hasher.update(&current);
            hasher.update(&proof[i]);
        } else {
            hasher.update(&proof[i]);
            hasher.update(&current);
        }
        
        current = hasher.finalize().into();
    }
    
    Ok(current)
}

#[allow(dead_code)]
/// Verifies if a leaf is in the merkle tree
pub fn verify_leaf_in_tree(leaf: [u8; 32], proof: &Vec<[u8; 32]>, root: [u8; 32]) -> Result<bool> {
    let mut current = leaf;
    
    for sibling in proof {
        let mut hasher = Sha256::new();
        
        // Sort the pair to ensure consistent ordering
        if current < *sibling {
            hasher.update(&current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(&current);
        }
        
        current = hasher.finalize().into();
    }
    
    Ok(current == root)
}

#[allow(dead_code)]
/// Verifies if a nullifier has been used
pub fn verify_nullifier(nullifier: [u8; 32], nullifier_set: &Vec<[u8; 32]>) -> Result<bool> {
    // Check if nullifier is already used
    if nullifier_set.contains(&nullifier) {
        return err!(MerkleError::NullifierAlreadyUsed);
    }
    
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_verification() {
        // Create a simple merkle tree with 4 leaves
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        let leaf4 = [4u8; 32];

        // Calculate intermediate hashes
        let mut hasher = Sha256::new();
        hasher.update(&leaf1);
        hasher.update(&leaf2);
        let hash12: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(&leaf3);
        hasher.update(&leaf4);
        let hash34: [u8; 32] = hasher.finalize().into();

        // Calculate root
        let mut hasher = Sha256::new();
        hasher.update(&hash12);
        hasher.update(&hash34);
        let root: [u8; 32] = hasher.finalize().into();

        // Create proof for leaf1
        let proof = vec![leaf2, hash34];

        // Verify proof
        assert!(verify_merkle_proof(&proof, root).is_ok());
    }

    #[test]
    fn test_nullifier_verification() {
        let nullifier = [1u8; 32];
        let mut nullifier_set = Vec::new();

        // First verification should succeed
        assert!(verify_nullifier(nullifier, &nullifier_set).is_ok());

        // Add nullifier to set
        nullifier_set.push(nullifier);

        // Second verification should fail
        assert!(verify_nullifier(nullifier, &nullifier_set).is_err());
    }
} 
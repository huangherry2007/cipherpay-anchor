use crate::state::MerkleRootCache;

/// Checks if the given Merkle root exists in the root cache.
pub fn is_valid_root(root: &[u8], cache: &MerkleRootCache) -> bool {
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&root[0..32]);
    cache.contains_root(&fixed)
}

/// Inserts a new Merkle root into the cache (evicting the oldest if full).
pub fn insert_merkle_root(new_root: &[u8], cache: &mut MerkleRootCache) {
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&new_root[0..32]);
    cache.insert_root(fixed);
}

use anchor_lang::prelude::*;

pub const MAX_ROOTS: usize = 1024;

#[account]
pub struct Nullifier {
    pub used: bool,
    pub bump: u8,
}

impl Nullifier {
    pub const SIZE: usize = 1 + 1; // bool + bump
}

#[account]
pub struct MerkleRootCache {
    pub roots: Vec<[u8; 32]>, // fixed-size byte arrays of cached roots
}

impl MerkleRootCache {
    pub const SIZE: usize = 4 + (MAX_ROOTS * 32);
    pub fn insert_root(&mut self, new_root: [u8; 32]) {
        if !self.roots.contains(&new_root) {
            if self.roots.len() >= MAX_ROOTS {
                self.roots.remove(0); // drop oldest
            }
            self.roots.push(new_root);
        }
    }

    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        self.roots.contains(root)
    }
}

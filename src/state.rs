use anchor_lang::prelude::*;
use crate::constants::MAX_ROOTS;

/// Marker PDA keyed by `deposit_hash` that makes `shielded_deposit` idempotent.
#[account]
pub struct DepositMarker {
    /// Has this deposit_hash already been consumed (commitment inserted)?
    pub processed: bool,
    /// PDA bump
    pub bump: u8,
}

impl DepositMarker {
    /// Raw field size (excluding the 8-byte Anchor discriminator)
    pub const SIZE: usize = 1 + 1;
    /// Full account space (including discriminator)
    pub const SPACE: usize = 8 + Self::SIZE;

    /// Mark as processed (idempotent setter).
    #[inline]
    pub fn set_processed(&mut self) {
        self.processed = true;
    }
}

/// Optional on-chain nullifier record (if you decide to persist spent notes).
#[account]
pub struct Nullifier {
    /// Whether this nullifier has been seen/used
    pub used: bool,
    /// PDA bump
    pub bump: u8,
}

impl Nullifier {
    pub const SIZE: usize = 1 + 1;
    pub const SPACE: usize = 8 + Self::SIZE;

    #[inline]
    pub fn mark_used(&mut self) {
        self.used = true;
    }
}

/// Ring-buffer-ish cache of recent Merkle roots (simple Vec variant).
///
/// Layout: Anchor serializes `Vec<[u8;32]>` as `4 (len) + len * 32` bytes.
/// We allocate enough space for `MAX_ROOTS` entries; at runtime we keep length
/// ≤ MAX_ROOTS and drop the oldest when full.
#[account]
pub struct MerkleRootCache {
    /// Recent roots (most recent is at the end).
    pub roots: Vec<[u8; 32]>,
}

impl MerkleRootCache {
    /// Raw field size (excluding discriminator). We reserve space for up to MAX_ROOTS elements.
    /// 4 bytes for Vec length + N * 32 bytes per root.
    pub const SIZE: usize = 4 + (MAX_ROOTS * 32);
    /// Full account space (including discriminator).
    pub const SPACE: usize = 8 + Self::SIZE;

    /// Insert a root if it is not already present. Returns true if inserted.
    pub fn try_insert_root(&mut self, new_root: [u8; 32]) -> bool {
        if self.roots.contains(&new_root) {
            return false;
        }
        if self.roots.len() >= MAX_ROOTS {
            // drop oldest to keep bounded size (O(n) but n=128 is tiny)
            self.roots.remove(0);
        }
        self.roots.push(new_root);
        true
    }

    /// Insert (without duplicate check). Returns whether we dropped an old root.
    pub fn insert_root(&mut self, new_root: [u8; 32]) -> bool {
        let mut dropped = false;
        if self.roots.len() >= MAX_ROOTS {
            self.roots.remove(0);
            dropped = true;
        }
        self.roots.push(new_root);
        dropped
    }

    /// Check if a root exists in the cache.
    #[inline]
    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        self.roots.contains(root)
    }

    /// Return the most recent root, if any.
    #[inline]
    pub fn latest(&self) -> Option<[u8; 32]> {
        self.roots.last().copied()
    }

    /// Whether the cache is at capacity.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.roots.len() >= MAX_ROOTS
    }
}

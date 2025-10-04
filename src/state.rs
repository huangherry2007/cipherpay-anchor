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
pub struct NullifierRecord {
    pub processed: bool,
    pub bump: u8,
}
impl NullifierRecord {
    pub const SIZE: usize = 1 + 1;
    pub const SPACE: usize = 8 + Self::SIZE;
}

#[account]
pub struct TreeState {
    pub version:     u16,        // v1
    pub current_root:[u8; 32],
    pub next_index:  u32,
    pub depth:       u8,
    pub _reserved:   [u8; 31],   // future flags/fields (optional)
}
// Anchor 0.29+: implement `Space` with `INIT_SPACE`
impl anchor_lang::Space for TreeState {
    const INIT_SPACE: usize = 2 + 32 + 4 + 1 + 31;
}

/// Fixed-capacity ring buffer for recent Merkle roots.
///
/// • Zero-copy: no (de)serialization of a large Vec on every ix.
/// • Backed by a PDA and accessed via `AccountLoader<MerkleRootCache>`.
///
/// Layout on-chain:
///   [8-byte discriminator] + [[u8;32]; MAX_ROOTS] + u16(next_slot) + u16(count)
#[account(zero_copy)]
#[repr(C)]
pub struct MerkleRootCache {
    /// Ring buffer of recent roots.
    pub roots: [[u8; 32]; MAX_ROOTS],
    /// Next write position in the ring (0..MAX_ROOTS-1).
    pub next_slot: u16,
    /// Number of valid entries (<= MAX_ROOTS).
    pub count: u16,
}

impl MerkleRootCache {
    /// Bytes excluding the discriminator.
    pub const BYTE_SIZE: usize = (MAX_ROOTS * 32) + 2 + 2;
    /// Bytes including the discriminator (what you pass as `space` minus the 8 you add in `#[account(init, space = 8 + ...)]`).
    pub const SIZE: usize = Self::BYTE_SIZE;
    /// Convenience: full account size including discriminator.
    pub const SPACE: usize = 8 + Self::BYTE_SIZE;

    #[inline]
    pub fn clear(&mut self) {
        // All zeros is a valid empty state, but we explicitly reset counters.
        self.next_slot = 0;
        self.count = 0;
        // Zero the roots array.
        // (Compiler is smart enough; this does NOT copy on stack.)
        self.roots = [[0u8; 32]; MAX_ROOTS];
    }

    /// Insert a new root (ring-buffer). Overwrites oldest when full.
    #[inline]
    pub fn insert(&mut self, new_root: [u8; 32]) {
        let idx = (self.next_slot as usize) % MAX_ROOTS;
        self.roots[idx] = new_root;
        self.next_slot = ((self.next_slot as usize + 1) % MAX_ROOTS) as u16;
        if (self.count as usize) < MAX_ROOTS {
            self.count += 1;
        }
    }

    /// Check whether a root exists in the cache (O(MAX_ROOTS)).
    #[inline]
    pub fn contains(&self, root: &[u8; 32]) -> bool {
        let total = self.count as usize;
        if total == 0 {
            return false;
        }
        // If not yet full, the logical order is 0..count-1.
        // If full, the oldest is at next_slot.
        let start = if total < MAX_ROOTS {
            0usize
        } else {
            self.next_slot as usize
        };
        for i in 0..total {
            let idx = (start + i) % MAX_ROOTS;
            if &self.roots[idx] == root {
                return true;
            }
        }
        false
    }

    /// Latest (most recently inserted) root, if any.
    #[inline]
    pub fn latest(&self) -> Option<[u8; 32]> {
        if self.count == 0 {
            None
        } else {
            let idx = (self.next_slot as usize + MAX_ROOTS - 1) % MAX_ROOTS;
            Some(self.roots[idx])
        }
    }
}

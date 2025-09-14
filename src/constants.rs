//! Program-wide constants


// =======================
// PDA seeds (yours, kept)
// =======================

/// Deposit marker PDA: seeds = [b"deposit", deposit_hash]
pub const DEPOSIT_MARKER_SEED: &[u8] = b"deposit";

/// Vault authority PDA (canonical owner of the vault ATA):
/// seeds = [b"vault", mint]
pub const VAULT_SEED: &[u8] = b"vault";

/// (Optional) Nullifier PDA if you decide to persist spent notes:
/// seeds = [b"nullifier", nullifier_bytes]
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Root cache PDA (ring buffer or single root, depending on your state design):
/// seeds = [b"root_cache", mint] (or global, if you prefer)
pub const MERKLE_ROOT_CACHE_SEED: &[u8] = b"root_cache";

/// How many historical roots to store if you keep a ring-buffer cache.
pub const MAX_ROOTS: usize = 128;

// ==================================
// Groth16 / BN254 byte-size helpers
// ==================================

/// Field element size in bytes (BN254 Fr)
pub const FIELD_BYTES: usize = 32;
/// G1 point = (x,y) = 2 * 32
pub const G1_BYTES: usize = 64;
/// G2 point = (x1,x2,y1,y2) = 4 * 32
pub const G2_BYTES: usize = 128;
/// Groth16 proof bytes = A(G1) + B(G2) + C(G1)
pub const PROOF_BYTES_LEN: usize = G1_BYTES + G2_BYTES + G1_BYTES; // 256
// BYTES_F is now defined in zk_verifier::solana_verifier module

// =====================================================
// Public-signal counts (must match your Circom circuits)
// =====================================================

/// deposit.circom publicSignals count:
/// [newCommitment, ownerCipherPayPubKey, newMerkleRoot, newNextLeafIndex, amount, depositHash]
pub const NPUB_DEPOSIT: usize = 6;

/// withdraw.circom publicSignals count:
/// [nullifier, merkleRoot, recipientWalletPubKey, amount, tokenId]
pub const NPUB_WITHDRAW: usize = 5;

/// transfer.circom publicSignals count:
/// [outC1, outC2, nullifier, merkleRoot, newRoot1, newRoot2, newNextIdx, encNote1Hash, encNote2Hash]
pub const NPUB_TRANSFER: usize = 9;

// =====================================
// Embedded verifying keys (binary blobs)
// =====================================
// These files are produced by your converter script and checked into the repo under
// `src/zk_verifier/*.bin`. Keep paths in sync with your tree.

pub const VK_DEPOSIT_BYTES: &[u8]  = include_bytes!("zk_verifier/deposit_vk.bin");
pub const VK_TRANSFER_BYTES: &[u8] = include_bytes!("zk_verifier/transfer_vk.bin");
pub const VK_WITHDRAW_BYTES: &[u8] = include_bytes!("zk_verifier/withdraw_vk.bin");

// ============
// Misc helpers
// ============

/// Little utility: read a u64 from the first 8 LE bytes of a 32-byte field element.
#[inline]
pub fn le_bytes_32_to_u64(x: &[u8; FIELD_BYTES]) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v |= (x[i] as u64) << (8 * i);
    }
    v
}


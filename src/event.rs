use anchor_lang::prelude::*;

/// Emitted after a successful shielded_deposit:
/// - `deposit_hash` was marked processed
/// - `commitment` inserted at `next_leaf_index`
/// - root cache updated with `new_merkle_root`
#[event]
pub struct DepositCompleted {
    pub deposit_hash: [u8; 32],
    pub owner_cipherpay_pubkey: [u8; 32],
    pub commitment: [u8; 32],
    pub old_merkle_root: [u8; 32],  // NEW
    pub new_merkle_root: [u8; 32],
    pub next_leaf_index: u32,
    pub mint: Pubkey,
}

/// Emitted after a successful shielded_transfer:
/// - proves membership of the input note (root = `merkle_root_before`)
/// - inserts two new commitments at indices `next_leaf_index` and `next_leaf_index + 1`
/// - binds ciphertext tags to outputs & recipients
#[event]
pub struct TransferCompleted {
    pub nullifier: [u8; 32],
    pub out1_commitment: [u8; 32],
    pub out2_commitment: [u8; 32],
    pub enc_note1_hash: [u8; 32],
    pub enc_note2_hash: [u8; 32],
    /// Root before appends (from membership proof)
    pub merkle_root_before: [u8; 32],
    /// Root after inserting out1
    pub new_merkle_root1: [u8; 32],
    /// Root after inserting out2
    pub new_merkle_root2: [u8; 32],
    /// Starting leaf index for out1 (out2 uses +1)
    pub next_leaf_index: u32,
    /// SPL mint that identifies the vault this applies to
    pub mint: Pubkey,
}

/// Emitted after a successful shielded_withdraw:
/// - proves inclusion, nullifies the note, and performs SPL transfer to `recipient`
#[event]
pub struct WithdrawCompleted {
    pub nullifier: [u8; 32],
    pub recipient: Pubkey,
    pub amount: u64,
    /// SPL mint that identifies the vault this came from
    pub mint: Pubkey,
}

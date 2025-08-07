use anchor_lang::prelude::*;

#[error_code]
pub enum CipherPayError {
    // === Deposit Errors ===
    #[msg("Deposit hash already used.")]
    DepositAlreadyUsed,

    #[msg("Zero-knowledge proof verification failed.")]
    InvalidZkProof,

    #[msg("Merkle root not found in root cache.")]
    UnknownMerkleRoot,

    #[msg("Leaf index in proof does not match on-chain next_leaf_index.")]
    LeafIndexMismatch,

    // === Transfer Errors ===
    #[msg("Nullifier already used.")]
    NullifierAlreadyUsed,

    #[msg("Nullifier provided does not match one in proof.")]
    NullifierMismatch,

    // === Withdraw Errors ===
    #[msg("Invalid withdrawal amount.")]
    InvalidWithdrawAmount,

    // === Token I/O Errors ===
    #[msg("Token transfer failed.")]
    TokenTransferFailed,

    // === General Errors ===
    #[msg("You are not authorized to perform this action.")]
    Unauthorized,
}

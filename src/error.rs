//! src/error.rs
use anchor_lang::prelude::*;

#[error_code]
pub enum CipherPayError {
    // ========== Deposit Errors ==========
    /// The deposit marker for this deposit_hash is already marked processed.
    #[msg("Deposit hash already used.")]
    DepositAlreadyUsed,

    /// The provided Merkle root was not found in the on-chain root cache.
    #[msg("Merkle root not found in root cache.")]
    UnknownMerkleRoot,

    /// The leaf index asserted in the proof doesn't match the program's expected next_leaf_index.
    #[msg("Leaf index in proof does not match on-chain next_leaf_index.")]
    LeafIndexMismatch,

    // ========== ZK / Verifier Errors ==========
    /// Generic verifier failure (pairing check / input inconsistency).
    #[msg("Zero-knowledge proof verification failed.")]
    InvalidZkProof,

    /// Proof bytes were not the expected 256 bytes (A:64 + B:128 + C:64).
    #[msg("Invalid Groth16 proof byte length.")]
    InvalidProofBytesLength,

    /// Public inputs blob length is not a multiple of 32, or doesn't match the expected count.
    #[msg("Invalid public inputs byte length.")]
    InvalidPublicInputsLength,

    /// Verifying key bytes are malformed or truncated.
    #[msg("Invalid or truncated verifying key bytes.")]
    InvalidVerifyingKey,

    /// The number of public inputs supplied does not match the circuit's expected count/order.
    #[msg("Mismatched number of public inputs for this circuit.")]
    PublicInputCountMismatch,

    /// When you bind opaque payload tags (e.g., encNote tags) to outputs/recipients and they don't match.
    #[msg("Public input payload binding mismatch.")]
    PayloadBindingMismatch,

    // ========== Transfer / Nullifier Errors ==========
    /// Nullifier is already recorded as used.
    #[msg("Nullifier already used.")]
    NullifierAlreadyUsed,

    /// Nullifier reconstructed from private inputs doesn't equal the one asserted (if you expose it).
    #[msg("Nullifier provided does not match one in proof.")]
    NullifierMismatch,

    // ========== Withdraw Errors ==========
    /// Sanity checks on amounts (e.g., zero/overflow) failed.
    #[msg("Invalid withdrawal amount.")]
    InvalidWithdrawAmount,

    // ========== Token / Vault Errors ==========
    /// A token transfer CPI returned an error status.
    #[msg("Token transfer failed.")]
    TokenTransferFailed,

    /// The provided vault ATA/mint doesn't match the program's canonical vault.
    #[msg("Provided vault account does not match program's vault.")]
    VaultMismatch,

    /// The PDA derived as the vault authority doesn't match the account provided.
    #[msg("Vault authority PDA does not match.")]
    VaultAuthorityMismatch,

    // ========== Transaction Validation Errors ==========
    /// Required Memo instruction not found in the same transaction.
    #[msg("Required Memo instruction not found in transaction.")]
    MemoMissing,

    /// Required SPL Token transfer not found in the same transaction.
    #[msg("Required SPL Token transfer not found in transaction.")]
    RequiredSplTransferMissing,

    // ========== General Errors ==========
    /// Signer/authority or account ownership checks failed.
    #[msg("You are not authorized to perform this action.")]
    Unauthorized,

    /// Generic bad input (range/format) guard.
    #[msg("Invalid input.")]
    InvalidInput,

    /// Any guarded arithmetic that would wrap/underflow.
    #[msg("Arithmetic overflow or underflow.")]
    ArithmeticError,

    #[msg("Old Merkle root does not match on-chain state.")]
    OldRootMismatch,          // 0x1782 or next free code
    #[msg("Next leaf index mismatch.")]
    NextLeafIndexMismatch,    // next free code

    #[msg("Already processed")]
    AlreadyProcessed,            // used by deposit marker + nullifier record
}

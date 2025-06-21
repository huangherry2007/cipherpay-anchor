use anchor_lang::prelude::*;

/// Error codes for the CipherPay program
#[error_code]
pub enum CipherPayError {
    /// Invalid proof format
    #[msg("Invalid proof format")]
    InvalidProofFormat,

    /// Proof verification failed
    #[msg("Proof verification failed")]
    ProofVerificationFailed,

    /// Insufficient compute budget
    #[msg("Insufficient compute budget")]
    InsufficientComputeBudget,

    /// Insufficient compute units
    #[msg("Insufficient compute units")]
    InsufficientComputeUnits,

    /// Invalid merkle root
    #[msg("Invalid merkle root")]
    InvalidMerkleRoot,

    /// Invalid merkle proof
    #[msg("Invalid merkle proof")]
    InvalidMerkleProof,

    /// Invalid nullifier
    #[msg("Invalid nullifier")]
    InvalidNullifier,

    /// Arithmetic overflow
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,

    /// Invalid stream parameters
    #[msg("Invalid stream parameters")]
    InvalidStreamParams,

    /// Stream has expired
    #[msg("Stream has expired")]
    StreamExpired,

    /// Invalid split distribution
    #[msg("Invalid split distribution")]
    InvalidSplitDistribution,

    /// Recipient limit exceeded
    #[msg("Recipient limit exceeded")]
    RecipientLimitExceeded,

    /// Amount overflow
    #[msg("Amount overflow")]
    AmountOverflow,

    /// Time constraint violation
    #[msg("Time constraint violation")]
    TimeConstraintViolation,

    /// Insufficient funds in vault
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,

    /// Nullifier already used
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,

    /// Duplicate recipient
    #[msg("Duplicate recipient")]
    DuplicateRecipient,

    /// Invalid split parameters
    #[msg("Invalid split parameters")]
    InvalidSplitParams,

    /// Zero amount
    #[msg("Zero amount")]
    ZeroAmount,

    /// Invalid compute budget
    #[msg("Invalid compute budget")]
    InvalidComputeBudget,

    /// Unsupported circuit type
    #[msg("Unsupported circuit type")]
    UnsupportedCircuit,

    /// Invalid public inputs
    #[msg("Invalid public inputs")]
    InvalidPublicInputs,

    /// Invalid curve point
    #[msg("Invalid curve point")]
    InvalidCurvePoint,

    /// Pairing verification failed
    #[msg("Pairing verification failed")]
    PairingVerificationFailed,

    /// Invalid audit proof
    #[msg("Invalid audit proof")]
    InvalidAuditProof,

    /// Invalid condition proof
    #[msg("Invalid condition proof")]
    InvalidConditionProof,

    /// Invalid stream proof
    #[msg("Invalid stream proof")]
    InvalidStreamProof,

    /// Invalid split proof
    #[msg("Invalid split proof")]
    InvalidSplitProof,

    /// Invalid transfer proof
    #[msg("Invalid transfer proof")]
    InvalidTransferProof,

    /// Invalid withdraw proof
    #[msg("Invalid withdraw proof")]
    InvalidWithdrawProof,

    /// State verification failed
    #[msg("State verification failed")]
    StateVerificationFailed,

    /// Authority verification failed
    #[msg("Authority verification failed")]
    AuthorityVerificationFailed,

    /// Vault not initialized
    #[msg("Vault not initialized")]
    VaultNotInitialized,

    /// Verifier not initialized
    #[msg("Verifier not initialized")]
    VerifierNotInitialized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        // Test that all error variants have messages
        let errors = [
            CipherPayError::InvalidProofFormat,
            CipherPayError::ProofVerificationFailed,
            CipherPayError::InsufficientComputeBudget,
            CipherPayError::InsufficientComputeUnits,
            CipherPayError::InvalidMerkleRoot,
            CipherPayError::InvalidMerkleProof,
            CipherPayError::InvalidNullifier,
            CipherPayError::ArithmeticOverflow,
            CipherPayError::InvalidStreamParams,
            CipherPayError::StreamExpired,
            CipherPayError::InvalidSplitDistribution,
            CipherPayError::RecipientLimitExceeded,
            CipherPayError::AmountOverflow,
            CipherPayError::TimeConstraintViolation,
            CipherPayError::InsufficientFunds,
            CipherPayError::NullifierAlreadyUsed,
            CipherPayError::DuplicateRecipient,
            CipherPayError::InvalidSplitParams,
            CipherPayError::ZeroAmount,
            CipherPayError::InvalidComputeBudget,
            CipherPayError::UnsupportedCircuit,
            CipherPayError::InvalidPublicInputs,
            CipherPayError::InvalidCurvePoint,
            CipherPayError::PairingVerificationFailed,
            CipherPayError::InvalidAuditProof,
            CipherPayError::InvalidConditionProof,
            CipherPayError::InvalidStreamProof,
            CipherPayError::InvalidSplitProof,
            CipherPayError::InvalidTransferProof,
            CipherPayError::InvalidWithdrawProof,
            CipherPayError::StateVerificationFailed,
            CipherPayError::AuthorityVerificationFailed,
            CipherPayError::VaultNotInitialized,
            CipherPayError::VerifierNotInitialized,
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
} 
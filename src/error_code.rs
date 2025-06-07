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

    /// Invalid merkle root
    #[msg("Invalid merkle root")]
    InvalidMerkleRoot,

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
            CipherPayError::InvalidMerkleRoot,
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
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
} 
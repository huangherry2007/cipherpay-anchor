/// Constants for stream verification
pub mod StreamVerification {
    /// Required compute units for stream verification
    pub const REQUIRED_UNITS: u32 = 200_000;
}

/// Constants for split verification
pub mod SplitVerification {
    /// Required compute units for split verification
    pub const REQUIRED_UNITS: u32 = 200_000;
}

/// Constants for account sizes
pub mod AccountSizes {
    /// Size of the VerifierState account
    pub const VERIFIER_STATE_SIZE: usize = 32 + 32 + 64 + 8 + 1;
    
    /// Size of the ShieldedVault account
    pub const SHIELDED_VAULT_SIZE: usize = 8 + 8 + 8 + 32 + 32 + 1 + 4 + (32 * 1000);
}

/// Constants for validation limits
pub mod ValidationLimits {
    /// Maximum number of recipients in a split
    pub const MAX_SPLIT_RECIPIENTS: usize = 10;
    
    /// Maximum size of nullifier set
    pub const MAX_NULLIFIER_SET_SIZE: usize = 1000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_sizes() {
        assert!(AccountSizes::VERIFIER_STATE_SIZE > 0);
        assert!(AccountSizes::SHIELDED_VAULT_SIZE > 0);
    }

    #[test]
    fn test_validation_limits() {
        assert!(ValidationLimits::MAX_SPLIT_RECIPIENTS > 0);
        assert!(ValidationLimits::MAX_NULLIFIER_SET_SIZE > 0);
    }
} 
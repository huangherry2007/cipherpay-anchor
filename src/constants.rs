// Constants for the CipherPay program

/// Constants for stream verification
#[allow(dead_code)]
pub mod stream_verification {
    /// Required compute units for stream verification
    pub const REQUIRED_UNITS: u32 = 200_000;
}

/// Constants for split verification
#[allow(dead_code)]
pub mod split_verification {
    /// Required compute units for split verification
    pub const REQUIRED_UNITS: u32 = 200_000;
}

/// Constants for transfer verification
#[allow(dead_code)]
pub mod transfer_verification {
    /// Required compute units for transfer verification
    pub const REQUIRED_UNITS: u32 = 150_000;
}

/// Constants for withdraw verification
#[allow(dead_code)]
pub mod withdraw_verification {
    /// Required compute units for withdraw verification
    pub const REQUIRED_UNITS: u32 = 150_000;
}

/// Constants for merkle verification
#[allow(dead_code)]
pub mod merkle_verification {
    /// Required compute units for merkle verification
    pub const REQUIRED_UNITS: u32 = 100_000;
}

/// Constants for nullifier verification
#[allow(dead_code)]
pub mod nullifier_verification {
    /// Required compute units for nullifier verification
    pub const REQUIRED_UNITS: u32 = 100_000;
}

/// Constants for audit verification
#[allow(dead_code)]
pub mod audit_verification {
    /// Required compute units for audit verification
    pub const REQUIRED_UNITS: u32 = 120_000;
}

/// Constants for condition verification
#[allow(dead_code)]
pub mod condition_verification {
    /// Required compute units for condition verification
    pub const REQUIRED_UNITS: u32 = 120_000;
}

/// Constants for account sizes
pub mod account_sizes {
    /// Size of the VerifierState account
    /// merkle_root (32) + authority (32) + last_verified_proof (64) + total_verified (8) + is_initialized (1)
    pub const VERIFIER_STATE_SIZE: usize = 32 + 32 + 64 + 8 + 1;
    
    /// Size of the ShieldedVault account
    /// total_deposited (8) + total_withdrawn (8) + balance (8) + nonce (8) + merkle_root (32) + authority (32) + is_initialized (1) + nullifier_set (4 + 32 * 1000)
    pub const SHIELDED_VAULT_SIZE: usize = 8 + 8 + 8 + 8 + 32 + 32 + 1 + 4 + (32 * 1000);
    
    /// Size of the StreamState account
    /// last_verified_time (8) + total_verified (8) + merkle_root (32)
    pub const STREAM_STATE_SIZE: usize = 8 + 8 + 32;
    
    /// Size of the SplitState account
    /// last_verified_time (8) + merkle_root (32)
    pub const SPLIT_STATE_SIZE: usize = 8 + 32;
}

/// Constants for validation limits
#[allow(dead_code)]
pub mod validation_limits {
    /// Maximum number of recipients in a split
    pub const MAX_SPLIT_RECIPIENTS: usize = 10;
    
    /// Maximum size of nullifier set
    pub const MAX_NULLIFIER_SET_SIZE: usize = 1000;
    
    /// Maximum proof size
    pub const MAX_PROOF_SIZE: usize = 1024;
    
    /// Maximum public inputs size
    pub const MAX_PUBLIC_INPUTS_SIZE: usize = 512;
}

/// Circuit type constants
#[allow(dead_code)]
pub mod circuit_types {
    pub const TRANSFER: &str = "transfer";
    pub const WITHDRAW: &str = "withdraw";
    pub const MERKLE: &str = "merkle";
    pub const NULLIFIER: &str = "nullifier";
    pub const AUDIT_PROOF: &str = "audit_proof";
    pub const ZK_STREAM: &str = "zkStream";
    pub const ZK_SPLIT: &str = "zkSplit";
    pub const ZK_CONDITION: &str = "zkCondition";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_sizes() {
        assert!(account_sizes::VERIFIER_STATE_SIZE > 0);
        assert!(account_sizes::SHIELDED_VAULT_SIZE > 0);
        assert!(account_sizes::STREAM_STATE_SIZE > 0);
        assert!(account_sizes::SPLIT_STATE_SIZE > 0);
    }

    #[test]
    fn test_validation_limits() {
        assert!(validation_limits::MAX_SPLIT_RECIPIENTS > 0);
        assert!(validation_limits::MAX_NULLIFIER_SET_SIZE > 0);
        assert!(validation_limits::MAX_PROOF_SIZE > 0);
        assert!(validation_limits::MAX_PUBLIC_INPUTS_SIZE > 0);
    }

    #[test]
    fn test_circuit_types() {
        assert_eq!(circuit_types::TRANSFER, "transfer");
        assert_eq!(circuit_types::WITHDRAW, "withdraw");
        assert_eq!(circuit_types::MERKLE, "merkle");
        assert_eq!(circuit_types::NULLIFIER, "nullifier");
        assert_eq!(circuit_types::AUDIT_PROOF, "audit_proof");
        assert_eq!(circuit_types::ZK_STREAM, "zkStream");
        assert_eq!(circuit_types::ZK_SPLIT, "zkSplit");
        assert_eq!(circuit_types::ZK_CONDITION, "zkCondition");
    }
} 
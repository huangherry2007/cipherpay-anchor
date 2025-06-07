use anchor_lang::prelude::*;

/// Event emitted when a proof is verified
#[event]
pub struct ProofVerified {
    pub stream_id: [u8; 32],
    pub timestamp: i64,
}

/// Event emitted when funds are deposited to the vault
#[event]
pub struct VaultDeposited {
    /// Amount deposited
    pub amount: u64,
    /// Timestamp of the deposit
    pub timestamp: i64,
}

/// Event emitted when funds are withdrawn from the vault
#[event]
pub struct VaultWithdrawn {
    /// Amount withdrawn
    pub amount: u64,
    /// Timestamp of the withdrawal
    pub timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_verified_event() {
        // Test with default values
        let event = ProofVerified {
            stream_id: [0; 32],
            timestamp: 1234567890,
        };
        assert_eq!(event.stream_id, [0; 32]);
        assert_eq!(event.timestamp, 1234567890);

        // Test with maximum values
        let event = ProofVerified {
            stream_id: [255; 32],
            timestamp: i64::MAX,
        };
        assert_eq!(event.stream_id, [255; 32]);
        assert_eq!(event.timestamp, i64::MAX);

        // Test with current timestamp
        let current_time = Clock::get().unwrap().unix_timestamp;
        let event = ProofVerified {
            stream_id: [42; 32],
            timestamp: current_time,
        };
        assert_eq!(event.stream_id, [42; 32]);
        assert!(event.timestamp <= current_time);
    }

    #[test]
    fn test_vault_events() {
        let base_time = Clock::get().unwrap().unix_timestamp;
        
        // Test deposit event
        let deposit_event = VaultDeposited {
            amount: 100,
            timestamp: base_time,
        };
        assert_eq!(deposit_event.amount, 100);
        assert_eq!(deposit_event.timestamp, base_time);

        // Test withdrawal event
        let withdraw_event = VaultWithdrawn {
            amount: 100,
            timestamp: base_time + 1,
        };
        assert_eq!(withdraw_event.amount, 100);
        assert_eq!(withdraw_event.timestamp, base_time + 1);
    }
} 
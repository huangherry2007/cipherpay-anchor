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

/// Event emitted when a transfer proof is verified
#[event]
pub struct TransferProofVerified {
    /// Amount transferred
    pub amount: u64,
    /// Recipient address
    pub recipient: Pubkey,
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when a withdraw proof is verified
#[event]
pub struct WithdrawProofVerified {
    /// Amount withdrawn
    pub amount: u64,
    /// Recipient address
    pub recipient: Pubkey,
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when a merkle proof is verified
#[event]
pub struct MerkleProofVerified {
    /// Merkle root
    pub merkle_root: [u8; 32],
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when a nullifier proof is verified
#[event]
pub struct NullifierProofVerified {
    /// Nullifier
    pub nullifier: [u8; 32],
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when an audit proof is verified
#[event]
pub struct AuditProofVerified {
    /// Audit ID
    pub audit_id: [u8; 32],
    /// Merkle root
    pub merkle_root: [u8; 32],
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when a stream proof is verified
#[event]
pub struct StreamProofVerified {
    /// Stream ID
    pub stream_id: [u8; 32],
    /// Amount
    pub amount: u64,
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when a split proof is verified
#[event]
pub struct SplitProofVerified {
    /// Split ID
    pub split_id: [u8; 32],
    /// Recipients
    pub recipients: Vec<Pubkey>,
    /// Amounts
    pub amounts: Vec<u64>,
    /// Timestamp of verification
    pub timestamp: i64,
}

/// Event emitted when a condition proof is verified
#[event]
pub struct ConditionProofVerified {
    /// Condition ID
    pub condition_id: [u8; 32],
    /// Merkle root
    pub merkle_root: [u8; 32],
    /// Timestamp of verification
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

        // Test with mock timestamp
        let mock_time = 1234567890;
        let event = ProofVerified {
            stream_id: [42; 32],
            timestamp: mock_time,
        };
        assert_eq!(event.stream_id, [42; 32]);
        assert_eq!(event.timestamp, mock_time);
    }

    #[test]
    fn test_vault_events() {
        let base_time = 1234567890;
        
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

    #[test]
    fn test_circuit_verification_events() {
        let base_time = 1234567890;
        let test_pubkey = Pubkey::new_unique();
        
        // Test transfer proof event
        let transfer_event = TransferProofVerified {
            amount: 1000,
            recipient: test_pubkey,
            timestamp: base_time,
        };
        assert_eq!(transfer_event.amount, 1000);
        assert_eq!(transfer_event.recipient, test_pubkey);
        
        // Test withdraw proof event
        let withdraw_event = WithdrawProofVerified {
            amount: 500,
            recipient: test_pubkey,
            timestamp: base_time + 1,
        };
        assert_eq!(withdraw_event.amount, 500);
        assert_eq!(withdraw_event.recipient, test_pubkey);
        
        // Test merkle proof event
        let merkle_event = MerkleProofVerified {
            merkle_root: [42; 32],
            timestamp: base_time + 2,
        };
        assert_eq!(merkle_event.merkle_root, [42; 32]);
        
        // Test nullifier proof event
        let nullifier_event = NullifierProofVerified {
            nullifier: [123; 32],
            timestamp: base_time + 3,
        };
        assert_eq!(nullifier_event.nullifier, [123; 32]);
        
        // Test audit proof event
        let audit_event = AuditProofVerified {
            audit_id: [1; 32],
            merkle_root: [2; 32],
            timestamp: base_time + 4,
        };
        assert_eq!(audit_event.audit_id, [1; 32]);
        assert_eq!(audit_event.merkle_root, [2; 32]);
        
        // Test stream proof event
        let stream_event = StreamProofVerified {
            stream_id: [10; 32],
            amount: 2000,
            timestamp: base_time + 5,
        };
        assert_eq!(stream_event.stream_id, [10; 32]);
        assert_eq!(stream_event.amount, 2000);
        
        // Test split proof event
        let split_event = SplitProofVerified {
            split_id: [20; 32],
            recipients: vec![test_pubkey],
            amounts: vec![100],
            timestamp: base_time + 6,
        };
        assert_eq!(split_event.split_id, [20; 32]);
        assert_eq!(split_event.recipients.len(), 1);
        assert_eq!(split_event.amounts.len(), 1);
        
        // Test condition proof event
        let condition_event = ConditionProofVerified {
            condition_id: [30; 32],
            merkle_root: [40; 32],
            timestamp: base_time + 7,
        };
        assert_eq!(condition_event.condition_id, [30; 32]);
        assert_eq!(condition_event.merkle_root, [40; 32]);
    }
} 
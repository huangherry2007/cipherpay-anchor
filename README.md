# CipherPay Anchor Program

This is the Solana program for CipherPay, implemented using the Anchor framework. It handles the on-chain verification of zero-knowledge proofs for private payments.

## Features

- Zero-knowledge proof verification for:
  - Private transfers
  - Time-based streams
  - Payment splits
  - Conditional payments
  - Audit proofs
  - Withdrawals
- Merkle tree state management
- Compute budget optimization
- Event emission for tracking

## Zero-Knowledge Circuits

The Solana program supports all CipherPay circuits for comprehensive privacy-preserving operations:

### Core Circuits

#### Transfer Circuit (`verifier-transfer.json`)
- **Purpose**: Verifies private transfers between users
- **Instruction**: `verify_transfer_proof`
- **Inputs**: Input notes, output notes, recipient, amount, fee
- **Outputs**: Proof validity, new commitments, nullifiers

#### Merkle Circuit (`verifier-merkle.json`)
- **Purpose**: Verifies Merkle tree membership proofs
- **Instruction**: `verify_merkle_proof`
- **Inputs**: Leaf commitment, Merkle path, root
- **Outputs**: Proof validity

#### Nullifier Circuit (`verifier-nullifier.json`)
- **Purpose**: Generates and verifies nullifiers for spent notes
- **Instruction**: `verify_nullifier`
- **Inputs**: Note commitment, secret
- **Outputs**: Nullifier hash

### Specialized Circuits

#### ZK Stream Circuit (`verifier-zkStream.json`)
- **Purpose**: Verifies streaming payments with time-based release
- **Instruction**: `verify_stream_proof`
- **Inputs**: Commitment, recipient, start/end times, current time, amount
- **Outputs**: Stream validity, release amount

#### ZK Split Circuit (`verifier-zkSplit.json`)
- **Purpose**: Verifies payment splitting among multiple recipients
- **Instruction**: `verify_split_proof`
- **Inputs**: Input note, output notes, total amount
- **Outputs**: Split validity, individual amounts

#### ZK Condition Circuit (`verifier-zkCondition.json`)
- **Purpose**: Verifies conditional payments with various condition types
- **Instruction**: `verify_condition_proof`
- **Inputs**: Commitment, condition type, condition data, recipient, amount
- **Outputs**: Condition validity, payment eligibility

### Utility Circuits

#### Audit Proof Circuit (`verifier-audit_proof.json`)
- **Purpose**: Generates audit proofs for compliance
- **Instruction**: `verify_audit_proof`
- **Inputs**: Notes, view key, total amount, timestamp
- **Outputs**: Audit proof validity

#### Withdraw Circuit (`verifier-withdraw.json`)
- **Purpose**: Verifies withdrawals from private to public addresses
- **Instruction**: `verify_withdraw_proof`
- **Inputs**: Input notes, recipient, amount, fee
- **Outputs**: Withdrawal validity, public transfer

### Circuit Integration

All circuits are integrated into the Solana program using the following pattern:

```rust
// Example: Transfer verification
#[program]
pub mod cipherpay {
    pub fn verify_transfer_proof(
        ctx: Context<VerifyTransfer>,
        proof_a: [u64; 2],
        proof_b: [[u64; 2]; 2],
        proof_c: [u64; 2],
        public_inputs: [u64; 8],
    ) -> Result<()> {
        // Verify the zero-knowledge proof
        let is_valid = verify_groth16_proof(
            &ctx.accounts.verifier_state,
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
        )?;
        
        require!(is_valid, CipherPayError::InvalidProof);
        
        // Emit event
        emit!(TransferProofVerified {
            recipient: ctx.accounts.recipient.key(),
            amount: public_inputs[0],
        });
        
        Ok(())
    }
}
```

### Circuit Files Location

Circuit verification keys are stored in `src/zk/circuits/`:
- `verifier-transfer.json`
- `verifier-merkle.json`
- `verifier-nullifier.json`
- `verifier-zkStream.json`
- `verifier-zkSplit.json`
- `verifier-zkCondition.json`
- `verifier-audit_proof.json`
- `verifier-withdraw.json`

## Program Structure

### Accounts

- `VerifierState`: Main state account for the program
- `StreamState`: State account for stream verifications
- `SplitState`: State account for split verifications
- `ConditionState`: State account for condition verifications
- `AuditState`: State account for audit verifications
- `WithdrawState`: State account for withdrawal verifications

### Instructions

1. `initialize`: Initialize the program with a merkle root
2. `verify_transfer_proof`: Verify a transfer proof
3. `verify_merkle_proof`: Verify a Merkle tree proof
4. `verify_nullifier`: Verify a nullifier
5. `verify_stream_proof`: Verify a stream proof
6. `verify_split_proof`: Verify a split proof
7. `verify_condition_proof`: Verify a condition proof
8. `verify_audit_proof`: Verify an audit proof
9. `verify_withdraw_proof`: Verify a withdrawal proof

### Events

- `TransferProofVerified`: Emitted when a transfer proof is verified
- `MerkleProofVerified`: Emitted when a Merkle proof is verified
- `NullifierVerified`: Emitted when a nullifier is verified
- `StreamProofVerified`: Emitted when a stream proof is verified
- `SplitProofVerified`: Emitted when a split proof is verified
- `ConditionProofVerified`: Emitted when a condition proof is verified
- `AuditProofVerified`: Emitted when an audit proof is verified
- `WithdrawProofVerified`: Emitted when a withdrawal proof is verified

## Development

### Prerequisites

- Rust 1.70.0 or later
- Solana CLI tools
- Anchor Framework

### Building

```bash
anchor build
```

### Testing

```bash
anchor test
```

### Deployment

```bash
anchor deploy
```

## Security Considerations

- All proofs are verified on-chain
- Compute budget is checked for each operation
- State updates are atomic
- Error handling for all edge cases

## License

MIT
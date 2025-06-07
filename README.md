# CipherPay Anchor Program

This is the Solana program for CipherPay, implemented using the Anchor framework. It handles the on-chain verification of zero-knowledge proofs for private payments.

## Features

- Zero-knowledge proof verification for:
  - Private transfers
  - Time-based streams
  - Payment splits
- Merkle tree state management
- Compute budget optimization
- Event emission for tracking

## Program Structure

### Accounts

- `VerifierState`: Main state account for the program
- `StreamState`: State account for stream verifications
- `SplitState`: State account for split verifications

### Instructions

1. `initialize`: Initialize the program with a merkle root
2. `verify_transfer_proof`: Verify a transfer proof
3. `verify_stream_proof`: Verify a stream proof
4. `verify_split_proof`: Verify a split proof

### Events

- `ProofVerified`: Emitted when a transfer proof is verified
- `StreamProofVerified`: Emitted when a stream proof is verified
- `SplitProofVerified`: Emitted when a split proof is verified

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
# CipherPay Anchor Test Suite

This directory contains a comprehensive test suite for the CipherPay Anchor program, including unit tests, integration tests, and performance benchmarks.

## Test Structure

### Test Modules

- **`unit_tests.rs`** - Unit tests for utility functions and state management
- **`integration_tests.rs`** - Integration tests for full program flows
- **`zk_verifier_tests.rs`** - Tests for zero-knowledge proof verification
- **`error_tests.rs`** - Tests for error conditions and edge cases
- **`test_helpers.rs`** - Helper functions and mock data generators
- **`comprehensive_tests.rs`** - Comprehensive test suite using all modules
- **`lib.rs`** - Test library with utilities and configuration

### Test Categories

#### 1. Unit Tests
- State management (DepositMarker, Nullifier, MerkleRootCache)
- Utility functions (as_fixed_32, is_valid_root, etc.)
- Constants validation
- Error type completeness

#### 2. Integration Tests
- Complete deposit flow with atomicity validation
- Complete transfer flow with nullifier tracking
- Complete withdraw flow with SPL token transfers
- Error handling and edge cases
- Duplicate prevention mechanisms

#### 3. ZK Verifier Tests
- Proof parsing and validation
- Public signal extraction
- Verifying key deserialization
- Circuit-specific verification functions

#### 4. Error Tests
- Transaction validation failures
- Duplicate prevention
- Invalid input handling
- Edge case scenarios

#### 5. Performance Tests
- Merkle root cache operations
- Field element conversions
- Proof verification benchmarks

## Running Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test Categories
```bash
# Unit tests only
cargo test unit_tests

# Integration tests only
cargo test integration_tests

# ZK verifier tests only
cargo test zk_verifier_tests

# Error tests only
cargo test error_tests

# Comprehensive tests only
cargo test comprehensive_tests
```

### Run Tests with Logging
```bash
RUST_LOG=debug cargo test
```

### Run Tests with Backtrace
```bash
RUST_BACKTRACE=1 cargo test
```

### Run Tests in Release Mode
```bash
cargo test --release
```

## Test Configuration

### Environment Variables
- `RUST_LOG` - Set logging level (default: info)
- `RUST_BACKTRACE` - Enable backtrace (default: 0)

### Test Features
- `real-crypto` - Enable real cryptographic operations
- `memo` - Enable SPL Memo program integration

## Test Helpers

### Mock Data Generators
```rust
use cipherpay_anchor::tests::mock_data;

// Generate test data
let deposit_hash = mock_data::generate_deposit_hash();
let nullifier = mock_data::generate_nullifier();
let merkle_root = mock_data::generate_merkle_root();
let commitment = mock_data::generate_commitment();
let amount = mock_data::generate_amount();
```

### Test Scenarios
```rust
use cipherpay_anchor::tests::scenarios;

// Create test scenarios
let deposit_scenario = scenarios::DepositScenario::new();
let transfer_scenario = scenarios::TransferScenario::new();
let withdraw_scenario = scenarios::WithdrawScenario::new();
```

### Test Assertions
```rust
use cipherpay_anchor::tests::assertions;

// Assert transaction success/failure
assertions::assert_transaction_success(result);
assertions::assert_transaction_failure(result);

// Assert account states
assertions::assert_deposit_marker_processed(&mut banks_client, &deposit_marker_pda).await?;
assertions::assert_nullifier_used(&mut banks_client, &nullifier_pda).await?;
```

## Test Coverage

The test suite covers:

- ✅ All program instructions
- ✅ All state management functions
- ✅ All utility functions
- ✅ All error conditions
- ✅ All edge cases
- ✅ Performance benchmarks
- ✅ Integration flows
- ✅ ZK proof verification
- ✅ Atomicity validation
- ✅ Duplicate prevention

## Test Data

### Mock Proofs
- Valid proof structures (256 bytes)
- Invalid proof lengths
- Malformed proof data

### Mock Public Signals
- Deposit signals (6 fields)
- Transfer signals (9 fields)
- Withdraw signals (5 fields)
- Invalid signal counts

### Mock Accounts
- Deposit markers
- Nullifier records
- Merkle root caches
- SPL token accounts

## Performance Benchmarks

The test suite includes performance benchmarks for:

- Merkle root cache operations
- Field element conversions
- Proof verification
- State management operations

## Debugging Tests

### Enable Debug Logging
```rust
use cipherpay_anchor::tests::test_logging;

#[tokio::test]
async fn my_test() {
    test_logging::init();
    test_logging::log("Starting test");
    // ... test code ...
}
```

### Performance Monitoring
```rust
use cipherpay_anchor::tests::test_performance;

#[test]
fn my_benchmark() {
    let result = test_performance::measure("my_operation", || {
        // ... operation to measure ...
    });
}
```

## Test Utilities

### Common Test Functions
```rust
use cipherpay_anchor::tests::utils;

// Create test program
let program_test = utils::create_test_program();

// Create test transaction
let transaction = utils::create_test_transaction(
    instructions,
    &payer,
    &signers,
    recent_blockhash,
);

// Execute transaction
let result = utils::execute_transaction(&mut banks_client, transaction).await;
```

### Test Constants
```rust
use cipherpay_anchor::tests::test_constants;

let program_id = test_constants::TEST_PROGRAM_ID;
let deposit_hash = test_constants::TEST_DEPOSIT_HASH;
let nullifier = test_constants::TEST_NULLIFIER;
```

## Contributing

When adding new tests:

1. Follow the existing test structure
2. Use appropriate test helpers
3. Include both positive and negative test cases
4. Add performance benchmarks for new functions
5. Update this README if adding new test categories

## Troubleshooting

### Common Issues

1. **Test failures due to missing programs**
   - Ensure all required programs are added to the test setup
   - Check program IDs are correct

2. **Transaction failures**
   - Verify account setup is correct
   - Check instruction data and accounts
   - Ensure proper signing

3. **Performance test failures**
   - Check system resources
   - Verify benchmark parameters
   - Consider test environment differences

### Debug Commands

```bash
# Run with verbose output
cargo test -- --nocapture

# Run specific test with debug
RUST_LOG=debug cargo test test_name

# Run tests with backtrace
RUST_BACKTRACE=1 cargo test

# Run tests in single thread
cargo test -- --test-threads=1
```

### test procedures on localnet
step 1: start "solana-test-validator --reset"
step 2: anchor build -- --features real-crypto
step 3: anchor deploy
step 4:
export CP_TREE_DEPTH=16
export CP_HASH_VARIANT=poseidon
export CP_GENESIS_ROOT=0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323

ANCHOR_PROVIDER_URL=http://127.0.0.1:8899 \
ANCHOR_WALLET=~/.config/solana/id.json \
anchor run init
step 5: 
### deposit/deposit1/deposit2/deposit3
DEPOSIT_VARIANT=deposit npm run test:deposit

TRANSFER_VARIANT=transfer npm run test:transfer

WITHDRAW_VARIANT=withdraw npm run test:withdraw

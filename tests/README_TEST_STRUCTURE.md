# CipherPay Test Structure

## Test Organization

### 1. Rust Tests (`/tests/` directory)
**Purpose**: Program logic, unit testing, and comprehensive coverage
**When to run**: During development, CI/CD, and program validation

#### Unit Tests (`unit_tests.rs`)
- State management functions
- Utility functions
- Constants validation
- Error type completeness

#### Integration Tests (`integration_tests.rs`)
- Program instruction testing
- Account creation and management
- Basic flow validation

#### ZK Verifier Tests (`zk_verifier_tests.rs`)
- Proof parsing and validation
- Public signal extraction
- Verifying key deserialization

#### Error Tests (`error_tests.rs`)
- Error condition testing
- Edge case validation
- Transaction failure scenarios

#### Comprehensive Tests (`comprehensive_tests.rs`)
- End-to-end scenarios
- Performance benchmarks
- Mock data validation

### 2. TypeScript Tests (`/tests/` directory)
**Purpose**: Real program integration and client-side validation
**When to run**: Before deployment, integration testing, and production validation

#### Deposit Tests (`deposit.ts`)
- Real ZK proof verification
- Actual program deployment testing
- Client-side deposit flow validation

#### Transfer Tests (`transfer.ts`)
- Real transfer proof validation
- End-to-end transfer flow testing

#### Withdraw Tests (`withdraw.ts`)
- Real withdraw proof validation
- Token transfer validation

## Test Execution Strategy

### Development Phase
```bash
# Run Rust tests (fast, isolated)
cargo test

# Run specific Rust test categories
cargo test unit_tests
cargo test integration_tests
```

### Pre-Deployment Phase
```bash
# 1. Deploy program to local validator
solana-test-validator

# 2. Run TypeScript tests (real program)
npm test
# or
yarn test
```

### CI/CD Pipeline
```bash
# Stage 1: Rust tests (always run)
cargo test --release

# Stage 2: TypeScript tests (if program deployed)
npm run test:integration
```

## Test Data Requirements

### Rust Tests
- **Mock data**: Generated programmatically
- **No external files**: Self-contained
- **Fast execution**: No network calls

### TypeScript Tests
- **Real proof files**: `proofs/deposit_proof.bin`, etc.
- **Local validator**: Running Solana cluster
- **Deployed program**: Program must be deployed

## File Structure
```
tests/
├── README_TEST_STRUCTURE.md     # This file
├── lib.rs                       # Rust test library
├── unit_tests.rs                # Rust unit tests
├── integration_tests.rs         # Rust integration tests
├── zk_verifier_tests.rs         # Rust ZK tests
├── error_tests.rs               # Rust error tests
├── test_helpers.rs              # Rust test helpers
├── comprehensive_tests.rs       # Rust comprehensive tests
├── deposit.ts                   # TypeScript deposit tests
├── transfer.ts                  # TypeScript transfer tests
├── withdraw.ts                  # TypeScript withdraw tests
└── README.md                    # General test documentation
```

## When to Use Each Test Type

### Use Rust Tests For:
- ✅ Program logic validation
- ✅ Unit testing individual functions
- ✅ Error handling and edge cases
- ✅ Performance benchmarking
- ✅ State management testing
- ✅ Mock data validation
- ✅ CI/CD pipeline testing

### Use TypeScript Tests For:
- ✅ Real program integration
- ✅ Client-side workflow validation
- ✅ Actual ZK proof verification
- ✅ End-to-end user flows
- ✅ Production-like testing
- ✅ Pre-deployment validation

## Eliminating Duplication

### What's Duplicated:
- Basic instruction testing
- Account creation validation
- Basic flow testing

### What's Unique to Each:
- **Rust**: Mock data, unit testing, performance
- **TypeScript**: Real proofs, deployed program, client integration

### Optimization Strategy:
1. **Keep both** - they serve different purposes
2. **Focus Rust tests** on program logic and unit testing
3. **Focus TypeScript tests** on real integration and client workflows
4. **Remove redundant tests** from TypeScript that are better covered in Rust
5. **Add unique tests** to each category based on their strengths

## Recommended Changes

### TypeScript Tests Should Focus On:
- Real ZK proof verification
- Client-side integration
- End-to-end user workflows
- Production-like scenarios

### Rust Tests Should Focus On:
- Program logic validation
- Unit testing
- Error handling
- Performance testing
- Mock data validation

This approach eliminates duplication while maintaining comprehensive test coverage across both program logic and real-world integration scenarios.

# zkVerify Migration Guide

This guide documents the migration from custom Groth16 implementation to zkVerify integration in CipherPay Anchor.

## 🎯 Migration Overview

**Before**: Custom Groth16 implementation with security vulnerabilities and size constraints  
**After**: Secure zkVerify integration with proper on-chain verification

## ✅ Benefits of Migration

- **Security**: Battle-tested zkVerify program instead of custom implementation
- **Size**: No more 16MB program size constraints
- **Maintenance**: Shared infrastructure maintained by zkVerify team
- **Performance**: Optimized verification algorithms
- **Compatibility**: Standard Groth16 format support

## 🔄 Migration Steps

### Step 1: Generate Verification Key IDs

```bash
# In cipherpay-circuits directory
cd cipherpay-circuits

# Build circuits first
npm run setup

# Generate VK IDs
npm run generate-vk-ids
```

This creates `cipherpay-anchor/src/zk_verifier/vk_ids.rs` with actual VK IDs.

### Step 2: Update Your Anchor Program

The main program has been updated to use zkVerify CPI calls:

```rust
// Before: Custom verification
verify_deposit_groth16(&proof, &public_inputs)?;

// After: zkVerify CPI
let cpi_program = ctx.accounts.zkverify_program.to_account_info();
let cpi_accounts = zkverify::cpi::accounts::VerifyGroth16 {};
let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

let verify_args = zkverify::cpi::Groth16VerifyArgs {
    proof: proof.clone(),
    public_inputs: public_inputs.clone(),
    vk_id: vk_ids::DEPOSIT_VK_ID,
};

zkverify::cpi::verify_groth16(cpi_ctx, verify_args)?;
```

### Step 3: Update Context Structs

All shielded transaction contexts now include the zkVerify program:

```rust
#[derive(Accounts)]
pub struct ShieldedDeposit<'info> {
    // ... existing accounts ...
    
    /// zkVerify program for Groth16 proof verification
    /// CHECK: This is the zkVerify program ID
    pub zkverify_program: UncheckedAccount<'info>,
}
```

### Step 4: Test the Integration

```bash
# In cipherpay-anchor directory
cargo test zkverify-integration
```

## 🏗️ Architecture Changes

### Before (Custom Implementation)
```
User → Smart Contract → Custom Groth16 Verifier
                     ↓
                 Insecure verification
```

### After (zkVerify Integration)
```
User → Smart Contract → zkVerify Program
                     ↓
                 Secure, on-chain verification
```

## 🔐 Security Improvements

1. **No More Trust Assumptions**: zkVerify is battle-tested and audited
2. **Proper Verification**: Full Groth16 verification on-chain
3. **No Size Constraints**: Can handle complex circuits
4. **Standard Format**: Uses industry-standard proof formats

## 📝 API Changes

### Function Signatures
No changes to public function signatures - all existing calls will work.

### Account Contexts
All shielded transaction calls now require the `zkverify_program` account.

### Error Handling
- `InvalidProof`: Proof format validation failed
- `InvalidPublicInputs`: Public inputs format validation failed
- zkVerify errors: Will fail the transaction if verification fails

## 🧪 Testing

### Unit Tests
```bash
cargo test
```

### Integration Tests
```bash
cargo test zkverify-integration
```

### Manual Testing
1. Generate proofs using your circuits
2. Submit transactions through your program
3. Verify zkVerify integration works

## 🚀 Deployment

### Devnet/Testnet
```bash
# Deploy to devnet
anchor deploy --provider.cluster devnet
```

### Mainnet
```bash
# Deploy to mainnet
anchor deploy --provider.cluster mainnet
```

**Note**: Ensure zkVerify is available on your target network.

## 🔍 Verification

### Check zkVerify Integration
```bash
# Verify the program includes zkVerify calls
grep -r "zkverify" src/
```

### Check Program Size
```bash
# Build and check size
cargo build-bpf
ls -la target/deploy/*.so
```

### Check CPI Calls
```bash
# Verify CPI calls are properly structured
grep -r "CpiContext" src/
```

## 🐛 Troubleshooting

### Common Issues

1. **"zkverify_program account not found"**
   - Ensure you're passing the zkVerify program account in transactions
   - Use the correct program ID: `zkVeriFY4u7epfRDmVFezQ6HiXPKUeSJTCc6fpgpEHp`

2. **"Verification failed"**
   - Check proof format (minimum 192 bytes)
   - Check public inputs format (32 bytes per signal)
   - Verify VK ID matches your circuit

3. **"Program too large"**
   - Old custom implementation files should be removed
   - Check for remaining large dependencies

### Debug Commands

```bash
# Check program size
cargo build-bpf && ls -la target/deploy/*.so

# Verify zkVerify integration
grep -r "zkverify" src/

# Check for old custom files
find src/ -name "*custom*" -o -name "*arkworks*"
```

## 📚 Additional Resources

- [zkVerify Documentation](https://docs.zkverify.com)
- [Light Protocol](https://lightprotocol.com)
- [Groth16 Specification](https://eprint.iacr.org/2016/260.pdf)

## 🎉 Migration Complete!

After completing these steps, your CipherPay Anchor program will:

✅ Use secure zkVerify for on-chain verification  
✅ Have no program size constraints  
✅ Maintain the same public API  
✅ Provide better security guarantees  
✅ Be easier to maintain and upgrade  

## 🔄 Rollback Plan

If you need to rollback:

1. Restore the old `zk_verifier/` directory from git
2. Revert context changes
3. Remove zkVerify CPI calls
4. Test thoroughly

**Note**: Rolling back removes security improvements and may reintroduce size constraints.

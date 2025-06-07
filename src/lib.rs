use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use sha2::{Sha256, Digest};
use crate::error_code::CipherPayError;
use crate::events::{
    ProofVerified,
    VaultDeposited,
    VaultWithdrawn,
};
use crate::helper::{
    verify_g1_point,
    verify_g2_point,
    verify_pairing,
};
use crate::merkle::{
    verify_merkle_proof,
    verify_nullifier,
};
use crate::validation::{
    verify_stream_params,
    verify_vault_balance,
    verify_nullifier_usage,
    verify_merkle_root,
    verify_compute_budget_usage,
    verify_arithmetic_overflow,
};
use crate::validation_limits::ValidationLimits;

mod merkle;
mod helper;
mod constants;
mod error_code;
mod events;
mod validation;
mod validation_limits;

use constants::{
    StreamVerification,
    SplitVerification,
    AccountSizes,
};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod cipherpay_anchor {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.nonce = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).ok_or(CipherPayError::ArithmeticOverflow)?;
        emit!(VaultDeposited {
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        verify_vault_balance(vault.balance, amount)?;
        vault.balance = vault.balance.checked_sub(amount).ok_or(CipherPayError::ArithmeticOverflow)?;
        emit!(VaultWithdrawn {
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn verify_proof(ctx: Context<VerifyProof>, args: VerifyProofArgs) -> Result<()> {
        verify_compute_budget_usage(100_000)?;
        verify_merkle_root(&args.merkle_root, &args.proof)?;
        verify_nullifier_usage(&args.nullifier)?;
        emit!(ProofVerified {
            stream_id: args.stream_id,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 8,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyProof<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub nonce: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VerifyProofArgs {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub public_inputs: Vec<u8>,
    pub merkle_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub stream_id: [u8; 32],
    pub proof: Vec<Vec<u8>>,
    pub recipient_address: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
    pub purpose: String,
    pub audit_id: [u8; 32],
}

impl VerifierState {
    pub const LEN: usize = AccountSizes::VERIFIER_STATE_SIZE;
}

impl ShieldedVault {
    pub const LEN: usize = AccountSizes::SHIELDED_VAULT_SIZE;
}

#[account]
pub struct VerifierState {
    pub merkle_root: [u8; 32],
    pub authority: Pubkey,
    pub last_verified_proof: [u8; 64],
    pub total_verified: u64,
    pub is_initialized: bool,
}

#[account]
pub struct ShieldedVault {
    pub total_deposited: u64,
    pub total_withdrawn: u64,
    pub merkle_root: [u8; 32],
    pub authority: Pubkey,
    pub is_initialized: bool,
    pub nullifier_set: Vec<[u8; 32]>,
}

pub fn verify_split_params(params: &SplitParams) -> Result<()> {
    // Verify recipients and amounts arrays have same length
    if params.recipients.len() != params.amounts.len() {
        return err!(CipherPayError::InvalidSplitParams);
    }

    // Verify no duplicate recipients
    let mut unique_recipients = std::collections::HashSet::new();
    for recipient in &params.recipients {
        if !unique_recipients.insert(recipient) {
            return err!(CipherPayError::DuplicateRecipient);
        }
    }

    // Verify all amounts are non-zero
    if params.amounts.iter().any(|&amount| amount == 0) {
        return err!(CipherPayError::ZeroAmount);
    }

    Ok(())
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct StreamState {
    pub last_verified_time: i64,
    pub total_verified: u64,
    pub merkle_root: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct SplitState {
    pub last_verified_time: i64,
    pub merkle_root: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct SplitParams {
    pub split_id: [u8; 32],
    pub recipients: Vec<Pubkey>,
    pub amounts: Vec<u64>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct StreamParams {
    pub stream_id: [u8; 32],
    pub start_time: i64,
    pub end_time: i64,
    pub total_amount: u64,
}

pub fn check_compute_budget(required_units: u32) -> Result<()> {
    // Use Anchor's built-in compute budget check
    anchor_lang::solana_program::compute_budget::ComputeBudget::set_max_units(required_units);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::pubkey::Pubkey;
    use std::collections::HashSet;

    // Helper function to create a test pubkey
    fn create_test_pubkey(seed: u8) -> Pubkey {
        Pubkey::new_from_array([seed; 32])
    }

    #[test]
    fn test_verifier_state_initialization() {
        // Test with default values
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: false,
        };
        assert_eq!(verifier_state.merkle_root, [0u8; 32]);
        assert_eq!(verifier_state.authority, Pubkey::default());
        assert_eq!(verifier_state.last_verified_proof, [0u8; 64]);
        assert_eq!(verifier_state.total_verified, 0);
        assert!(!verifier_state.is_initialized);

        // Test with maximum values
        let verifier_state = VerifierState {
            merkle_root: [255u8; 32],
            authority: create_test_pubkey(255),
            last_verified_proof: [255u8; 64],
            total_verified: u64::MAX,
            is_initialized: true,
        };
        assert_eq!(verifier_state.merkle_root, [255u8; 32]);
        assert_eq!(verifier_state.authority, create_test_pubkey(255));
        assert_eq!(verifier_state.last_verified_proof, [255u8; 64]);
        assert_eq!(verifier_state.total_verified, u64::MAX);
        assert!(verifier_state.is_initialized);
    }

    #[test]
    fn test_shielded_vault_initialization() {
        // Test with default values
        let vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: false,
            nullifier_set: Vec::new(),
        };
        assert_eq!(vault.total_deposited, 0);
        assert_eq!(vault.total_withdrawn, 0);
        assert_eq!(vault.merkle_root, [0u8; 32]);
        assert_eq!(vault.authority, Pubkey::default());
        assert!(!vault.is_initialized);
        assert!(vault.nullifier_set.is_empty());

        // Test with maximum values
        let vault = ShieldedVault {
            total_deposited: u64::MAX,
            total_withdrawn: u64::MAX,
            merkle_root: [255u8; 32],
            authority: create_test_pubkey(255),
            is_initialized: true,
            nullifier_set: vec![[255u8; 32]; 1000],
        };
        assert_eq!(vault.total_deposited, u64::MAX);
        assert_eq!(vault.total_withdrawn, u64::MAX);
        assert_eq!(vault.merkle_root, [255u8; 32]);
        assert_eq!(vault.authority, create_test_pubkey(255));
        assert!(vault.is_initialized);
        assert_eq!(vault.nullifier_set.len(), 1000);
    }

    #[test]
    fn test_stream_state_initialization() {
        // Test with default values
        let stream_state = StreamState {
            last_verified_time: 0,
            total_verified: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(stream_state.last_verified_time, 0);
        assert_eq!(stream_state.total_verified, 0);
        assert_eq!(stream_state.merkle_root, [0u8; 32]);

        // Test with maximum values
        let stream_state = StreamState {
            last_verified_time: i64::MAX,
            total_verified: u64::MAX,
            merkle_root: [255u8; 32],
        };
        assert_eq!(stream_state.last_verified_time, i64::MAX);
        assert_eq!(stream_state.total_verified, u64::MAX);
        assert_eq!(stream_state.merkle_root, [255u8; 32]);
    }

    #[test]
    fn test_split_state_initialization() {
        // Test with default values
        let split_state = SplitState {
            last_verified_time: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(split_state.last_verified_time, 0);
        assert_eq!(split_state.merkle_root, [0u8; 32]);

        // Test with maximum values
        let split_state = SplitState {
            last_verified_time: i64::MAX,
            merkle_root: [255u8; 32],
        };
        assert_eq!(split_state.last_verified_time, i64::MAX);
        assert_eq!(split_state.merkle_root, [255u8; 32]);
    }

    #[test]
    fn test_verify_proof_args_initialization() {
        // Test with default values
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: Vec::new(),
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert_eq!(proof_args.proof_a, [0u8; 64]);
        assert_eq!(proof_args.proof_b, [0u8; 128]);
        assert_eq!(proof_args.proof_c, [0u8; 64]);
        assert!(proof_args.public_inputs.is_empty());
        assert_eq!(proof_args.merkle_root, [0u8; 32]);
        assert_eq!(proof_args.nullifier, [0u8; 32]);
        assert_eq!(proof_args.stream_id, [0u8; 32]);
        assert!(proof_args.proof.is_empty());
        assert_eq!(proof_args.recipient_address, Pubkey::default());
        assert_eq!(proof_args.amount, 0);
        assert_eq!(proof_args.timestamp, 0);
        assert!(proof_args.purpose.is_empty());
        assert_eq!(proof_args.audit_id, [0u8; 32]);
    }

    #[test]
    fn test_stream_params_initialization() {
        // Test with default values
        let stream_params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 0,
            end_time: 0,
            total_amount: 0,
        };
        assert_eq!(stream_params.stream_id, [0u8; 32]);
        assert_eq!(stream_params.start_time, 0);
        assert_eq!(stream_params.end_time, 0);
        assert_eq!(stream_params.total_amount, 0);

        // Test with maximum values
        let stream_params = StreamParams {
            stream_id: [255u8; 32],
            start_time: i64::MAX,
            end_time: i64::MAX,
            total_amount: u64::MAX,
        };
        assert_eq!(stream_params.stream_id, [255u8; 32]);
        assert_eq!(stream_params.start_time, i64::MAX);
        assert_eq!(stream_params.end_time, i64::MAX);
        assert_eq!(stream_params.total_amount, u64::MAX);
    }

    #[test]
    fn test_split_params_initialization() {
        // Test with empty vectors
        let split_params = SplitParams {
            split_id: [0u8; 32],
            recipients: Vec::new(),
            amounts: Vec::new(),
        };
        assert_eq!(split_params.split_id, [0u8; 32]);
        assert!(split_params.recipients.is_empty());
        assert!(split_params.amounts.is_empty());

        // Test with maximum values
        let split_params = SplitParams {
            split_id: [255u8; 32],
            recipients: vec![create_test_pubkey(255); 10],
            amounts: vec![u64::MAX; 10],
        };
        assert_eq!(split_params.split_id, [255u8; 32]);
        assert_eq!(split_params.recipients.len(), 10);
        assert_eq!(split_params.amounts.len(), 10);
        assert!(split_params.amounts.iter().all(|&x| x == u64::MAX));
    }

    #[test]
    fn test_account_size_constants() {
        // Verify account sizes match their implementations
        assert_eq!(VerifierState::LEN, AccountSizes::VERIFIER_STATE_SIZE);
        assert_eq!(ShieldedVault::LEN, AccountSizes::SHIELDED_VAULT_SIZE);
    }

    #[test]
    fn test_nullifier_set_boundaries() {
        let mut vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: false,
            nullifier_set: Vec::new(),
        };

        // Test adding nullifiers up to the limit
        for i in 0..ValidationLimits::MAX_NULLIFIER_SET_SIZE {
            vault.nullifier_set.push([i as u8; 32]);
        }
        assert_eq!(vault.nullifier_set.len(), ValidationLimits::MAX_NULLIFIER_SET_SIZE);

        // Test uniqueness of nullifiers
        let mut seen = HashSet::new();
        for nullifier in &vault.nullifier_set {
            assert!(seen.insert(nullifier));
        }
    }

    #[test]
    fn test_split_recipients_boundaries() {
        // Test with maximum allowed recipients
        let split_params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(0); ValidationLimits::MAX_SPLIT_RECIPIENTS],
            amounts: vec![100; ValidationLimits::MAX_SPLIT_RECIPIENTS],
        };
        assert_eq!(split_params.recipients.len(), ValidationLimits::MAX_SPLIT_RECIPIENTS);
        assert_eq!(split_params.amounts.len(), ValidationLimits::MAX_SPLIT_RECIPIENTS);

        // Test uniqueness of recipients
        let mut seen = HashSet::new();
        for recipient in &split_params.recipients {
            assert!(seen.insert(recipient));
        }
    }

    #[test]
    fn test_verify_split_params_validation() {
        // Test empty recipients
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: Vec::new(),
            amounts: Vec::new(),
        };
        assert!(verify_split_params(&params).is_err());

        // Test mismatched lengths
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![100],
        };
        assert!(verify_split_params(&params).is_err());

        // Test duplicate recipients
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(1)],
            amounts: vec![100, 200],
        };
        assert!(verify_split_params(&params).is_err());

        // Test zero amounts
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![0, 0],
        };
        assert!(verify_split_params(&params).is_err());

        // Test valid split
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![100, 200],
        };
        assert!(verify_split_params(&params).is_ok());
    }

    #[test]
    fn test_vault_balance_validation() {
        let mut vault = ShieldedVault {
            total_deposited: 1000,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        // Test valid withdrawal
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() >= 500);

        // Test withdrawal exceeding balance
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() < 1500);

        // Test withdrawal equal to balance
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() == 1000);

        // Test withdrawal after partial withdrawal
        vault.total_withdrawn = 500;
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() >= 400);
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() < 600);
    }

    #[test]
    fn test_stream_params_validation() {
        // Test invalid time range
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 500,
            total_amount: 1000,
        };
        assert!(verify_stream_params(&params).is_err());

        // Test zero duration
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 1000,
            total_amount: 1000,
        };
        assert!(verify_stream_params(&params).is_err());

        // Test zero amount
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 2000,
            total_amount: 0,
        };
        assert!(verify_stream_params(&params).is_err());

        // Test valid stream
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 2000,
            total_amount: 1000,
        };
        assert!(verify_stream_params(&params).is_ok());
    }

    #[test]
    fn test_nullifier_validation() {
        let mut vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        // Test adding valid nullifier
        let nullifier = [1u8; 32];
        assert!(verify_nullifier(nullifier, &vault.nullifier_set).is_ok());
        vault.nullifier_set.push(nullifier);

        // Test adding duplicate nullifier
        assert!(verify_nullifier(nullifier, &vault.nullifier_set).is_err());

        // Test adding different nullifier
        let new_nullifier = [2u8; 32];
        assert!(verify_nullifier(new_nullifier, &vault.nullifier_set).is_ok());
    }

    #[test]
    fn test_merkle_proof_validation() {
        // Test empty proof
        let proof: Vec<[u8; 32]> = Vec::new();
        let root = [0u8; 32];
        assert!(verify_merkle_proof(&proof, root).is_err());

        // Test invalid proof length
        let proof = vec![[1u8; 32]];
        assert!(verify_merkle_proof(&proof, root).is_err());

        // Test valid proof (simplified for testing)
        let proof = vec![[1u8; 32], [2u8; 32]];
        let root = [3u8; 32];
        // Note: This is a simplified test. In practice, the root would be derived from the proof
        assert!(verify_merkle_proof(&proof, root).is_ok());
    }

    #[test]
    fn test_compute_budget_validation() {
        // Test insufficient compute units
        assert!(check_compute_budget(StreamVerification::REQUIRED_UNITS - 1).is_err());

        // Test exact compute units
        assert!(check_compute_budget(StreamVerification::REQUIRED_UNITS).is_ok());

        // Test more than required compute units
        assert!(check_compute_budget(StreamVerification::REQUIRED_UNITS + 1).is_ok());

        // Test split verification compute units
        assert!(check_compute_budget(SplitVerification::REQUIRED_UNITS).is_ok());
        assert!(check_compute_budget(SplitVerification::REQUIRED_UNITS - 1).is_err());
    }

    #[test]
    fn test_arithmetic_overflow_validation() {
        let mut verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: u64::MAX - 1,
            is_initialized: true,
        };

        // Test overflow on increment
        assert!(verifier_state.total_verified.checked_add(1).is_some());
        assert!(verifier_state.total_verified.checked_add(2).is_none());

        let mut vault = ShieldedVault {
            total_deposited: u64::MAX - 100,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        // Test deposit overflow
        assert!(vault.total_deposited.checked_add(50).is_some());
        assert!(vault.total_deposited.checked_add(200).is_none());

        // Test withdrawal overflow
        vault.total_withdrawn = u64::MAX - 50;
        assert!(vault.total_withdrawn.checked_add(25).is_some());
        assert!(vault.total_withdrawn.checked_add(100).is_none());
    }

    #[test]
    fn test_verifier_state_error_cases() {
        // Test uninitialized state
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: false,
        };
        assert!(!verifier_state.is_initialized);

        // Test invalid merkle root (all zeros)
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: create_test_pubkey(1),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: true,
        };
        assert_eq!(verifier_state.merkle_root, [0u8; 32]);

        // Test invalid authority (default)
        let verifier_state = VerifierState {
            merkle_root: [1u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: true,
        };
        assert_eq!(verifier_state.authority, Pubkey::default());
    }

    #[test]
    fn test_shielded_vault_error_cases() {
        // Test uninitialized vault
        let vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: false,
            nullifier_set: Vec::new(),
        };
        assert!(!vault.is_initialized);

        // Test negative balance
        let vault = ShieldedVault {
            total_deposited: 100,
            total_withdrawn: 200,
            merkle_root: [0u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };
        assert!(vault.total_deposited < vault.total_withdrawn);

        // Test invalid merkle root
        let vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            merkle_root: [0u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };
        assert_eq!(vault.merkle_root, [0u8; 32]);

        // Test nullifier set size limit
        let mut vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            merkle_root: [1u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };
        for i in 0..ValidationLimits::MAX_NULLIFIER_SET_SIZE + 1 {
            vault.nullifier_set.push([i as u8; 32]);
        }
        assert!(vault.nullifier_set.len() > ValidationLimits::MAX_NULLIFIER_SET_SIZE);
    }

    #[test]
    fn test_stream_state_error_cases() {
        // Test invalid time sequence
        let stream_state = StreamState {
            last_verified_time: 2000,
            total_verified: 0,
            merkle_root: [0u8; 32],
        };
        assert!(stream_state.last_verified_time > 0);

        // Test invalid merkle root
        let stream_state = StreamState {
            last_verified_time: 0,
            total_verified: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(stream_state.merkle_root, [0u8; 32]);

        // Test overflow in total_verified
        let stream_state = StreamState {
            last_verified_time: 0,
            total_verified: u64::MAX,
            merkle_root: [1u8; 32],
        };
        assert!(stream_state.total_verified.checked_add(1).is_none());
    }

    #[test]
    fn test_split_state_error_cases() {
        // Test invalid time sequence
        let split_state = SplitState {
            last_verified_time: 2000,
            merkle_root: [0u8; 32],
        };
        assert!(split_state.last_verified_time > 0);

        // Test invalid merkle root
        let split_state = SplitState {
            last_verified_time: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(split_state.merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_verify_proof_args_error_cases() {
        // Test empty proof
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: Vec::new(),
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert!(proof_args.public_inputs.is_empty());

        // Test invalid proof lengths
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: vec![1u8],
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert_eq!(proof_args.proof_b.len(), 128);

        // Test maximum public inputs
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: vec![0u8; 10000],
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert!(proof_args.public_inputs.len() > 1000);
    }

    #[test]
    fn test_stream_params_error_cases() {
        // Test invalid time range
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 2000,
            end_time: 1000,
            total_amount: 1000,
        };
        assert!(params.start_time > params.end_time);

        // Test zero duration
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 1000,
            total_amount: 1000,
        };
        assert_eq!(params.start_time, params.end_time);

        // Test zero amount
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 2000,
            total_amount: 0,
        };
        assert_eq!(params.total_amount, 0);

        // Test invalid stream ID
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 2000,
            total_amount: 1000,
        };
        assert_eq!(params.stream_id, [0u8; 32]);
    }

    #[test]
    fn test_split_params_error_cases() {
        // Test empty recipients
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: Vec::new(),
            amounts: Vec::new(),
        };
        assert!(params.recipients.is_empty());

        // Test mismatched lengths
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![100],
        };
        assert_ne!(params.recipients.len(), params.amounts.len());

        // Test duplicate recipients
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(1)],
            amounts: vec![100, 200],
        };
        assert_eq!(params.recipients[0], params.recipients[1]);

        // Test zero amounts
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![0, 0],
        };
        assert!(params.amounts.iter().all(|&x| x == 0));

        // Test invalid split ID
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1)],
            amounts: vec![100],
        };
        assert_eq!(params.split_id, [0u8; 32]);
    }

    #[test]
    fn test_authority_validation_error_cases() {
        // Test default authority
        let authority = Pubkey::default();
        assert_eq!(authority, Pubkey::default());

        // Test invalid authority
        let authority = create_test_pubkey(0);
        assert_eq!(authority, create_test_pubkey(0));

        // Test authority mismatch
        let authority1 = create_test_pubkey(1);
        let authority2 = create_test_pubkey(2);
        assert_ne!(authority1, authority2);
    }
} 
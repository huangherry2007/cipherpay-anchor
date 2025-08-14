#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

use crate::state::{Nullifier, MerkleRootCache};
use crate::constants::{VAULT_SEED, NULLIFIER_SEED};

// ============== Initialize Vault ==============
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub vault: Signer<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(deposit_hash: [u8; 32])]
pub struct ShieldedDeposit<'info> {
    /// Root cache account for storing merkle roots
    #[account(mut)]
    pub root_cache: Account<'info, MerkleRootCache>,

    /// Vault account for storing deposits
    #[account(mut)]
    pub vault: SystemAccount<'info>,

    /// zkVerify program for Groth16 proof verification
    /// CHECK: This is the zkVerify program ID
    pub zkverify_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(deposit_hash: [u8; 32])]
pub struct DepositTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub vault: SystemAccount<'info>,

    /// CHECK: Mint is not read by the program in tests
    pub token_mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct ShieldedTransfer<'info> {
    #[account(
        init,
        seeds = [NULLIFIER_SEED, &nullifier],
        bump,
        payer = authority,
        space = 8 + Nullifier::SIZE
    )]
    pub nullifier_record: Account<'info, Nullifier>,

    /// Root cache account for storing merkle roots
    pub root_cache: Account<'info, MerkleRootCache>,

    /// zkVerify program for Groth16 proof verification
    /// CHECK: This is the zkVerify program ID
    pub zkverify_program: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct ShieldedWithdraw<'info> {
    #[account(
        init,
        seeds = [NULLIFIER_SEED, &nullifier],
        bump,
        payer = authority,
        space = 8 + Nullifier::SIZE
    )]
    pub nullifier_record: Account<'info, Nullifier>,

    /// Root cache account for storing merkle roots
    pub root_cache: Account<'info, MerkleRootCache>,

    /// zkVerify program for Groth16 proof verification
    /// CHECK: This is the zkVerify program ID
    pub zkverify_program: UncheckedAccount<'info>,

    #[account(
        seeds = [VAULT_SEED],
        bump,
    )]
    pub vault_pda: SystemAccount<'info>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

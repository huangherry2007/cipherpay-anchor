#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

use crate::state::{Nullifier, MerkleRootCache};

pub const VAULT_SEED: &[u8] = b"vault";
pub const NULLIFIER_SEED: &[u8] = b"nullifier";
pub const MERKLE_ROOT_CACHE_SEED: &[u8] = b"root_cache";

#[derive(Accounts)]
#[instruction(deposit_hash: [u8; 32])]
pub struct ShieldedDeposit<'info> {
    #[account(
        seeds = [MERKLE_ROOT_CACHE_SEED],
        bump,
        mut
    )]
    pub root_cache: Account<'info, MerkleRootCache>,

    #[account(
        seeds = [VAULT_SEED],
        bump,
    )]
    pub vault_pda: SystemAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(deposit_hash: [u8; 32])]
pub struct DepositTokens<'info> {
    #[account(
        seeds = [VAULT_SEED],
        bump,
    )]
    pub vault_pda: SystemAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut)]
    pub payer_token_account: Account<'info, TokenAccount>,

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
        payer = payer,
        space = 8 + Nullifier::SIZE
    )]
    pub nullifier_record: Account<'info, Nullifier>,

    #[account(
        seeds = [MERKLE_ROOT_CACHE_SEED],
        bump,
    )]
    pub root_cache: Account<'info, MerkleRootCache>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct ShieldedWithdraw<'info> {
    #[account(
        init,
        seeds = [NULLIFIER_SEED, &nullifier],
        bump,
        payer = payer,
        space = 8 + Nullifier::SIZE
    )]
    pub nullifier_record: Account<'info, Nullifier>,

    #[account(
        seeds = [MERKLE_ROOT_CACHE_SEED],
        bump,
    )]
    pub root_cache: Account<'info, MerkleRootCache>,

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
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

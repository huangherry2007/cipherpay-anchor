#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Token, TokenAccount};

use crate::constants::{DEPOSIT_MARKER_SEED, NULLIFIER_SEED, VAULT_SEED};
use crate::state::{DepositMarker, MerkleRootCache, Nullifier};

// ---------------- Init vault PDA (authority-held mint authority elsewhere) ---------------
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    /// PDA to be derived with VAULT_SEED; created off-chain or here if you prefer.
    #[account(mut)]
    pub vault: Signer<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// One-time init of the root cache account.
#[derive(Accounts)]
pub struct InitializeRootCache<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + MerkleRootCache::SIZE
    )]
    pub root_cache: Account<'info, MerkleRootCache>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// (Optional/no-op in your model) SPL token deposit helper
#[derive(Accounts)]
#[instruction(_deposit_hash: [u8;32])]
pub struct DepositTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub vault: SystemAccount<'info>,

    /// CHECK: mint not inspected in tests
    pub token_mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

/// Atomic shielded deposit (enforces SPL transfer + memo IN THE SAME TX).
#[derive(Accounts)]
#[instruction(deposit_hash: [u8; 32])]
pub struct ShieldedDepositAtomic<'info> {
    /// Payer for the CPI/lamports of the new marker.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Rolling cache of recent Merkle roots.
    #[account(mut)]
    pub root_cache: Account<'info, MerkleRootCache>,

    /// One per `deposit_hash` (idempotency). If it already exists, tx fails at init.
    // this must MATCH the IDL:
    #[account(
        init,
        payer = payer,
        seeds = [b"deposit", deposit_hash.as_ref()],   // ← include the arg
        bump,
        space = 8 + DepositMarker::SPACE
    )]
    pub deposit_marker: Account<'info, DepositMarker>,

    /// Program’s vault PDA (authority for the vault ATA).
    #[account(seeds = [VAULT_SEED], bump)]
    /// CHECK: PDA authority only; used as ATA authority + signer seeds.
    pub vault_pda: UncheckedAccount<'info>,

    /// Program’s vault ATA for this mint (must match the transfer seen in this tx).
    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = vault_pda
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// Mint of the deposited SPL token.
    /// CHECK: We only use its key for ATA constraint & sysvar checks.
    pub token_mint: UncheckedAccount<'info>,

    /// Instructions sysvar (to assert memo + transfer are in this same tx).
    /// CHECK: sysvar address is verified here.
    #[account(address = solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

/// Nullifier record for shielded transfer
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

    #[account(mut)]
    pub root_cache: Account<'info, MerkleRootCache>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Nullifier record + program vault for shielded withdraw
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

    #[account(mut)]
    pub root_cache: Account<'info, MerkleRootCache>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Program vault PDA (authority of the vault ATA).
    #[account(seeds = [VAULT_SEED], bump)]
    /// CHECK: PDA authority only for signing CPIs with seeds.
    pub vault_pda: UncheckedAccount<'info>,

    /// Program vault ATA for the mint being withdrawn.
    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = vault_pda
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// Recipient’s ATA for the same mint.
    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = recipient_owner
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,

    /// Owner of the recipient ATA (will receive funds).
    #[account(mut)]
    pub recipient_owner: Signer<'info>,

    /// Mint being withdrawn (must match both ATAs).
    /// CHECK: used for ATA constraints only.
    pub token_mint: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

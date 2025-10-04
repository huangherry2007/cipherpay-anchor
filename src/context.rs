// src/context.rs
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Token, TokenAccount};

use crate::constants::{DEPOSIT_MARKER_SEED, NULLIFIER_SEED, VAULT_SEED, TREE_SEED, ROOT_CACHE_SEED};
use crate::state::*;

/// Initialize the global Merkle tree state (one per deployment/cluster)
#[derive(Accounts)]
pub struct InitializeTreeState<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + TreeState::INIT_SPACE,   // keep whichever constant your state defines
        seeds = [TREE_SEED],
        bump
    )]
    pub tree: Account<'info, TreeState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

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
        space = 8 + MerkleRootCache::SIZE,
        seeds = [ROOT_CACHE_SEED],
        bump
    )]
    pub root_cache: AccountLoader<'info, MerkleRootCache>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(deposit_hash: Vec<u8>, proof_bytes: Vec<u8>, public_inputs_bytes: Vec<u8>)]
pub struct ShieldedDepositAtomic<'info> {
    #[account(mut, signer)]
    pub payer: Signer<'info>,

    // global tree
    #[account(mut, seeds = [TREE_SEED], bump)]
    pub tree: Account<'info, TreeState>,

    #[account(mut)]
    pub root_cache: AccountLoader<'info, MerkleRootCache>,

    #[account(
        init,
        payer = payer,
        space = DepositMarker::SPACE,
        seeds = [DEPOSIT_MARKER_SEED, deposit_hash.as_ref()],
        bump
    )]
    pub deposit_marker: Account<'info, DepositMarker>,

    /// CHECK: program vault PDA (authority)
    pub vault_pda: UncheckedAccount<'info>,

    /// CHECK: program’s vault ATA for this mint
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// CHECK: SPL mint
    pub token_mint: UncheckedAccount<'info>,

    /// CHECK: sysvar instructions
    pub instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

/// Spend one input (nullifier) and append two outputs.
/// Only `payer` signs (covers rent for the nullifier record).
#[derive(Accounts)]
#[instruction(nullifier: Vec<u8>, _proof: Vec<u8>, _publics: Vec<u8>)]
pub struct ShieldedTransfer<'info> {
    /// Fee payer / only signer.
    #[account(mut, signer)]
    pub payer: Signer<'info>,

    /// Global Merkle tree (strict sync with proof’s spent root).
    #[account(mut, seeds = [TREE_SEED], bump)]
    pub tree: Account<'info, TreeState>,

    /// Rolling cache of recent roots (zero-copy account).
    #[account(mut, seeds = [ROOT_CACHE_SEED], bump)]
    pub root_cache: AccountLoader<'info, MerkleRootCache>,

    /// Per-nullifier one-shot PDA; prevents double-spends.
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + NullifierRecord::SIZE,   // or ::SPACE if you defined it
        seeds = [NULLIFIER_SEED, nullifier.as_ref()],  // <- use the *instruction arg* bytes
        bump
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,

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
        space = 8 + NullifierRecord::SIZE
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,

    #[account(mut)]
    pub root_cache: AccountLoader<'info, MerkleRootCache>,

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

//! CipherPay Anchor Program (atomic deposit + zk verification)
//! src/lib.rs

#![allow(unexpected_cfgs)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
#[cfg(feature = "real-crypto")]
use anchor_spl::token::{self, Transfer as SplTransfer};

use crate::constants::{DEPOSIT_MARKER_SEED, VAULT_SEED, TREE_SEED};
use crate::context::*;
use crate::error::CipherPayError;
use crate::event::*;
use crate::utils::{
    assert_memo_in_same_tx,
    assert_transfer_checked_in_same_tx,
    insert_merkle_root,
    insert_many_roots,
    is_valid_root,
};

#[cfg(feature = "real-crypto")]
use crate::zk_verifier::solana_verifier;

declare_id!("9dsJPKp8Z6TBtfbhHu1ssE8KSUMWUNUFAXy8SUxMuf9o");

pub mod constants;
pub mod context;
pub mod error;
pub mod event;
pub mod state;
pub mod utils;
pub mod zk_verifier;

fn fe32_to_u32_le(fe: [u8; 32]) -> u32 {
    u32::from_le_bytes([fe[0], fe[1], fe[2], fe[3]])
}

#[program]
#[allow(deprecated)]
pub mod cipherpay_anchor {
    use super::*;

    #[cfg(feature = "real-crypto")]
    use crate::zk_verifier::solana_verifier::{deposit_idx, transfer_idx, withdraw_idx};

    // For builds without `real-crypto`, provide indices so the code compiles.
    #[cfg(not(feature = "real-crypto"))]
    mod stub_idx {
        pub mod deposit_idx {
            pub const NEW_COMMITMENT: usize = 0;
            pub const OWNER_CIPHERPAY_PUBKEY: usize = 1;
            pub const NEW_MERKLE_ROOT: usize = 2;
            pub const NEW_NEXT_LEAF_INDEX: usize = 3;
            pub const AMOUNT: usize = 4;
            pub const DEPOSIT_HASH: usize = 5;
            pub const OLD_MERKLE_ROOT: usize = 6;
        }
        pub mod transfer_idx {
            pub const OUT_COMMITMENT_1: usize = 0;
            pub const OUT_COMMITMENT_2: usize = 1;
            pub const NULLIFIER: usize = 2;
            pub const MERKLE_ROOT: usize = 3;
            pub const NEW_MERKLE_ROOT_1: usize = 4;
            pub const NEW_MERKLE_ROOT_2: usize = 5;
            pub const NEW_NEXT_LEAF_INDEX: usize = 6;
            pub const ENC_NOTE1_HASH: usize = 7;
            pub const ENC_NOTE2_HASH: usize = 8;
        }
        pub mod withdraw_idx {
            pub const NULLIFIER: usize = 0;
            pub const MERKLE_ROOT: usize = 1;
            pub const RECIPIENT_WALLET_PUBKEY: usize = 2;
            pub const AMOUNT: usize = 3;
            pub const TOKEN_ID: usize = 4;
        }
    }
    #[cfg(not(feature = "real-crypto"))]
    use stub_idx::{deposit_idx, transfer_idx, withdraw_idx};

    pub fn initialize_vault(_ctx: Context<InitializeVault>) -> Result<()> {
        Ok(())
    }

    /// Create an empty Merkle root cache.
    pub fn initialize_root_cache(ctx: Context<InitializeRootCache>) -> Result<()> {
        ctx.accounts.root_cache.roots = Vec::new();
        Ok(())
    }

    pub fn initialize_tree_state(ctx: Context<InitializeTreeState>, depth: u8, genesis_root: [u8;32]) -> Result<()> {
        let t = &mut ctx.accounts.tree;
        t.version      = 1;
        t.depth        = depth;
        t.current_root = genesis_root;
        t.next_index   = 0;
        Ok(())
    }

    /// Optional SPL hook (no-op in your current design)
    pub fn deposit_tokens(_ctx: Context<DepositTokens>, _deposit_hash: Vec<u8>) -> Result<()> {
        Ok(())
    }

    /// Atomic deposit: Memo(deposit_hash) + SPL TransferChecked to vault ATA in the *same* tx,
    /// then accept zk-proof and roll the Merkle root forward.
    pub fn shielded_deposit_atomic(
        ctx: Context<ShieldedDepositAtomic>,
        deposit_hash: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(deposit_hash.len() == 32, CipherPayError::InvalidInput);
        let mut deposit_hash32 = [0u8; 32];
        deposit_hash32.copy_from_slice(&deposit_hash);

        let marker = &mut ctx.accounts.deposit_marker;
        if marker.processed {
            return Ok(());
        }
        marker.bump = ctx.bumps.deposit_marker;

        #[cfg(feature = "real-crypto")]
        {
            solana_verifier::verify_deposit(&proof_bytes, &public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;

            let sigs = solana_verifier::parse_public_signals_exact(&public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;

            let new_commitment        = sigs[deposit_idx::NEW_COMMITMENT];
            let owner_cipherpay_pk    = sigs[deposit_idx::OWNER_CIPHERPAY_PUBKEY];
            let new_root              = sigs[deposit_idx::NEW_MERKLE_ROOT];
            let new_next_leaf_index   = sigs[deposit_idx::NEW_NEXT_LEAF_INDEX];
            let amount_fe             = sigs[deposit_idx::AMOUNT];
            let expected_deposit_hash = sigs[deposit_idx::DEPOSIT_HASH];
            let old_root              = sigs[deposit_idx::OLD_MERKLE_ROOT]; // <— NEW

            require!(expected_deposit_hash == deposit_hash32, CipherPayError::InvalidZkProof);

            // FE (LE) -> u64
            let mut amount_u64: u64 = 0;
            for i in 0..8 { amount_u64 |= (amount_fe[i] as u64) << (8*i); }

            // Atomicity with the SPL tx in the same transaction
            assert_memo_in_same_tx(&ctx.accounts.instructions, &deposit_hash32)?;
            assert_transfer_checked_in_same_tx(
                &ctx.accounts.instructions,
                &ctx.accounts.vault_token_account.key(),
                amount_u64,
            )?;

            // Single-history checks
            require!(old_root == ctx.accounts.tree.current_root, CipherPayError::OldRootMismatch);
            let sig_next = u32::from_le_bytes([new_next_leaf_index[0], new_next_leaf_index[1], new_next_leaf_index[2], new_next_leaf_index[3]]);
            require!(sig_next == ctx.accounts.tree.next_index + 1, CipherPayError::InvalidInput);

            // State updates
            ctx.accounts.tree.current_root = new_root;
            ctx.accounts.tree.next_index   = sig_next;

            insert_merkle_root(&new_root, &mut ctx.accounts.root_cache);

            marker.processed = true;
            emit!(DepositCompleted {
                deposit_hash: deposit_hash32,
                owner_cipherpay_pubkey: owner_cipherpay_pk,
                commitment: new_commitment,
                old_merkle_root: old_root,        // <— include in event
                new_merkle_root: new_root,
                next_leaf_index: sig_next,
                mint: ctx.accounts.token_mint.key(),
            });
        }

        #[cfg(not(feature = "real-crypto"))]
        {
            assert_memo_in_same_tx(&ctx.accounts.instructions, &deposit_hash32)?;
            assert_transfer_checked_in_same_tx(
                &ctx.accounts.instructions,
                &ctx.accounts.vault_token_account.key(),
                0,
            )?;

            // For stub builds, still bump the cursor deterministically.
            ctx.accounts.tree.next_index = ctx.accounts.tree.next_index.saturating_add(1);

            marker.processed = true;
            emit!(DepositCompleted {
                deposit_hash: deposit_hash32,
                owner_cipherpay_pubkey: [0u8; 32],
                commitment: [0u8; 32],
                old_merkle_root: [0u8; 32],
                new_merkle_root: [0u8; 32],
                next_leaf_index: ctx.accounts.tree.next_index,
                mint: ctx.accounts.token_mint.key(),
            });
        }

        Ok(())
    }

    pub fn shielded_transfer(
        ctx: Context<ShieldedTransfer>,
        nullifier: [u8; 32],
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        #[cfg(feature = "real-crypto")]
        {
            // 0) Verify the ZK proof and parse public signals in *exact* circuit order
            solana_verifier::verify_transfer(&proof_bytes, &public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;
            let sigs = solana_verifier::parse_public_signals_exact(&public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;

            let out1_commitment     = sigs[transfer_idx::OUT_COMMITMENT_1];
            let out2_commitment     = sigs[transfer_idx::OUT_COMMITMENT_2];
            let nf_from_snark       = sigs[transfer_idx::NULLIFIER];
            let merkle_root_before  = sigs[transfer_idx::MERKLE_ROOT];
            let new_root1           = sigs[transfer_idx::NEW_MERKLE_ROOT_1];
            let new_root2           = sigs[transfer_idx::NEW_MERKLE_ROOT_2];
            let new_next_leaf_index = sigs[transfer_idx::NEW_NEXT_LEAF_INDEX];
            let enc1                = sigs[transfer_idx::ENC_NOTE1_HASH];
            let enc2                = sigs[transfer_idx::ENC_NOTE2_HASH];

            // 1) Nullifier must match argument and be unused
            require!(nf_from_snark == nullifier, CipherPayError::NullifierMismatch);
            let rec = &mut ctx.accounts.nullifier_record;
            require!(!rec.used, CipherPayError::NullifierAlreadyUsed);
            rec.used = true;
            rec.bump = ctx.bumps.nullifier_record;

            // 2) STRICT sync check: spent root must equal on-chain current root
            let tree = &mut ctx.accounts.tree;
            require!(
                merkle_root_before == tree.current_root,
                CipherPayError::OldRootMismatch
            );

            // 3) Index transition check: new_next = old_next + 2 (and within depth)
            let old_next = tree.next_index;
            let new_next = fe32_to_u32_le(new_next_leaf_index);
            let max_leaves: u64 = 1u64 << (tree.depth as u32);
            require!((new_next as u64) <= max_leaves, CipherPayError::InvalidInput);
            require!(
                new_next == old_next.checked_add(2).ok_or_else(|| error!(CipherPayError::ArithmeticError))?,
                CipherPayError::NextLeafIndexMismatch
            );

            // 4) Advance the tree state atomically
            tree.current_root = new_root2;
            tree.next_index   = new_next;

            // 5) Add the two new roots to the cache (useful for withdraw)
            insert_many_roots(&[new_root1, new_root2], &mut ctx.accounts.root_cache);

            // 6) Emit event
            emit!(TransferCompleted {
                nullifier,
                out1_commitment,
                out2_commitment,
                enc_note1_hash: enc1,
                enc_note2_hash: enc2,
                merkle_root_before,
                new_merkle_root1: new_root1,
                new_merkle_root2: new_root2,
                next_leaf_index: new_next,
                mint: Pubkey::default(),
            });
        }

        #[cfg(not(feature = "real-crypto"))]
        {
            let rec = &mut ctx.accounts.nullifier_record;
            require!(!rec.used, CipherPayError::NullifierAlreadyUsed);
            rec.used = true;
            rec.bump = ctx.bumps.nullifier_record;

            emit!(TransferCompleted {
                nullifier,
                out1_commitment: [0u8; 32],
                out2_commitment: [0u8; 32],
                enc_note1_hash: [0u8; 32],
                enc_note2_hash: [0u8; 32],
                merkle_root_before: [0u8; 32],
                new_merkle_root1: [0u8; 32],
                new_merkle_root2: [0u8; 32],
                next_leaf_index: 0,
                mint: Pubkey::default(),
            });
        }

        Ok(())
    }

    /// Spend one note, withdraw SPL tokens from the program’s vault ATA to the recipient.
    pub fn shielded_withdraw(
        ctx: Context<ShieldedWithdraw>,
        nullifier: [u8; 32],
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        #[cfg(feature = "real-crypto")]
        {
            solana_verifier::verify_withdraw(&proof_bytes, &public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;
            let sigs = solana_verifier::parse_public_signals_exact(&public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;

            let nf_from_snark = sigs[withdraw_idx::NULLIFIER];
            let merkle_root   = sigs[withdraw_idx::MERKLE_ROOT];
            let recipient_pk  = sigs[withdraw_idx::RECIPIENT_WALLET_PUBKEY];
            let amount_fe     = sigs[withdraw_idx::AMOUNT];
            let _token_id     = sigs[withdraw_idx::TOKEN_ID];

            require!(nf_from_snark == nullifier, CipherPayError::NullifierMismatch);

            let rec = &mut ctx.accounts.nullifier_record;
            require!(!rec.used, CipherPayError::NullifierAlreadyUsed);
            rec.used = true;
            rec.bump = ctx.bumps.nullifier_record;

            require!(is_valid_root(&merkle_root, &ctx.accounts.root_cache), CipherPayError::UnknownMerkleRoot);

            // FE (LE) -> u64
            let mut amount: u64 = 0;
            for i in 0..8 { amount |= (amount_fe[i] as u64) << (8 * i); }

            // Transfer SPL from program vault ATA to recipient ATA.
            let cpi_accounts = SplTransfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.vault_pda.to_account_info(),
            };

            let bump = ctx.bumps.vault_pda;
            let seeds: &[&[u8]] = &[VAULT_SEED, &[bump]];
            let signer: &[&[&[u8]]] = &[seeds];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer,
            );
            token::transfer(cpi_ctx, amount).map_err(|_| error!(CipherPayError::TokenTransferFailed))?;

            emit!(WithdrawCompleted {
                nullifier,
                recipient: ctx.accounts.recipient_owner.key(),
                amount,
                mint: ctx.accounts.token_mint.key(),
            });
        }

        #[cfg(not(feature = "real-crypto"))]
        {
            let rec = &mut ctx.accounts.nullifier_record;
            require!(!rec.used, CipherPayError::NullifierAlreadyUsed);
            rec.used = true;
            rec.bump = ctx.bumps.nullifier_record;

            emit!(WithdrawCompleted {
                nullifier,
                recipient: ctx.accounts.recipient_owner.key(),
                amount: 0,
                mint: ctx.accounts.token_mint.key(),
            });
        }

        Ok(())
    }
}
//! CipherPay Anchor Program (atomic deposit + zk verification)

#![allow(unexpected_cfgs)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
#[cfg(feature = "real-crypto")]
use anchor_spl::token::{self, Transfer as SplTransfer};

use crate::constants::{DEPOSIT_MARKER_SEED, VAULT_SEED};
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

#[cfg(feature = "debug-seeds")]
use anchor_lang::solana_program::pubkey::Pubkey;

declare_id!("9dsJPKp8Z6TBtfbhHu1ssE8KSUMWUNUFAXy8SUxMuf9o");

pub mod constants;
pub mod context;
pub mod error;
pub mod event;
pub mod state;
pub mod utils;
pub mod zk_verifier;

#[program]
#[allow(deprecated)]
pub mod cipherpay_anchor {
    use super::*;
    #[cfg(feature = "real-crypto")]
    use crate::zk_verifier::solana_verifier::{deposit_idx, transfer_idx, withdraw_idx};
    #[cfg(not(feature = "real-crypto"))]
    mod stub_idx {
        pub mod deposit_idx {
            pub const NEW_COMMITMENT: usize = 0;
            pub const OWNER_CIPHERPAY_PUBKEY: usize = 1;
            pub const NEW_MERKLE_ROOT: usize = 2;
            pub const NEW_NEXT_LEAF_INDEX: usize = 3;
            pub const AMOUNT: usize = 4;
            pub const DEPOSIT_HASH: usize = 5;
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

    /// Optional SPL hook (no-op in your current design)
    pub fn deposit_tokens(_ctx: Context<DepositTokens>, _deposit_hash: Vec<u8>) -> Result<()> {
        Ok(())
    }

    /// Atomic deposit: enforces Memo(deposit_hash) + SPL TransferChecked to the vault ATA
    /// in the *same* transaction, then accepts the zk-proof and rolls the Merkle root forward.
    pub fn shielded_deposit_atomic(
        ctx: Context<ShieldedDepositAtomic>,
        deposit_hash: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        // Validate and normalize the deposit hash first.
        require!(deposit_hash.len() == 32, CipherPayError::InvalidInput);
        let mut deposit_hash32 = [0u8; 32];
        deposit_hash32.copy_from_slice(&deposit_hash);

        // ───────────────────── DEBUG-SEEDS PATH ─────────────────────
        // In this mode we DO NOT mutate accounts. We only print PDA candidates
        // computed on-chain, then return an error so you can read the logs.
        #[cfg(feature = "debug-seeds")]
        {
            msg!("🔬 [debug-seeds] program_id: {}", ctx.program_id);

            // hex string without extra deps
            let mut hex = String::with_capacity(64);
            for b in deposit_hash32.iter() {
                use core::fmt::Write;
                let _ = write!(&mut hex, "{:02x}", b);
            }
            msg!("🔬 deposit_hash (LE, hex) = {}", hex);

            let (pda_raw, bump_raw) =
                Pubkey::find_program_address(&[DEPOSIT_MARKER_SEED, &deposit_hash32], ctx.program_id);
            let mut dh_rev = deposit_hash32;
            dh_rev.reverse();
            let (pda_rev, bump_rev) =
                Pubkey::find_program_address(&[DEPOSIT_MARKER_SEED, &dh_rev], ctx.program_id);
            let (pda_empty, bump_empty) =
                Pubkey::find_program_address(&[DEPOSIT_MARKER_SEED], ctx.program_id);

            let seed_txt = core::str::from_utf8(DEPOSIT_MARKER_SEED).unwrap_or("<bin>");
            msg!("🔬 expected PDA (seed=[\"{}\", 32 raw])    = {} (bump {})", seed_txt, pda_raw, bump_raw);
            msg!("🔬 expected PDA (seed=[\"{}\", 32 rev])    = {} (bump {})", seed_txt, pda_rev, bump_rev);
            msg!("🔬 expected PDA (seed=[\"{}\"])            = {} (bump {})", seed_txt, pda_empty, bump_empty);
            msg!("🔬 provided deposit_marker account         = {}", ctx.accounts.deposit_marker.key());

            // Also print the order of all accounts Anchor passed to the ix, for sanity.
            // (Indices mirror your TS logs.)
            msg!("🔎 accounts (as seen by program):");
            msg!("  [payer]                {}", ctx.accounts.payer.key());
            msg!("  [root_cache]           {}", ctx.accounts.root_cache.key());
            msg!("  [deposit_marker]       {}", ctx.accounts.deposit_marker.key());
            msg!("  [vault_pda]            {}", ctx.accounts.vault_pda.key());
            msg!("  [vault_token_account]  {}", ctx.accounts.vault_token_account.key());
            msg!("  [token_mint]           {}", ctx.accounts.token_mint.key());
            msg!("  [instructions]         {}", ctx.accounts.instructions.key());
            msg!("  [system_program]       {}", ctx.accounts.system_program.key());
            msg!("  [token_program]        {}", ctx.accounts.token_program.key());
            msg!("  [associated_token_prog]{}", ctx.accounts.associated_token_program.key());

            // Keep going: verify memo + SPL transfer, then succeed (no state writes).
            assert_memo_in_same_tx(&ctx.accounts.instructions, &deposit_hash32)?;
            // In stub/debug builds, expected_amount=0 means "wildcard" (see utils.rs).
            assert_transfer_checked_in_same_tx(
                &ctx.accounts.instructions,
                &ctx.accounts.vault_token_account.key(),
                0,
            )?;
            msg!("✅ [debug-seeds] memo + SPL transfer present; finishing OK (no marker writes)");
            return Ok(());
        }

        // ───────────────────── NORMAL PATH ─────────────────────
        // Here Anchor enforces the seeds; we update the deposit_marker and root cache.
        #[cfg(not(feature = "debug-seeds"))]
        {
            let marker = &mut ctx.accounts.deposit_marker;
            if marker.processed {
                // idempotent no-op
                return Ok(());
            }
            marker.bump = ctx.bumps.deposit_marker;

            #[cfg(feature = "real-crypto")]
            {
                // 1) Verify the zk proof
                solana_verifier::verify_deposit(&proof_bytes, &public_inputs_bytes)
                    .map_err(|_| error!(CipherPayError::InvalidZkProof))?;

                // 2) Parse public signals (order: newCommitment, ownerKey, newRoot, newNextIndex, amount, depositHash)
                let sigs = solana_verifier::parse_public_signals_exact(&public_inputs_bytes)
                    .map_err(|_| error!(CipherPayError::InvalidZkProof))?;
                let new_commitment        = sigs[deposit_idx::NEW_COMMITMENT];
                let owner_cipherpay_pk    = sigs[deposit_idx::OWNER_CIPHERPAY_PUBKEY];
                let new_root              = sigs[deposit_idx::NEW_MERKLE_ROOT];
                let new_next_leaf_index   = sigs[deposit_idx::NEW_NEXT_LEAF_INDEX];
                let amount_fe             = sigs[deposit_idx::AMOUNT];
                let expected_deposit_hash = sigs[deposit_idx::DEPOSIT_HASH];

                // 3) The hash bound inside the proof must match instruction arg
                require!(expected_deposit_hash == deposit_hash32, CipherPayError::InvalidZkProof);

                // 4) Convert amount field element -> u64 (LE first 8 bytes)
                let mut amount_u64: u64 = 0;
                for i in 0..8 { amount_u64 |= (amount_fe[i] as u64) << (8*i); }

                // 5) ENFORCE atomicity:
                //    (a) the tx carries a Memo with EXACT deposit_hash bytes
                assert_memo_in_same_tx(&ctx.accounts.instructions, &deposit_hash32)?;
                //    (b) the tx carries an SPL Transfer/TransferChecked TO our vault ATA with EXACT amount
                assert_transfer_checked_in_same_tx(
                    &ctx.accounts.instructions,
                    &ctx.accounts.vault_token_account.key(),
                    amount_u64,
                )?;

                // 6) Update root cache and mark idempotent processed
                insert_merkle_root(&new_root, &mut ctx.accounts.root_cache);
                marker.processed = true;

                // 7) Emit
                emit!(DepositCompleted {
                    deposit_hash: deposit_hash32,
                    owner_cipherpay_pubkey: owner_cipherpay_pk,
                    commitment: new_commitment,
                    new_merkle_root: new_root,
                    next_leaf_index: u32::from_le_bytes([
                        new_next_leaf_index[0], new_next_leaf_index[1],
                        new_next_leaf_index[2], new_next_leaf_index[3]
                    ]),
                    mint: ctx.accounts.token_mint.key(),
                });
            }

            #[cfg(not(feature = "real-crypto"))]
            {
                // In stub mode, still enforce memo + presence of transfer (amount = 0 ok)
                assert_memo_in_same_tx(&ctx.accounts.instructions, &deposit_hash32)?;
                assert_transfer_checked_in_same_tx(
                    &ctx.accounts.instructions,
                    &ctx.accounts.vault_token_account.key(),
                    0,
                )?;

                marker.processed = true;
                emit!(DepositCompleted {
                    deposit_hash: deposit_hash32,
                    owner_cipherpay_pubkey: [0u8; 32],
                    commitment: [0u8; 32],
                    new_merkle_root: [0u8; 32],
                    next_leaf_index: 0,
                    mint: ctx.accounts.token_mint.key(),
                });
            }

            Ok(())
        }
    }

    /// Spend one note, create two, update Merkle roots (no SPL I/O).
    pub fn shielded_transfer(
        ctx: Context<ShieldedTransfer>,
        nullifier: [u8; 32],
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        #[cfg(feature = "real-crypto")]
        {
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

            require!(nf_from_snark == nullifier, CipherPayError::NullifierMismatch);

            // consume nullifier
            let rec = &mut ctx.accounts.nullifier_record;
            require!(!rec.used, CipherPayError::NullifierAlreadyUsed);
            rec.used = true;
            rec.bump = ctx.bumps.nullifier_record;

            // check known root and roll forward
            require!(
                is_valid_root(&merkle_root_before, &ctx.accounts.root_cache),
                CipherPayError::UnknownMerkleRoot
            );
            insert_many_roots(&[new_root1, new_root2], &mut ctx.accounts.root_cache);

            emit!(TransferCompleted {
                nullifier,
                out1_commitment,
                out2_commitment,
                enc_note1_hash: enc1,
                enc_note2_hash: enc2,
                merkle_root_before,
                new_merkle_root1: new_root1,
                new_merkle_root2: new_root2,
                next_leaf_index: u32::from_le_bytes([
                    new_next_leaf_index[0], new_next_leaf_index[1],
                    new_next_leaf_index[2], new_next_leaf_index[3]
                ]),
                mint: Pubkey::default(), // TODO: add mint to context if needed
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
            let _token_id     = sigs[withdraw_idx::TOKEN_ID]; // map to mint for multi-mint support

            require!(nf_from_snark == nullifier, CipherPayError::NullifierMismatch);

            let rec = &mut ctx.accounts.nullifier_record;
            require!(!rec.used, CipherPayError::NullifierAlreadyUsed);
            rec.used = true;
            rec.bump = ctx.bumps.nullifier_record;

            require!(is_valid_root(&merkle_root, &ctx.accounts.root_cache), CipherPayError::UnknownMerkleRoot);

            // FE (little-endian) -> u64
            let mut amount: u64 = 0;
            for i in 0..8 {
                amount |= (amount_fe[i] as u64) << (8 * i);
            }

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

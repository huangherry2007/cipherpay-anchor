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

declare_id!("56nPWpjBLbh1n8vvUdCYGmg3dS5zNwLW9UhCg4MMpBmN");

pub mod constants;
pub mod context;
pub mod error;
pub mod event;
pub mod state;
pub mod utils;
pub mod zk_verifier;

fn parse_transfer_publics(bytes: &[u8]) -> Result<[[u8; 32]; 9]> {
    require!(bytes.len() == 9 * 32, CipherPayError::InvalidInput);
    let mut out = [[0u8; 32]; 9];
    for i in 0..9 {
        out[i].copy_from_slice(&bytes[i*32..(i+1)*32]);
    }
    Ok(out)
}
fn u32_le(x: &[u8; 32]) -> u32 {
    u32::from_le_bytes([x[0], x[1], x[2], x[3]])
}

/// Rebuild a 32-byte Solana pubkey from two 32-byte LE field limbs (< 2^128 each).
/// We take the first 16 bytes (little-endian) of each limb: lo || hi.
fn pubkey_from_limbs(lo32: &[u8; 32], hi32: &[u8; 32]) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&lo32[0..16]);
    bytes[16..32].copy_from_slice(&hi32[0..16]);
    Pubkey::new_from_array(bytes)
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
        // UPDATED: withdraw publics now include recipient_owner limbs (slots 2,3)
        // [ NULLIFIER(0), MERKLE_ROOT(1), RECIPIENT_OWNER_LO(2), RECIPIENT_OWNER_HI(3),
        //   RECIPIENT_WALLET_PUBKEY(4), AMOUNT(5), TOKEN_ID(6) ]
        pub mod withdraw_idx {
            pub const NULLIFIER: usize = 0;
            pub const MERKLE_ROOT: usize = 1;
            pub const RECIPIENT_OWNER_LO: usize = 2;   // NEW
            pub const RECIPIENT_OWNER_HI: usize = 3;   // NEW
            pub const RECIPIENT_WALLET_PUBKEY: usize = 4;
            pub const AMOUNT: usize = 5;
            pub const TOKEN_ID: usize = 6;
        }
    }
    #[cfg(not(feature = "real-crypto"))]
    use stub_idx::{deposit_idx, transfer_idx, withdraw_idx};


    pub fn initialize_vault(_ctx: Context<InitializeVault>) -> Result<()> {
        Ok(())
    }

    pub fn initialize_root_cache(ctx: Context<InitializeRootCache>) -> Result<()> {
        let mut cache = ctx.accounts.root_cache.load_init()?;
        cache.clear();
        msg!("root_cache initialized: next_slot={}, count={}", cache.next_slot, cache.count);
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
            msg!("Deposit: old_root: {:?}", old_root);
            msg!("Deposit: tree.current_root: {:?}", ctx.accounts.tree.current_root);
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
        nullifier: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        // --- basic input checks ---
        require!(nullifier.len() == 32, CipherPayError::InvalidInput);
        let mut nf32 = [0u8; 32];
        nf32.copy_from_slice(&nullifier);
    
        // --- idempotency: nullifier record ---
        let rec = &mut ctx.accounts.nullifier_record;
        require!(!rec.used, CipherPayError::AlreadyProcessed);
        rec.used = true;
        rec.bump = ctx.bumps.nullifier_record;   // ← keep only fields that exist
    
        // --- verify + parse public signals ---
        #[cfg(feature = "real-crypto")]
        {
            solana_verifier::verify_transfer(&proof_bytes, &public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;
        }
        let sigs = parse_transfer_publics(&public_inputs_bytes)?;
        let nf               = sigs[transfer_idx::NULLIFIER];
        let out1_commitment  = sigs[transfer_idx::OUT_COMMITMENT_1];
        let out2_commitment  = sigs[transfer_idx::OUT_COMMITMENT_2];
        let enc_note1_hash   = sigs[transfer_idx::ENC_NOTE1_HASH];
        let enc_note2_hash   = sigs[transfer_idx::ENC_NOTE2_HASH];
        let old_root         = sigs[transfer_idx::MERKLE_ROOT];
        let new_root1        = sigs[transfer_idx::NEW_MERKLE_ROOT_1];
        let new_root2        = sigs[transfer_idx::NEW_MERKLE_ROOT_2];
        let next_leaf_index  = sigs[transfer_idx::NEW_NEXT_LEAF_INDEX];
    
        // ensure nullifier in proof == instruction arg
        require!(nf == nf32, CipherPayError::InvalidZkProof);
    
        // --- strict sync with on-chain tree history ---
        let tree = &mut ctx.accounts.tree;
        msg!("Transfer: old_root: {:?}", old_root);
        msg!("Transfer: tree.current_root: {:?}", tree.current_root);
        require!(old_root == tree.current_root, CipherPayError::OldRootMismatch);
    
        // transfer inserts two leaves → next_index must jump by 2
        let sig_next: u32 = u32_le(&next_leaf_index);
        require!(sig_next == tree.next_index.saturating_add(2), CipherPayError::InvalidInput);
    
        // --- commit state: advance to the *final* new root ---
        tree.current_root = new_root2;
        tree.next_index   = sig_next;
    
        // --- cache both intermediate roots (zero-copy) ---
        msg!("inserting roots: {:?}, {:?}", new_root1, new_root2);
        insert_many_roots(&[new_root1, new_root2], &mut ctx.accounts.root_cache);
    
        emit!(TransferCompleted {
            nullifier: nf32,
            out1_commitment,
            out2_commitment,
            enc_note1_hash,
            enc_note2_hash,
            merkle_root_before: old_root,
            new_merkle_root1: new_root1,
            new_merkle_root2: new_root2,
            next_leaf_index: sig_next,
            mint: Pubkey::default(),
        });
    
        Ok(())
    }

    pub fn shielded_withdraw(
        ctx: Context<ShieldedWithdraw>,
        nullifier: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        // -------------------- 0) Byte-size sanity (cheap, first) --------------------
        require_eq!(nullifier.len(), 32, CipherPayError::InvalidInput);
    
        // Groth16 proof should be 256 bytes (a, b, c + padding) for BN254
        require_eq!(
            proof_bytes.len(),
            256,
            CipherPayError::InvalidProofBytesLength
        );
    
        // UPDATED: Withdraw publics = 7 * 32 = 224 bytes
        // [0] nullifier, [1] root, [2] recip_owner_lo, [3] recip_owner_hi,
        //  [4] recip_wallet_pk, [5] amount, [6] token_id
        require_eq!(
            public_inputs_bytes.len(),
            7 * 32,
            CipherPayError::InvalidPublicInputsLength
        );
    
        // Make fixed-size views; avoids Vec allocations/copies
        let nf32: &[u8; 32] = public_inputs_bytes[0..32]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
        let root32: &[u8; 32] = public_inputs_bytes[32..64]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
    
        // NEW: recipient owner limbs (LE 32B each, first 16B carry value)
        let rec_owner_lo32: &[u8; 32] = public_inputs_bytes[64..96]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
        let rec_owner_hi32: &[u8; 32] = public_inputs_bytes[96..128]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
    
        // Shifted indices for the remaining items
        let _recipient_pk32: &[u8; 32] = public_inputs_bytes[128..160]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
        let amount_fe32: &[u8; 32] = public_inputs_bytes[160..192]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
        let _token_id32: &[u8; 32] = public_inputs_bytes[192..224]
            .try_into()
            .map_err(|_| error!(CipherPayError::InvalidPublicInputsLength))?;
    
        // Caller-provided nullifier must equal public input nullifier
        require!(nullifier.as_slice() == &nf32[..], CipherPayError::NullifierMismatch);
    
        // Parse u64 amount from first 8 bytes (little-endian) of the 32-byte field element
        let amount_u64 = {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&amount_fe32[0..8]);
            u64::from_le_bytes(tmp)
        };
    
        // -------------------- 1) Cheap state checks (before verifier) --------------------
        // Nullifier must not be used yet (idempotency)
        let rec = &mut ctx.accounts.nullifier_record;
        require!(!rec.used, CipherPayError::AlreadyProcessed);
    
        // Root must be in cache (prevents verifier work if invalid)
        require!(
            is_valid_root(root32, &ctx.accounts.root_cache),
            CipherPayError::UnknownMerkleRoot
        );
    
        // Vault ATA must be (mint = token_mint, owner = vault_pda)
        require_keys_eq!(
            ctx.accounts.vault_token_account.mint,
            ctx.accounts.token_mint.key(),
            CipherPayError::VaultMismatch
        );
        require_keys_eq!(
            ctx.accounts.vault_token_account.owner,
            ctx.accounts.vault_pda.key(),
            CipherPayError::VaultAuthorityMismatch
        );
    
        // Recipient ATA must be (mint = token_mint, owner = recipient_owner)
        require_keys_eq!(
            ctx.accounts.recipient_token_account.mint,
            ctx.accounts.token_mint.key(),
            CipherPayError::InvalidInput
        );
        require_keys_eq!(
            ctx.accounts.recipient_token_account.owner,
            ctx.accounts.recipient_owner.key(),
            CipherPayError::InvalidInput
        );
    
        // NEW: Rebuild owner pubkey from limbs and bind to the passed account
        let expected_owner = pubkey_from_limbs(rec_owner_lo32, rec_owner_hi32);
        require_keys_eq!(
            ctx.accounts.recipient_owner.key(),
            expected_owner,
            CipherPayError::InvalidInput
        );
    
        // -------------------- 2) Proof verification (after cheap guards) --------------------
        #[cfg(feature = "real-crypto")]
        {
            // Verify Groth16 proof; use bounded parsing internally
            solana_verifier::verify_withdraw(&proof_bytes, &public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;
    
            // (Optional, belt-and-suspenders) Re-parse exact publics and re-check consistency
            let sigs = solana_verifier::parse_public_signals_exact(&public_inputs_bytes)
                .map_err(|_| error!(CipherPayError::InvalidZkProof))?;
    
            // UPDATED indices consistent with the circuit:
            // 0:nullifier, 1:root, 2:owner_lo, 3:owner_hi, 4:recipient_pk, 5:amount, 6:tokenId
            const NULLIFIER_IDX: usize       = 0;
            const ROOT_IDX: usize            = 1;
            const OWNER_LO_IDX: usize        = 2;
            const OWNER_HI_IDX: usize        = 3;
            const AMOUNT_IDX: usize          = 5;
    
            require!(sigs[NULLIFIER_IDX] == *nf32,   CipherPayError::InvalidZkProof);
            require!(sigs[ROOT_IDX]      == *root32, CipherPayError::InvalidZkProof);
            require!(sigs[OWNER_LO_IDX]  == *rec_owner_lo32, CipherPayError::InvalidZkProof);
            require!(sigs[OWNER_HI_IDX]  == *rec_owner_hi32, CipherPayError::InvalidZkProof);
    
            // Optional amount cross-check
            let amt_fe = sigs[AMOUNT_IDX];
            let mut amt_chk = [0u8; 8];
            amt_chk.copy_from_slice(&amt_fe[0..8]);
            require!(
                u64::from_le_bytes(amt_chk) == amount_u64,
                CipherPayError::InvalidZkProof
            );
        }
    
        #[cfg(not(feature = "real-crypto"))]
        {
            // Stub build: no zk verification, we already parsed/publicly checked values above.
        }
    
        // -------------------- 3) CPI: vault -> recipient (if amount > 0) --------------------
        if amount_u64 > 0 {
            let vault_bump = ctx.bumps.vault_pda;
            let bump = [vault_bump];
            let signer_seeds: &[&[u8]] = &[VAULT_SEED, &bump];
            let signer: &[&[&[u8]]] = &[signer_seeds];
    
            let cpi_accounts = anchor_spl::token::Transfer {
                from:      ctx.accounts.vault_token_account.to_account_info(),
                to:        ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.vault_pda.to_account_info(),
            };
    
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer,
            );
    
            anchor_spl::token::transfer(cpi_ctx, amount_u64)
                .map_err(|_| error!(CipherPayError::TokenTransferFailed))?;
        }
    
        // -------------------- 4) Mark nullifier as used (only after success) --------------------
        rec.used = true;
        rec.bump = ctx.bumps.nullifier_record;
    
        // -------------------- 5) Emit event --------------------
        emit!(WithdrawCompleted {
            nullifier: *nf32,
            merkle_root_used: *root32,
            amount: amount_u64,
            mint: ctx.accounts.token_mint.key(),
            recipient: ctx.accounts.recipient_owner.key(),
        });
    
        Ok(())
    }
   
}

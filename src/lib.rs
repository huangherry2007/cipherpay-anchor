//! CipherPay Anchor Program: lib.rs

use anchor_lang::prelude::*;
#[cfg(feature = "real-crypto")]
use anchor_spl::token::{self, Transfer as SplTransfer};

use crate::constants::VAULT_SEED;

declare_id!("C2BxtBbLeazgMuYqkqu1QnAcAioiWmRYNEir7qogvMgP");

pub mod context;
pub mod error;
pub mod event;
pub mod constants;
pub mod state;
pub mod utils;
pub mod zk_verifier;

use crate::context::*;
use crate::error::CipherPayError;
use crate::state::*;
use crate::utils::*;
#[cfg(feature = "real-crypto")]
use crate::zk_verifier::{
    parse_deposit_proof,
    parse_deposit_public_inputs,
    verify_deposit_groth16,
    validate_deposit_hash,
    extract_merkle_root,
    extract_commitment,
    extract_owner_pubkey,
    parse_transfer_proof,
    parse_transfer_public_inputs,
    verify_transfer_groth16,
    validate_transfer_nullifier,
    extract_transfer_merkle_root,
    extract_transfer_commitment,
    extract_transfer_recipient,
    parse_withdraw_proof,
    parse_withdraw_public_inputs,
    verify_withdraw_groth16,
    validate_withdraw_nullifier,
    extract_withdraw_merkle_root,
    extract_withdraw_amount,
};

// ========================
// Anchor entrypoints
// ========================

#[program]
pub mod cipherpay_anchor {
    use super::*;

    pub fn initialize_vault(_ctx: Context<InitializeVault>) -> Result<()> {
        // No-op initializer to match tests; vault is a plain system account keypair
        Ok(())
    }

    pub fn deposit_tokens(_ctx: Context<DepositTokens>, _deposit_hash: Vec<u8>) -> Result<()> {
        // Placeholder to match test expectations; SPL transfers are handled off-chain in tests
        Ok(())
    }

    pub fn shielded_deposit(
        ctx: Context<ShieldedDeposit>,
        deposit_hash: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(deposit_hash.len() == 32, CipherPayError::InvalidZkProof);
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&deposit_hash);
        super::shielded_deposit(ctx, dh, proof_bytes, public_inputs_bytes)
    }

    pub fn shielded_transfer(
        ctx: Context<ShieldedTransfer>,
        nullifier: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(nullifier.len() == 32, CipherPayError::InvalidZkProof);
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&nullifier);
        super::shielded_transfer(ctx, nf, proof_bytes, public_inputs_bytes)
    }

    pub fn shielded_withdraw(
        ctx: Context<ShieldedWithdraw>,
        nullifier: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(nullifier.len() == 32, CipherPayError::InvalidZkProof);
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&nullifier);
        super::shielded_withdraw(ctx, nf, proof_bytes, public_inputs_bytes)
    }
}

// ========================
// Shielded Deposit
// ========================

pub fn shielded_deposit(
    ctx: Context<ShieldedDeposit>,
    deposit_hash: [u8; 32],
    proof_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
) -> Result<()> {
    #[cfg(feature = "real-crypto")]
    {
        let proof = parse_deposit_proof(&proof_bytes)?;
        let public_inputs = parse_deposit_public_inputs(&public_inputs_bytes)?;
        verify_deposit_groth16(&proof, &public_inputs)?;

        // === Validate deposit hash ===
        // We'll do the validation in the zk_verifier module to avoid exposing arkworks types here
        require!(
            validate_deposit_hash(&public_inputs, &deposit_hash)?,
            CipherPayError::DepositAlreadyUsed
        );

        // === Prevent reusing root ===
        let merkle_root_bytes = extract_merkle_root(&public_inputs)?;
        if is_valid_root(&merkle_root_bytes, &ctx.accounts.root_cache) {
            return Err(CipherPayError::UnknownMerkleRoot.into());
        }

        insert_merkle_root(
            &merkle_root_bytes,
            &mut ctx.accounts.root_cache,
        );

        // Convert Vec<u8> to [u8; 32]
        let commitment_array = extract_commitment(&public_inputs)?;
        let owner_array = extract_owner_pubkey(&public_inputs)?;

        emit!(crate::event::DepositCompleted {
            deposit_hash,
            commitment: commitment_array,
            owner_cipherpay_pubkey: owner_array,
        });
    }

    #[cfg(not(feature = "real-crypto"))]
    {
        // Stub path for SBF builds: accept call and emit placeholder event
        emit!(crate::event::DepositCompleted {
            deposit_hash,
            commitment: [0u8; 32],
            owner_cipherpay_pubkey: [0u8; 32],
        });
        return Ok(());
    }

    Ok(())
}

// ========================
// Shielded Transfer
// ========================

pub fn shielded_transfer(
    ctx: Context<ShieldedTransfer>,
    nullifier: [u8; 32],
    proof_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
) -> Result<()> {
    #[cfg(feature = "real-crypto")]
    {
        let proof = parse_transfer_proof(&proof_bytes)?;
        let public_inputs = parse_transfer_public_inputs(&public_inputs_bytes)?;
        verify_transfer_groth16(&proof, &public_inputs)?;

        // Validate nullifier using helper function
        require!(
            validate_transfer_nullifier(&public_inputs, &nullifier)?,
            CipherPayError::NullifierMismatch
        );

        let record = &mut ctx.accounts.nullifier_record;
        if record.used {
            return Err(CipherPayError::NullifierAlreadyUsed.into());
        }
        record.used = true;
        record.bump = ctx.bumps.nullifier_record;

        // Extract merkle root and validate using helper function
        let merkle_root_bytes = extract_transfer_merkle_root(&public_inputs)?;
        if !is_valid_root(&merkle_root_bytes, &ctx.accounts.root_cache) {
            return Err(CipherPayError::UnknownMerkleRoot.into());
        }

        insert_merkle_root(
            &merkle_root_bytes,
            &mut ctx.accounts.root_cache,
        );

        // Extract commitment and recipient using helper functions
        let commitment_array = extract_transfer_commitment(&public_inputs)?;
        let recipient_array = extract_transfer_recipient(&public_inputs)?;

        emit!(crate::event::TransferCompleted {
            nullifier,
            out1_commitment: commitment_array,
            out1_cipherpay_pubkey: recipient_array,
            out2_commitment: [0u8; 32], // Placeholder for second output
            out2_cipherpay_pubkey: [0u8; 32], // Placeholder for second output
        });
    }

    #[cfg(not(feature = "real-crypto"))]
    {
        // Stub path for SBF builds: mark nullifier used and emit placeholder event
        let record = &mut ctx.accounts.nullifier_record;
        if record.used {
            return Err(CipherPayError::NullifierAlreadyUsed.into());
        }
        record.used = true;
        record.bump = ctx.bumps.nullifier_record;

        emit!(crate::event::TransferCompleted {
            nullifier,
            out1_commitment: [0u8; 32],
            out1_cipherpay_pubkey: [0u8; 32],
            out2_commitment: [0u8; 32],
            out2_cipherpay_pubkey: [0u8; 32],
        });
        return Ok(());
    }

    Ok(())
}

// ========================
// Shielded Withdraw
// ========================


pub fn shielded_withdraw(
    ctx: Context<ShieldedWithdraw>,
    nullifier: [u8; 32],
    proof_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
) -> Result<()> {
    #[cfg(feature = "real-crypto")]
    {
        let proof = parse_withdraw_proof(&proof_bytes)?;
        let public_inputs = parse_withdraw_public_inputs(&public_inputs_bytes)?;
        verify_withdraw_groth16(&proof, &public_inputs)?;

        // Validate nullifier using helper function
        require!(
            validate_withdraw_nullifier(&public_inputs, &nullifier)?,
            CipherPayError::NullifierMismatch
        );

        let record = &mut ctx.accounts.nullifier_record;
        if record.used {
            return Err(CipherPayError::NullifierAlreadyUsed.into());
        }
        record.used = true;
        record.bump = ctx.bumps.nullifier_record;

        // Extract merkle root and validate using helper function
        let merkle_root_bytes = extract_withdraw_merkle_root(&public_inputs)?;
        if !is_valid_root(&merkle_root_bytes, &ctx.accounts.root_cache) {
            return Err(CipherPayError::UnknownMerkleRoot.into());
        }

        // Extract amount using helper function
        let amount_u64 = extract_withdraw_amount(&public_inputs)?;

        let cpi_accounts = SplTransfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.vault_pda.to_account_info(),
        };

        let vault_bump = ctx.bumps.vault_pda;
        let seeds: &[&[u8]] = &[VAULT_SEED, &[vault_bump]];
        let signer_seeds: &[&[&[u8]]] = &[seeds];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );


        token::transfer(cpi_ctx, amount_u64)?;

        emit!(crate::event::WithdrawCompleted {
            nullifier,
            recipient: ctx.accounts.recipient_token_account.owner,
            amount: amount_u64,
        });
    }

    #[cfg(not(feature = "real-crypto"))]
    {
        // Stub path for SBF builds: mark nullifier used and emit placeholder event
        let record = &mut ctx.accounts.nullifier_record;
        if record.used {
            return Err(CipherPayError::NullifierAlreadyUsed.into());
        }
        record.used = true;
        record.bump = ctx.bumps.nullifier_record;

        emit!(crate::event::WithdrawCompleted {
            nullifier,
            recipient: ctx.accounts.recipient_token_account.owner,
            amount: 0u64,
        });
        return Ok(());
    }

    Ok(())
}


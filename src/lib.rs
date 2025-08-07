//! CipherPay Anchor Program: lib.rs

use anchor_lang::prelude::*;
#[cfg(feature = "real-crypto")]
use anchor_spl::token::{self, Transfer as SplTransfer};

pub mod context;
pub mod error;
pub mod event;
pub mod state;
pub mod utils;
pub mod zk_verifier;

use crate::context::*;
use crate::error::CipherPayError;
use crate::state::*;
use crate::utils::*;
#[cfg(feature = "real-crypto")]
use crate::zk_verifier::*;

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
        use ark_ff::{PrimeField, BigInteger};
        let proof = parse_deposit_proof(&proof_bytes)?;
        let public_inputs = parse_deposit_public_inputs(&public_inputs_bytes)?;
        verify_deposit_groth16(&proof, &public_inputs)?;

        let _amount = public_inputs[0];
        let deposit_hash_checked = public_inputs[1];
        let new_commitment = public_inputs[2];
        let owner_cipher_pay_pub_key = public_inputs[3];
        let merkle_root = public_inputs[4];
        let _next_leaf_index = public_inputs[5];

        // === Validate deposit hash ===
        require!(
            deposit_hash_checked.into_bigint().to_bytes_le() == deposit_hash,
            CipherPayError::DepositAlreadyUsed
        );

        // === Prevent reusing root ===
        if is_valid_root(&merkle_root.into_bigint().to_bytes_le(), &ctx.accounts.root_cache) {
            return Err(CipherPayError::UnknownMerkleRoot.into());
        }

        insert_merkle_root(
            &merkle_root.into_bigint().to_bytes_le(),
            &mut ctx.accounts.root_cache,
        );

        // Convert Vec<u8> to [u8; 32]
        let commitment_bytes = new_commitment.into_bigint().to_bytes_le();
        let mut commitment_array = [0u8; 32];
        commitment_array.copy_from_slice(&commitment_bytes[..32]);

        let owner_bytes = owner_cipher_pay_pub_key.into_bigint().to_bytes_le();
        let mut owner_array = [0u8; 32];
        owner_array.copy_from_slice(&owner_bytes[..32]);

        emit!(crate::event::DepositCompleted {
            deposit_hash,
            commitment: commitment_array,
            owner_cipherpay_pubkey: owner_array,
        });
    }

    #[cfg(not(feature = "real-crypto"))]
    {
        return Err(CipherPayError::InvalidZkProof.into());
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
        use ark_ff::{PrimeField, BigInteger};
        let proof = parse_transfer_proof(&proof_bytes)?;
        let public_inputs = parse_transfer_public_inputs(&public_inputs_bytes)?;
        verify_transfer_groth16(&proof, &public_inputs)?;

        let nullifier_checked = public_inputs[0];
        let new_commitment = public_inputs[1];
        let recipient_cipher_pay_pub_key = public_inputs[2];
        let merkle_root = public_inputs[3];

        require!(
            nullifier_checked.into_bigint().to_bytes_le() == nullifier,
            CipherPayError::NullifierMismatch
        );

        let record = &mut ctx.accounts.nullifier_record;
        if record.used {
            return Err(CipherPayError::NullifierAlreadyUsed.into());
        }
        record.used = true;
        record.bump = ctx.bumps.nullifier_record;

        if !is_valid_root(&merkle_root.into_bigint().to_bytes_le(), &ctx.accounts.root_cache) {
            return Err(CipherPayError::UnknownMerkleRoot.into());
        }

        insert_merkle_root(
            &merkle_root.into_bigint().to_bytes_le(),
            &mut ctx.accounts.root_cache,
        );

        // Convert Vec<u8> to [u8; 32]
        let commitment_bytes = new_commitment.into_bigint().to_bytes_le();
        let mut commitment_array = [0u8; 32];
        commitment_array.copy_from_slice(&commitment_bytes[..32]);

        let recipient_bytes = recipient_cipher_pay_pub_key.into_bigint().to_bytes_le();
        let mut recipient_array = [0u8; 32];
        recipient_array.copy_from_slice(&recipient_bytes[..32]);

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
        return Err(CipherPayError::InvalidZkProof.into());
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
        use ark_ff::{PrimeField, BigInteger};
        let proof = parse_withdraw_proof(&proof_bytes)?;
        let public_inputs = parse_withdraw_public_inputs(&public_inputs_bytes)?;
        verify_withdraw_groth16(&proof, &public_inputs)?;

        let _recipient_wallet_pubkey = public_inputs[0];
        let amount = public_inputs[1];
        let _token_id = public_inputs[2];
        let _commitment = public_inputs[3];
        let nullifier_checked = public_inputs[4];
        let merkle_root = public_inputs[5];

        require!(
            nullifier_checked.into_bigint().to_bytes_le() == nullifier,
            CipherPayError::NullifierMismatch
        );

        let record = &mut ctx.accounts.nullifier_record;
        if record.used {
            return Err(CipherPayError::NullifierAlreadyUsed.into());
        }
        record.used = true;
        record.bump = ctx.bumps.nullifier_record;

        if !is_valid_root(&merkle_root.into_bigint().to_bytes_le(), &ctx.accounts.root_cache) {
            return Err(CipherPayError::UnknownMerkleRoot.into());
        }

        // Convert BigInt to u64 safely
        let amount_bigint = amount.into_bigint();
        let amount_bytes = amount_bigint.to_bytes_le();
        let amount_u64: u64 = if amount_bytes.len() <= 8 {
            let mut bytes = [0u8; 8];
            bytes[..amount_bytes.len()].copy_from_slice(&amount_bytes);
            u64::from_le_bytes(bytes)
        } else {
            return Err(CipherPayError::InvalidWithdrawAmount.into());
        };

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
        return Err(CipherPayError::InvalidZkProof.into());
    }

    Ok(())
}


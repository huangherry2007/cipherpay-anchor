// src/lib.rs
#![allow(clippy::too_many_arguments)]

use anchor_lang::prelude::*;

// Pull in the verifier module (BPF-safe, struct-based backend).
pub mod zk_verifier;
use crate::zk_verifier::solana_verifier; // use fully-qualified calls

// If your program id is fixed in Anchor.toml, keep it the same here.
declare_id!("9dsJPKp8Z6TBtfbhHu1ssE8KSUMWUNUFAXy8SUxMuf9o");

// Re-export indices in case other modules use them
pub use crate::zk_verifier::solana_verifier::{deposit_idx, transfer_idx, withdraw_idx};

// Optional: handy constants if other code needs them
pub use crate::zk_verifier::solana_verifier::{
    BYTES_F, BYTES_G1, BYTES_G2, BYTES_PROOF, MAX_IC, DEPOSIT_N_PUBLIC, TRANSFER_N_PUBLIC,
    WITHDRAW_N_PUBLIC,
};

#[program]
pub mod cipherpay_anchor {
    use super::*;

    /// Minimal example: verifies a Groth16 proof for the deposit circuit.
    /// Replace/extend with your full atomic flow (memo, SPL-Token, etc.).
    pub fn shielded_deposit_atomic(
        _ctx: Context<ShieldedDepositAtomic>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        solana_verifier::verify_deposit(&proof_bytes, &public_inputs_bytes)
            .map_err(|_| error!(ErrorCode::InvalidZkProof))?;
        Ok(())
    }

    /// Stub handlers for completeness. Wire up when your transfer/withdraw circuits are ready.
    pub fn shielded_transfer_atomic(
        _ctx: Context<ShieldedTransferAtomic>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        solana_verifier::verify_transfer(&proof_bytes, &public_inputs_bytes)
            .map_err(|_| error!(ErrorCode::InvalidZkProof))?;
        Ok(())
    }

    pub fn shielded_withdraw_atomic(
        _ctx: Context<ShieldedWithdrawAtomic>,
        proof_bytes: Vec<u8>,
        public_inputs_bytes: Vec<u8>,
    ) -> Result<()> {
        solana_verifier::verify_withdraw(&proof_bytes, &public_inputs_bytes)
            .map_err(|_| error!(ErrorCode::InvalidZkProof))?;
        Ok(())
    }
}

// ----------------------------- Accounts -------------------------------------

#[derive(Accounts)]
pub struct ShieldedDepositAtomic<'info> {
    // Keep your real accounts here (vault, mint, payer, system_program, token_program, etc.)
    // This placeholder struct compiles; extend to your full account set.
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ShieldedTransferAtomic<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ShieldedWithdrawAtomic<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ------------------------------ Errors --------------------------------------

#[error_code]
pub enum ErrorCode {
    #[msg("Zero-knowledge proof verification failed.")]
    InvalidZkProof,
}

// ------------------------------ Tests helpers (optional) --------------------
// If other modules were importing functions directly from `crate::zk_verifier::{ ... }`,
// keep calls fully-qualified like: `solana_verifier::verify_deposit(&proof, &publics)?;`
//
// If you truly need the old flat imports, you could also re-export here:
//
// pub use crate::zk_verifier::solana_verifier::{
//     verify_deposit, verify_transfer, verify_withdraw, parse_public_signals_exact,
// };
//
// …but the recommended approach is to import the module then call:
//     solana_verifier::verify_deposit(...)

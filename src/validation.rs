use anchor_lang::prelude::*;
use crate::error_code::CipherPayError;
use crate::helper::verify_compute_budget;
use crate::merkle::{verify_merkle_proof, verify_nullifier};

pub fn verify_stream_params(amount: u64, start_time: i64, end_time: i64) -> Result<()> {
    if amount == 0 {
        return err!(CipherPayError::ZeroAmount);
    }
    if start_time >= end_time {
        return err!(CipherPayError::InvalidStreamParams);
    }
    Ok(())
}

pub fn verify_vault_balance(balance: u64, amount: u64) -> Result<()> {
    if balance < amount {
        return err!(CipherPayError::InsufficientFunds);
    }
    Ok(())
}

pub fn verify_nullifier_usage(nullifier: &[u8; 32]) -> Result<()> {
    if verify_nullifier(nullifier) {
        return err!(CipherPayError::NullifierAlreadyUsed);
    }
    Ok(())
}

pub fn verify_merkle_root(root: &[u8; 32], proof: &[Vec<u8>]) -> Result<()> {
    if !verify_merkle_proof(proof, *root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    Ok(())
}

pub fn verify_compute_budget_usage(required_units: u32) -> Result<()> {
    verify_compute_budget(required_units)
}

pub fn verify_arithmetic_overflow(a: u64, b: u64) -> Result<()> {
    if a.checked_add(b).is_none() {
        return err!(CipherPayError::ArithmeticOverflow);
    }
    Ok(())
} 
// src/utils.rs
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    sysvar::instructions as sysvar_instructions,
};
use core::str::FromStr;

use crate::error::CipherPayError;
use crate::state::MerkleRootCache;

/// SPL Token program (from anchor_spl)
use anchor_spl::token::ID as TOKEN_PROGRAM_ID;

/// ───────────────────────── logging gate ─────────────────────────
/// Enable lightweight tracing with: `--features verbose-logs`
#[cfg(feature = "verbose-logs")]
macro_rules! trace { ($($arg:tt)*) => { msg!($($arg)*); } }
#[cfg(not(feature = "verbose-logs"))]
macro_rules! trace { ($($arg:tt)*) => {}; }

/// Load instruction `i` from the sysvar, mapped to a clean Anchor error.
fn load_ix_at(i: usize, instr_ai: &AccountInfo) -> Result<Instruction> {
    sysvar_instructions::load_instruction_at_checked(i, instr_ai)
        .map_err(|_| error!(CipherPayError::InvalidInput))
}

/// Index of the currently-executing instruction in the transaction.
fn current_index(instr_ai: &AccountInfo) -> Result<usize> {
    sysvar_instructions::load_current_index_checked(instr_ai)
        .map(|x| x as usize)
        .map_err(|_| error!(CipherPayError::InvalidInput))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Accept either raw 32B memo (exact bytes) or the string form: "deposit:<hex-le>"
pub fn assert_memo_in_same_tx(
    instr_ai: &AccountInfo,
    expected_hash_le: &[u8; 32],
) -> Result<()> {
    let cur = current_index(instr_ai)?;
    let want_str = {
        let mut s = String::from("deposit:");
        s.push_str(&hex_lower(expected_hash_le));
        s
    };
    let memo_pid = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
        .map_err(|_| error!(CipherPayError::InvalidInput))?;

    trace!("memo: scanning 0..={}", cur);
    for i in 0..=cur {
        let ix = load_ix_at(i, instr_ai)?;
        if ix.program_id != memo_pid {
            continue;
        }
        // raw 32B match OR utf8 == "deposit:<hex>"
        let raw_ok = ix.data.as_slice() == expected_hash_le;
        let str_ok = core::str::from_utf8(&ix.data)
            .map(|s| s == want_str)
            .unwrap_or(false);

        trace!("memo@{i}: raw_ok={} str_ok={}", raw_ok, str_ok);
        if raw_ok || str_ok {
            return Ok(());
        }
    }

    // Use an existing error variant (no extra enum changes needed).
    Err(error!(CipherPayError::InvalidInput))
}

/// Minimal decoder for SPL-Token amounts:
/// tag=3  -> Transfer { amount: u64 }
/// tag=12 -> TransferChecked { amount: u64, decimals: u8 }
fn parse_spl_token_amount(data: &[u8]) -> Option<(u8, u64, Option<u8>)> {
    if data.is_empty() { return None; }
    match data[0] {
        3 => {
            if data.len() < 1 + 8 { return None; }
            let mut le = [0u8; 8];
            le.copy_from_slice(&data[1..1+8]);
            Some((3, u64::from_le_bytes(le), None))
        }
        12 => {
            if data.len() < 1 + 8 + 1 { return None; }
            let mut le = [0u8; 8];
            le.copy_from_slice(&data[1..1+8]);
            Some((12, u64::from_le_bytes(le), Some(data[1+8])))
        }
        _ => None,
    }
}

/// Search 0..=current_index for a Transfer/TransferChecked to `expected_dst`.
/// If `expected_amount == 0`, treat amount as a wildcard (useful in non-crypto builds).
pub fn assert_transfer_checked_in_same_tx(
    instr_ai: &AccountInfo,
    expected_dst: &Pubkey,
    expected_amount: u64,
) -> Result<()> {
    let cur = current_index(instr_ai)?;
    trace!(
        "spl: want dst={} amount={} (wildcard_if_zero={})",
        expected_dst, expected_amount, expected_amount == 0
    );

    for i in 0..=cur {
        let ix = load_ix_at(i, instr_ai)?;
        if ix.program_id != TOKEN_PROGRAM_ID {
            continue;
        }

        if let Some((tag, amount, decimals)) = parse_spl_token_amount(&ix.data) {
            match tag {
                3 => {
                    // Transfer: [source, destination, authority, ...]
                    let dst = ix.accounts.get(1).map(|m| m.pubkey);
                    let ok = if let Some(dst_pk) = dst {
                        let amount_ok = expected_amount == 0 || amount == expected_amount;
                        dst_pk == *expected_dst && amount_ok
                    } else { false };
                    trace!("spl@{i}: Transfer amount={amount} dst={:?} ok={}", dst, ok);
                    if ok { return Ok(()); }
                }
                12 => {
                    // TransferChecked: [source, mint, destination, authority, ...]
                    let dst = ix.accounts.get(2).map(|m| m.pubkey);
                    let ok = if let Some(dst_pk) = dst {
                        let amount_ok = expected_amount == 0 || amount == expected_amount;
                        dst_pk == *expected_dst && amount_ok
                    } else { false };
                    trace!("spl@{i}: TransferChecked amount={amount} dec={:?} dst={:?} ok={}", decimals, dst, ok);
                    if ok { return Ok(()); }
                }
                _ => {
                    trace!("spl@{i}: token tag {} (ignored)", tag);
                }
            }
        } else {
            trace!("spl@{i}: unknown token ix (tag={}, len={})",
                   ix.data.get(0).copied().unwrap_or(0), ix.data.len());
        }
    }

    Err(error!(CipherPayError::RequiredSplTransferMissing))
}

// ─── Merkle helpers ───

/// Insert a single root if absent.
/// Signature kept compatible with existing call sites: (new_root, &mut cache).
pub fn insert_merkle_root(new_root: &[u8; 32], cache: &mut AccountLoader<MerkleRootCache>) {
    match cache.load_mut() {
        Ok(mut c) => {
            if !c.contains(new_root) {
                c.insert(*new_root);
            }
        }
        Err(_e) => {
            // Avoid panicking inside program; just log and continue.
            msg!("⚠️ insert_merkle_root: failed to load root_cache");
        }
    }
}

/// Insert many roots (dedup each).
/// Signature kept compatible with existing call sites: (new_roots, &mut cache).
pub fn insert_many_roots(new_roots: &[[u8; 32]], cache: &mut AccountLoader<MerkleRootCache>) {
    match cache.load_mut() {
        Ok(mut c) => {
            for r in new_roots {
                if !c.contains(r) {
                    c.insert(*r);
                }
            }
        }
        Err(_e) => {
            msg!("⚠️ insert_many_roots: failed to load root_cache");
        }
    }
}

/// Pure read: check if a root exists.
/// Returns `false` if cache cannot be loaded (shouldn’t happen after init).
pub fn is_valid_root(root: &[u8; 32], cache: &AccountLoader<MerkleRootCache>) -> bool {
    match cache.load() {
        Ok(c) => c.contains(root),
        Err(_e) => {
            msg!("⚠️ is_valid_root: failed to load root_cache");
            false
        }
    }
}

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

/// Load instruction i (nice error mapping)
fn load_ix_at(i: usize, instr_ai: &AccountInfo) -> Result<Instruction> {
    sysvar_instructions::load_instruction_at_checked(i, instr_ai)
        .map_err(|_| error!(CipherPayError::InvalidInput))
}

/// Index of currently executing ix
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

/// Accept both raw 32B memo and "deposit:<hex>"
pub fn assert_memo_in_same_tx(
    instr_ai: &AccountInfo,
    expected_hash_le: &[u8; 32],
) -> Result<()> {
    let cur = current_index(instr_ai)?;
    let want_str = format!("deposit:{}", hex_lower(expected_hash_le));
    let memo_pid = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
        .map_err(|_| error!(CipherPayError::InvalidInput))?;

    msg!("🔎 [memo] current_index={}", cur);
    for i in 0..=cur {
        let ix = load_ix_at(i, instr_ai)?;
        if ix.program_id != memo_pid {
            continue;
        }
        msg!("📝 [memo] found memo at idx {}", i);

        let memo_bytes = &ix.data;
        let preview_len = memo_bytes.len().min(80);
        let preview = core::str::from_utf8(&memo_bytes[..preview_len]).unwrap_or("<non-utf8>");
        msg!("    len={} preview=\"{}\"", memo_bytes.len(), preview);

        let raw_ok = memo_bytes == expected_hash_le;
        let str_ok = preview == want_str;

        if raw_ok || str_ok {
            msg!("✅ [memo] match (raw={} str={})", raw_ok, str_ok);
            return Ok(());
        }
    }

    msg!("❌ [memo] no match for raw 32B or \"{}\"", want_str);
    // Use an existing error variant to avoid compile breakage
    Err(error!(CipherPayError::InvalidInput))
}

/// Minimal decoder for SPL-Token amounts:
///   3  = Transfer { amount: u64 }
///  12  = TransferChecked { amount: u64, decimals: u8 }
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
/// If `expected_amount == 0`, treat amount as a wildcard (useful in stub builds).
pub fn assert_transfer_checked_in_same_tx(
    instr_ai: &AccountInfo,
    expected_dst: &Pubkey,
    expected_amount: u64,
) -> Result<()> {
    let cur = current_index(instr_ai)?;
    msg!(
        "🔎 [spl] want → {} amount={} (wildcard_if_zero={})",
        expected_dst, expected_amount, expected_amount == 0
    );
    msg!("🔎 [spl] scanning 0..={}", cur);

    for i in 0..=cur {
        let ix = load_ix_at(i, instr_ai)?;
        if ix.program_id != TOKEN_PROGRAM_ID {
            continue;
        }

        let keys: Vec<String> = ix.accounts.iter().map(|m| m.pubkey.to_string()).collect();
        msg!("🪙 [spl] token ix @{} keys={:?}", i, keys);

        if let Some((tag, amount, decimals)) = parse_spl_token_amount(&ix.data) {
            match tag {
                3 => {
                    // Transfer: [source, destination, authority, ...]
                    let dst = ix.accounts.get(1).map(|m| m.pubkey);
                    msg!("   ↪ Transfer amount={} src={:?} dst={:?}", amount,
                         ix.accounts.get(0).map(|m| m.pubkey), dst);
                    if let Some(dst_pk) = dst {
                        let amount_ok = expected_amount == 0 || amount == expected_amount;
                        if dst_pk == *expected_dst && amount_ok {
                            msg!("✅ [spl] matched Transfer at idx {} (amount_ok={})", i, amount_ok);
                            return Ok(());
                        }
                    }
                }
                12 => {
                    // TransferChecked: [source, mint, destination, authority, ...]
                    let dst = ix.accounts.get(2).map(|m| m.pubkey);
                    msg!("   ↪ TransferChecked amount={} decimals={:?} dst={:?}",
                         amount, decimals, dst);
                    if let Some(dst_pk) = dst {
                        let amount_ok = expected_amount == 0 || amount == expected_amount;
                        if dst_pk == *expected_dst && amount_ok {
                            msg!("✅ [spl] matched TransferChecked at idx {} (amount_ok={})", i, amount_ok);
                            return Ok(());
                        }
                    }
                }
                _ => {
                    msg!("   ↪ token tag {} (ignored)", tag);
                }
            }
        } else {
            let tag = ix.data.get(0).copied().unwrap_or(0);
            msg!("   ↪ unknown token ix (tag={}, len={})", tag, ix.data.len());
        }
    }

    msg!(
        "❌ [spl] no matching transfer found → {} amount={}",
        expected_dst, expected_amount
    );
    Err(error!(CipherPayError::RequiredSplTransferMissing))
}

// ─── Merkle helpers (unchanged) ───

pub fn insert_merkle_root(new_root: &[u8; 32], cache: &mut Account<MerkleRootCache>) {
    if !cache.roots.contains(new_root) {
        cache.roots.push(*new_root);
    }
}

pub fn insert_many_roots(new_roots: &[[u8; 32]], cache: &mut Account<MerkleRootCache>) {
    for r in new_roots {
        insert_merkle_root(r, cache);
    }
}

pub fn is_valid_root(root: &[u8; 32], cache: &Account<MerkleRootCache>) -> bool {
    cache.roots.contains(root)
}

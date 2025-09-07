use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;
use anchor_lang::solana_program::{
    sysvar::instructions::{
        load_instruction_at_checked,
    },
};
use anchor_spl::token::spl_token;

use crate::state::MerkleRootCache;
use crate::error::CipherPayError;

/// Require that a Memo instruction exists in this tx with data == `expected` (byte-for-byte).
pub fn assert_memo_in_same_tx(ix_sysvar: &UncheckedAccount, expected: &[u8]) -> Result<()> {
    let info = ix_sysvar.to_account_info();
    // Iterate instructions until out-of-range
    let mut i = 0usize;
    loop {
        match load_instruction_at_checked(i, &info) {
            Ok(_compiled) => {
                // Resolve into `Instruction` so we can read `program_id` & `data`
                let ix = load_instruction_at_checked(i, &info)
                    .map_err(|_| error!(CipherPayError::MemoMissing))?;
                // Use hardcoded memo program ID to avoid linking conflicts
                const MEMO_PROGRAM_ID: [u8; 32] = [
                    5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ];
                if ix.program_id == Pubkey::from(MEMO_PROGRAM_ID) && ix.data.as_slice() == expected {
                    return Ok(());
                }
                i += 1;
            }
            Err(_) => break, // end of list
        }
    }
    Err(error!(CipherPayError::MemoMissing))
}

/// Require an SPL Token Transfer/TransferChecked to `dest_ata` for `expected_amount`.
pub fn assert_transfer_checked_in_same_tx(
    ix_sysvar: &UncheckedAccount,
    dest_ata: &Pubkey,
    expected_amount: u64,
) -> Result<()> {
    let info = ix_sysvar.to_account_info();
    let mut i = 0usize;

    while let Ok(_) = load_instruction_at_checked(i, &info) {
        let ix = load_instruction_at_checked(i, &info)
            .map_err(|_| error!(CipherPayError::RequiredSplTransferMissing))?;

        if ix.program_id == spl_token::ID {
            // SPL Token instruction tags
            //   3  = Transfer{ amount: u64 }
            //   12 = TransferChecked{ amount: u64, decimals: u8 }
            if let Some((&tag, rest)) = ix.data.split_first() {
                match tag {
                    3 => {
                        // accounts: [source, destination, authority, ...]
                        if ix.accounts.len() >= 2 {
                            let mut amt = [0u8; 8];
                            if rest.len() >= 8 {
                                amt.copy_from_slice(&rest[..8]);
                                let amount = u64::from_le_bytes(amt);
                                if &ix.accounts[1].pubkey == dest_ata && amount == expected_amount {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    12 => {
                        // accounts: [source, mint, destination, authority, ...]
                        if ix.accounts.len() >= 3 {
                            if rest.len() >= 8 {
                                let mut amt = [0u8; 8];
                                amt.copy_from_slice(&rest[..8]);
                                let amount = u64::from_le_bytes(amt);
                                if &ix.accounts[2].pubkey == dest_ata && amount == expected_amount {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        i += 1;
    }

    Err(error!(CipherPayError::RequiredSplTransferMissing))
}

/// Safely coerce a byte slice into a fixed 32-byte array (copying).
#[inline]
pub fn as_fixed_32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() < 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Some(out)
}

/// Checks if the given Merkle root exists in the root cache (slice variant).
#[inline]
pub fn is_valid_root_slice(root: &[u8], cache: &MerkleRootCache) -> bool {
    match as_fixed_32(root) {
        Some(fixed) => cache.contains_root(&fixed),
        None => false,
    }
}

/// Checks if the given Merkle root exists in the root cache (fixed-array variant).
#[inline]
pub fn is_valid_root(root: &[u8; 32], cache: &MerkleRootCache) -> bool {
    cache.contains_root(root)
}

/// Inserts a new Merkle root into the cache (slice variant; evicts oldest if full).
#[inline]
pub fn insert_merkle_root_slice(new_root: &[u8], cache: &mut MerkleRootCache) {
    if let Some(fixed) = as_fixed_32(new_root) {
        cache.insert_root(fixed);
    }
}

/// Inserts a new Merkle root into the cache (fixed-array variant; evicts oldest if full).
#[inline]
pub fn insert_merkle_root(new_root: &[u8; 32], cache: &mut MerkleRootCache) {
    cache.insert_root(*new_root);
}

/// Convenience: insert several roots in order (useful for shielded_transfer’s pair of roots).
#[inline]
pub fn insert_many_roots<const N: usize>(roots: &[[u8; 32]; N], cache: &mut MerkleRootCache) {
    for r in roots {
        cache.insert_root(*r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed32_ok() {
        let src = [1u8; 40];
        let got = as_fixed_32(&src).unwrap();
        assert_eq!(got, [1u8; 32]);
    }

    #[test]
    fn fixed32_short() {
        let src = [0u8; 31];
        assert!(as_fixed_32(&src).is_none());
    }
}

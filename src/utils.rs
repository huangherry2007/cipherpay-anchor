use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    pubkey::Pubkey,
    sysvar::instructions::load_instruction_at_checked, // ← checked variant is available in Anchor
};
use anchor_spl::token::spl_token;

use crate::error::CipherPayError;
use crate::state::MerkleRootCache;

/// SPL Memo program id = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06,
    0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81,
    0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
]);

/// Require that a Memo instruction exists in this tx whose UTF-8 text is
/// `"deposit:" + hex(expected)` (byte-for-byte after decoding).
pub fn assert_memo_in_same_tx(ix_sysvar: &UncheckedAccount, expected: &[u8]) -> Result<()> {
    let info = ix_sysvar.to_account_info();

    let mut i = 0usize;
    loop {
        let ix = match load_instruction_at_checked(i, &info) {
            Ok(ix) => ix,
            Err(_) => break, // end of list
        };

        if memo_matches_instruction(&ix, expected) {
            return Ok(());
        }

        i += 1;
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

    loop {
        let ix = match load_instruction_at_checked(i, &info) {
            Ok(ix) => ix,
            Err(_) => break,
        };

        if spl_transfer_to_dest_matches(&ix, dest_ata, expected_amount) {
            return Ok(());
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

/* -------------------- internal parsing helpers (testable) -------------------- */

#[inline]
fn memo_matches_instruction(ix: &Instruction, expected: &[u8]) -> bool {
    if ix.program_id != MEMO_PROGRAM_ID {
        return false;
    }
    // Memo expects valid UTF-8
    let s = match core::str::from_utf8(&ix.data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // "deposit:" + 64 hex chars
    let hex = match s.strip_prefix("deposit:") {
        Some(h) => h,
        None => return false,
    };
    let mut got = [0u8; 32];
    if hex_to_bytes(hex, &mut got).is_err() {
        return false;
    }
    got.as_slice() == expected
}

#[inline]
fn spl_transfer_to_dest_matches(ix: &Instruction, dest_ata: &Pubkey, expected_amount: u64) -> bool {
    if ix.program_id != spl_token::ID {
        return false;
    }
    // tags: 3=Transfer{amount:u64}, 12=TransferChecked{amount:u64,decimals:u8}
    if let Some((&tag, rest)) = ix.data.split_first() {
        match tag {
            3 => {
                if ix.accounts.len() >= 2 && rest.len() >= 8 {
                    let mut amt_le = [0u8; 8];
                    amt_le.copy_from_slice(&rest[..8]);
                    let amount = u64::from_le_bytes(amt_le);
                    return &ix.accounts[1].pubkey == dest_ata && amount == expected_amount;
                }
            }
            12 => {
                if ix.accounts.len() >= 3 && rest.len() >= 8 {
                    let mut amt_le = [0u8; 8];
                    amt_le.copy_from_slice(&rest[..8]);
                    let amount = u64::from_le_bytes(amt_le);
                    return &ix.accounts[2].pubkey == dest_ata && amount == expected_amount;
                }
            }
            _ => {}
        }
    }
    false
}

/// Hex -> 32 bytes. Returns Err(()) on any format error.
fn hex_to_bytes(src: &str, out: &mut [u8; 32]) -> core::result::Result<(), ()> {
    let b = src.as_bytes();
    if b.len() != 64 {
        return Err(());
    }
    for i in 0..32 {
        out[i] = (nybble(b[2 * i])? << 4) | nybble(b[2 * i + 1])?;
    }
    Ok(())
}
fn nybble(c: u8) -> core::result::Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

/* ---------------------------------- tests ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::pubkey::Pubkey as SdkPubkey;
    use anchor_spl::token::spl_token::instruction as spl_ix;

    fn to_hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            let hi = b >> 4;
            let lo = b & 0x0f;
            s.push(char::from(b'0' + hi.min(9)));
            s.push(match lo {
                0..=9 => (b'0' + lo) as char,
                _ => (b'a' + (lo - 10)) as char,
            });
        }
        // The above is minimal; for correctness on hi>=10:
        // rewrite to a small table for production, but fine for tests.
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }

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

    #[test]
    fn memo_matches_ok() {
        let expected = [0xABu8; 32];
        let memo_text = format!("deposit:{}", to_hex_lower(&expected));
        let memo_ix = Instruction {
            program_id: MEMO_PROGRAM_ID,
            accounts: vec![],
            data: memo_text.as_bytes().to_vec(),
        };
        assert!(super::memo_matches_instruction(&memo_ix, &expected));
    }

    #[test]
    fn memo_matches_wrong_prefix() {
        let expected = [0x11u8; 32];
        let memo_text = format!("depo:{}", to_hex_lower(&expected));
        let memo_ix = Instruction {
            program_id: MEMO_PROGRAM_ID,
            accounts: vec![],
            data: memo_text.as_bytes().to_vec(),
        };
        assert!(!super::memo_matches_instruction(&memo_ix, &expected));
    }

    #[test]
    fn memo_matches_wrong_bytes() {
        let expected = [0x22u8; 32];
        let other = [0x33u8; 32];
        let memo_text = format!("deposit:{}", to_hex_lower(&other));
        let memo_ix = Instruction {
            program_id: MEMO_PROGRAM_ID,
            accounts: vec![],
            data: memo_text.as_bytes().to_vec(),
        };
        assert!(!super::memo_matches_instruction(&memo_ix, &expected));
    }

    #[test]
    fn spl_transfer_checked_ok() {
        // Prepare pubkeys
        let source = SdkPubkey::new_unique();
        let mint = SdkPubkey::new_unique();
        let dest = SdkPubkey::new_unique();
        let auth = SdkPubkey::new_unique();

        let amount: u64 = 100;
        let decimals: u8 = 0;

        // Build a proper TransferChecked instruction
        let ix = spl_ix::transfer_checked(
            &spl_token::ID,
            &source, // source
            &mint,   // mint
            &dest,   // destination
            &auth,   // authority
            &[],     // signers
            amount,
            decimals,
        )
        .expect("build transfer_checked");

        assert!(super::spl_transfer_to_dest_matches(&ix, &dest, amount));
        assert!(!super::spl_transfer_to_dest_matches(&ix, &dest, amount + 1));
    }

    #[test]
    fn spl_transfer_plain_ok() {
        // Prepare pubkeys
        let source = SdkPubkey::new_unique();
        let dest = SdkPubkey::new_unique();
        let auth = SdkPubkey::new_unique();

        let amount: u64 = 42;

        // Build a plain Transfer instruction
        let ix = spl_ix::transfer(
            &spl_token::ID,
            &source, // source
            &dest,   // destination
            &auth,   // authority
            &[],     // signers
            amount,
        )
        .expect("build transfer");

        assert!(super::spl_transfer_to_dest_matches(&ix, &dest, amount));
        assert!(!super::spl_transfer_to_dest_matches(&ix, &dest, amount + 1));
    }
}

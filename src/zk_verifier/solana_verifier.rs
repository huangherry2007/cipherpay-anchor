//! BPF-safe Groth16 adapter using the local `groth16.rs`.
//! - vk.bin: BIG-ENDIAN limbs (α1 | β2 | γ2 | δ2 | IC[0..n])
//! - proof/publics on wire: LITTLE-ENDIAN 32B limbs
//! - We convert LE→BE per 32B limb, negate A.y, and try B0/B1 (G2 limb order).

#![allow(clippy::needless_range_loop)]

extern crate alloc;
use alloc::vec::Vec;
use anchor_lang::prelude::msg;

// === Use your local verifier module ===
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

const NEGATE_A_Y: bool = true;
const SWAP_PROOF_B: bool = true; // B1
const SWAP_VK_G2:   bool = true; // VK1

// ---- Sizes ------------------------------------------------------------------
pub const BYTES_F: usize = 32;
pub const BYTES_G1: usize = 64;
pub const BYTES_G2: usize = 128;
pub const BYTES_PROOF: usize = BYTES_G1 + BYTES_G2 + BYTES_G1;
pub const MAX_IC: usize = 64;

// ---- Circuit-specific public counts ----------------------------------------
pub const DEPOSIT_N_PUBLIC: usize = 6;
pub const TRANSFER_N_PUBLIC: usize = 8;  // TODO: set real value
pub const WITHDRAW_N_PUBLIC: usize = 8;  // TODO: set real value

// ---- Public signal indices (adjust if your order differs) -------------------
pub mod deposit_idx {
    pub const NEW_COMMITMENT: usize        = 0;
    pub const OWNER_CIPHERPAY_PUBKEY: usize = 1;
    pub const NEW_MERKLE_ROOT: usize       = 2;
    pub const NEW_NEXT_LEAF_INDEX: usize   = 3;
    pub const AMOUNT: usize                = 4;
    pub const DEPOSIT_HASH: usize          = 5;
}
pub mod transfer_idx { pub const _PLACEHOLDER: usize = 0; }
pub mod withdraw_idx { pub const _PLACEHOLDER: usize = 0; }

// -------------------- Little helpers (LE/BE & math) -------------------------
const BN254_FQ_MOD_BE: [u8; 32] = [
    0x30,0x64,0x4e,0x72,0xe1,0x31,0xa0,0x29,0xb8,0x50,0x45,0xb6,0x81,0x81,0x58,0x5d,
    0x97,0x81,0x6a,0x91,0x68,0x71,0xca,0x8d,0x3c,0x20,0x8c,0x16,0xd8,0x7c,0xfd,0x47,
];

#[inline] fn le32_to_be32(le: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = le[31 - i]; }
    out
}
#[inline] fn le64_to_be64_xy(le: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&le32_to_be32(&le[..32]));
    out[32..].copy_from_slice(&le32_to_be32(&le[32..64]));
    out
}
/// y := (p - y) mod p  (big-endian limb). If y == 0, keep 0.
fn negate_fq_be_in_place(y: &mut [u8; 32]) {
    if y.iter().all(|&b| b == 0) { return; }
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let p = BN254_FQ_MOD_BE[i] as i16;
        let yi = y[i] as i16;
        let mut diff = p as i32 - yi as i32 - borrow as i32;
        if diff < 0 { diff += 256; borrow = 1; } else { borrow = 0; }
        y[i] = diff as u8;
    }
}

// ---- Public inputs & proof (LE on wire) ------------------------------------
pub fn parse_public_signals_exact(bytes: &[u8]) -> Result<Vec<[u8; 32]>, &'static str> {
    if bytes.len() % BYTES_F != 0 { return Err("public inputs len not multiple of 32"); }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for i in (0..bytes.len()).step_by(32) {
        out.push(bytes[i..i+32].try_into().map_err(|_| "bad 32B slice")?);
    }
    Ok(out)
}
pub fn extract_public_input(bytes: &[u8], idx: usize) -> Result<[u8; 32], &'static str> {
    bytes.get(idx*BYTES_F .. (idx+1)*BYTES_F)
        .ok_or("index OOB")
        .and_then(|s| s.try_into().map_err(|_| "bad 32B"))
}
pub fn parse_proof_bytes(proof_le: &[u8]) -> Result<(&[u8; 64], &[u8; 128], &[u8; 64]), &'static str> {
    if proof_le.len() != BYTES_PROOF { return Err("bad proof len"); }
    let a = proof_le.get(0..64).ok_or("OOB")?.try_into().map_err(|_| "bad 64B")?;
    let b = proof_le.get(64..192).ok_or("OOB")?.try_into().map_err(|_| "bad 128B")?;
    let c = proof_le.get(192..256).ok_or("OOB")?.try_into().map_err(|_| "bad 64B")?;
    Ok((a, b, c))
}

// ---- VK.bin parsing (BE on disk) -------------------------------------------
fn ic_count_from_vk(vk_be: &[u8]) -> Result<usize, &'static str> {
    if vk_be.len() < BYTES_G1 + 3*BYTES_G2 + BYTES_G1 { return Err("vk too short"); }
    let rem = vk_be.len() - (BYTES_G1 + 3*BYTES_G2);
    if rem % BYTES_G1 != 0 { return Err("IC remainder not multiple of 64"); }
    Ok(rem / BYTES_G1)
}

/// Return (alpha, beta, gamma, delta, IC_vec)
fn parse_vk_parts(vk_be: &[u8]) -> Result<([u8;64],[u8;128],[u8;128],[u8;128], Vec<[u8;64]>), &'static str> {
    let ic = ic_count_from_vk(vk_be)?;
    let mut off = 0usize;
    let mut take = |n: usize| -> Result<&[u8], &'static str> {
        if off + n > vk_be.len() { return Err("vk parse OOB"); }
        let s = &vk_be[off .. off+n]; off += n; Ok(s)
    };
    let mut alpha = [0u8; 64]; alpha.copy_from_slice(take(BYTES_G1)?);
    let mut beta  = [0u8;128]; beta .copy_from_slice(take(BYTES_G2)?);
    let mut gamma = [0u8;128]; gamma.copy_from_slice(take(BYTES_G2)?);
    let mut delta = [0u8;128]; delta.copy_from_slice(take(BYTES_G2)?);

    let mut ic_vec: Vec<[u8;64]> = Vec::with_capacity(ic);
    for _ in 0..ic {
        let mut g1 = [0u8; 64];
        g1.copy_from_slice(take(BYTES_G1)?);
        ic_vec.push(g1);
    }
    Ok((alpha, beta, gamma, delta, ic_vec))
}

// ---- G2 limb swap for B (BE) — borrow-friendly -----------------------------
/// swap 32B block at i with 32B block at j, using split_at_mut for disjoint borrows (requires i < j)
fn swap32_in_place(slice: &mut [u8], i: usize, j: usize) {
    debug_assert!(i + 32 <= j); // we only call with (0,32) and (64,96)
    let (left, right) = slice.split_at_mut(j);
    let (li, r0) = (&mut left[i .. i+32], &mut right[0 .. 32]);
    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(li);
    li.copy_from_slice(r0);
    r0.copy_from_slice(&tmp);
}
fn swap_g2_inner_limbs_be(mut b: [u8; 128]) -> [u8; 128] {
    // x: [0..32]=c0, [32..64]=c1 ; y: [64..96]=c0, [96..128]=c1
    swap32_in_place(&mut b, 0, 32);
    swap32_in_place(&mut b, 64, 96);
    b
}

// -------------------- Core verify (const-generic N) -------------------------
fn verify_once_const<const N: usize>(vk_be: &[u8], proof_le: &[u8], public_le: &[u8]) -> Result<(), &'static str> {
    if proof_le.len() != BYTES_PROOF { return Err("proof must be 256 bytes"); }
    if public_le.len() != N * BYTES_F { return Err("public inputs length mismatch"); }

    let (alpha_be, beta_be, gamma_be, delta_be, ic_vec) = parse_vk_parts(vk_be)?;
    if ic_vec.len() != N + 1 { return Err("vk.ic count != N+1"); }
    if ic_vec.len() > MAX_IC { return Err("vk.ic too large"); }

    let vk = Groth16Verifyingkey {
        nr_pubinputs: ic_vec.len().saturating_sub(1),
        vk_alpha_g1: alpha_be,
        vk_beta_g2:  if SWAP_VK_G2 { swap_g2_inner_limbs_be(beta_be)  } else { beta_be  },
        vk_gamme_g2: if SWAP_VK_G2 { swap_g2_inner_limbs_be(gamma_be) } else { gamma_be },
        vk_delta_g2: if SWAP_VK_G2 { swap_g2_inner_limbs_be(delta_be) } else { delta_be },
        vk_ic: &ic_vec,
    };

    // publics: LE -> BE
    let mut publics_vec = Vec::<[u8; 32]>::with_capacity(N);
    for i in 0..N { publics_vec.push(le32_to_be32(&public_le[i*32 .. (i+1)*32])); }
    let publics: &[[u8; 32]; N] = publics_vec.as_slice().try_into().map_err(|_| "publics slice to array failed")?;

    // proof A/B/C
    let (a_le, b_le, c_le) = parse_proof_bytes(proof_le)?;

    // A: LE->BE, y := p - y if enabled
    let mut a_be = le64_to_be64_xy(a_le);
    if NEGATE_A_Y {
        let mut ay = [0u8; 32];
        ay.copy_from_slice(&a_be[32..64]);
        negate_fq_be_in_place(&mut ay);
        a_be[32..64].copy_from_slice(&ay);
    }

    // B: LE limbs -> BE limbs; swap inner limbs if enabled
    let mut b_be = [0u8; BYTES_G2];
    b_be[  0.. 32].copy_from_slice(&le32_to_be32(&b_le[ 0.. 32]));
    b_be[ 32.. 64].copy_from_slice(&le32_to_be32(&b_le[32.. 64]));
    b_be[ 64.. 96].copy_from_slice(&le32_to_be32(&b_le[64.. 96]));
    b_be[ 96..128].copy_from_slice(&le32_to_be32(&b_le[96..128]));
    if SWAP_PROOF_B { b_be = swap_g2_inner_limbs_be(b_be); }

    // C: LE->BE
    let c_be = le64_to_be64_xy(c_le);

    let mut verifier = Groth16Verifier::<N>::new(&a_be, &b_be, &c_be, publics, &vk)
        .map_err(|_| "verifier new failed")?;
    verifier.verify().map_err(|_| "pairing failed")
}

// -------------------- Public wrappers per circuit ---------------------------
const DEPOSIT_VK_BIN: &[u8]  = include_bytes!("deposit_vk.bin");
const TRANSFER_VK_BIN: &[u8] = include_bytes!("transfer_vk.bin");  // add when ready
const WITHDRAW_VK_BIN: &[u8] = include_bytes!("withdraw_vk.bin");  // add when ready

pub fn verify_deposit(proof_le: &[u8], public_le: &[u8]) -> Result<(), &'static str> {
    verify_once_const::<{ DEPOSIT_N_PUBLIC }>(DEPOSIT_VK_BIN, proof_le, public_le)
}
pub fn verify_transfer(proof_le: &[u8], public_le: &[u8]) -> Result<(), &'static str> {
    verify_once_const::<{ TRANSFER_N_PUBLIC }>(TRANSFER_VK_BIN, proof_le, public_le)
}
pub fn verify_withdraw(proof_le: &[u8], public_le: &[u8]) -> Result<(), &'static str> {
    verify_once_const::<{ WITHDRAW_N_PUBLIC }>(WITHDRAW_VK_BIN, proof_le, public_le)
}

// Thin shims if your crate calls these names
pub fn verify_deposit_payload(p: &[u8], s: &[u8]) -> Result<(), &'static str> { verify_deposit(p, s) }
pub fn verify_transfer_payload(p: &[u8], s: &[u8]) -> Result<(), &'static str> { verify_transfer(p, s) }
pub fn verify_withdraw_payload(p: &[u8], s: &[u8]) -> Result<(), &'static str> { verify_withdraw(p, s) }

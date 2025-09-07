//! Solana-native Groth16 verification (BN254) for CipherPay.
//! Uses the `groth16-solana` crate and Solana's altbn254 syscalls.

use anchor_lang::prelude::*;
use solana_program::msg;

use crate::CipherPayError;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

// ============================ byte sizes / layout ============================

const BYTES_F: usize = 32;       // field element limb
pub const BYTES_G1: usize = 64;  // (x,y)
pub const BYTES_G2: usize = 128; // (x.c0, x.c1, y.c0, y.c1)
pub const BYTES_PROOF: usize = BYTES_G1 + BYTES_G2 + BYTES_G1; // 256

// Maximum number of IC elements (upper bound sanity; not enforced here)
pub const MAX_IC: usize = 20;

// ============================= circuit metadata =============================

pub const DEPOSIT_N_PUBLIC: usize = 6; // [newCommitment, ownerCipherPayPubKey, newMerkleRoot, newNextLeafIndex, amount, depositHash]
pub const TRANSFER_N_PUBLIC: usize = 9;
pub const WITHDRAW_N_PUBLIC: usize = 5;

pub mod deposit_idx {
    pub const NEW_COMMITMENT: usize = 0;
    pub const OWNER_CIPHERPAY_PUBKEY: usize = 1;
    pub const NEW_MERKLE_ROOT: usize = 2;
    pub const NEW_NEXT_LEAF_INDEX: usize = 3;
    pub const AMOUNT: usize = 4;
    pub const DEPOSIT_HASH: usize = 5;
}
pub mod transfer_idx {
    pub const OUT_COMMITMENT1: usize = 0;
    pub const OUT_COMMITMENT2: usize = 1;
    pub const NULLIFIER: usize = 2;
    pub const MERKLE_ROOT: usize = 3;
    pub const NEW_MERKLE_ROOT1: usize = 4;
    pub const NEW_MERKLE_ROOT2: usize = 5;
    pub const NEW_NEXT_LEAF_IDX: usize = 6;
    pub const ENC_NOTE1_HASH: usize = 7;
    pub const ENC_NOTE2_HASH: usize = 8;
}
pub mod withdraw_idx {
    pub const NULLIFIER: usize = 0;
    pub const MERKLE_ROOT: usize = 1;
    pub const RECIPIENT_WALLET_PUBKEY: usize = 2;
    pub const AMOUNT: usize = 3;
    pub const TOKEN_ID: usize = 4;
}

// Verifying key blobs (must be generated with the crate’s parse-vk tool; BE limbs, correct limb order)
pub const DEPOSIT_VK_BIN: &[u8] = include_bytes!("deposit_vk.bin");
pub const TRANSFER_VK_BIN: &[u8] = include_bytes!("transfer_vk.bin");
pub const WITHDRAW_VK_BIN: &[u8] = include_bytes!("withdraw_vk.bin");

// =============================== endian helpers =============================

/// Reverse a single 32-byte limb (LE <-> BE).
#[inline]
fn rev32(input: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = input[31 - i];
    }
    out
}

/// Convert a G1 point from LE limbs on the wire to BE limbs (x||y), per 32-byte limb.
#[inline]
fn le_g1_to_be(g1_le: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&rev32(g1_le[..32].try_into().unwrap()));
    out[32..].copy_from_slice(&rev32(g1_le[32..].try_into().unwrap()));
    out
}

/// Convert a G2 point from LE limbs on the wire to BE limbs (x.c0, x.c1, y.c0, y.c1),
/// reversing each 32-byte limb.
#[inline]
fn le_g2_to_be(g2_le: &[u8; 128]) -> [u8; 128] {
    let mut out = [0u8; 128];
    for i in 0..4 {
        let start = i * 32;
        out[start..start + 32].copy_from_slice(&rev32(g2_le[start..start + 32].try_into().unwrap()));
    }
    out
}

// =============================== math helpers ===============================

// BN254 base field modulus (Fq) in big-endian bytes:
const FQ_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4E, 0x72, 0xE1, 0x31, 0xA0, 0x29, 0xB8, 0x50, 0x45, 0xB6, 0x81, 0x81, 0x58, 0x5D,
    0x97, 0x81, 0x6A, 0x91, 0x68, 0x71, 0xCA, 0x8D, 0x3C, 0x20, 0x8C, 0x16, 0xD8, 0x7C, 0xFD, 0x47,
];

#[inline]
fn is_zero32(x: &[u8; 32]) -> bool {
    x.iter().all(|&b| b == 0)
}

#[inline]
fn be_sub_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // returns (a - b) mod 2^256 (caller ensures a >= b over Fq range)
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let ai = a[i] as u16;
        let bi = b[i] as u16;
        let tmp = ai.wrapping_sub(bi).wrapping_sub(borrow);
        borrow = if ai < bi + borrow { 1 } else { 0 };
        out[i] = (tmp & 0xFF) as u8;
    }
    out
}

/// Negate a BE G1 point (x||y) -> (x||-y) in BN254 (special case y=0 -> 0).
#[inline]
fn negate_g1_a_be(a_be: &[u8; BYTES_G1]) -> [u8; BYTES_G1] {
    let (x, y) = a_be.split_at(32);
    let mut out = [0u8; BYTES_G1];
    out[..32].copy_from_slice(x);
    let y32: [u8; 32] = y.try_into().unwrap();
    let y_neg = if is_zero32(&y32) { y32 } else { be_sub_32(&FQ_MODULUS_BE, &y32) };
    out[32..].copy_from_slice(&y_neg);
    out
}

// =============================== core helpers ===============================

/// Parse proof = A||B||C with sizes (64,128,64) — *no endianness change here*.
pub fn parse_proof_bytes(bytes: &[u8]) -> Result<([u8; BYTES_G1], [u8; BYTES_G2], [u8; BYTES_G1])> {
    if bytes.len() != BYTES_PROOF {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    let mut a = [0u8; BYTES_G1];
    let mut b = [0u8; BYTES_G2];
    let mut c = [0u8; BYTES_G1];
    a.copy_from_slice(&bytes[0..BYTES_G1]);
    b.copy_from_slice(&bytes[BYTES_G1..BYTES_G1 + BYTES_G2]);
    c.copy_from_slice(&bytes[BYTES_G1 + BYTES_G2..BYTES_PROOF]);
    Ok((a, b, c))
}

/// Parse bytes into N 32B limbs (no conversion).
pub fn parse_public_signals_exact(bytes: &[u8]) -> Result<Vec<[u8; BYTES_F]>> {
    if bytes.len() % BYTES_F != 0 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    let n = bytes.len() / BYTES_F;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut limb = [0u8; BYTES_F];
        limb.copy_from_slice(&bytes[i * BYTES_F..(i + 1) * BYTES_F]);
        out.push(limb);
    }
    Ok(out)
}

/// Same as above but returns a fixed-size array for const-generic verifier.
fn parse_public_signals_array<const N: usize>(bytes: &[u8]) -> Result<[[u8; BYTES_F]; N]> {
    if bytes.len() != N * BYTES_F {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    let mut out = [[0u8; BYTES_F]; N];
    for i in 0..N {
        out[i].copy_from_slice(&bytes[i * BYTES_F..(i + 1) * BYTES_F]);
    }
    Ok(out)
}

/// Read a specific public input (bounds-checked).
#[inline]
pub fn extract_public_input(public_inputs: &[[u8; BYTES_F]], index: usize) -> Result<[u8; BYTES_F]> {
    public_inputs.get(index).cloned().ok_or(CipherPayError::InvalidZkProof.into())
}

/// Convenience for small amounts encoded in the first 8 bytes (LE).
#[inline]
pub fn extract_amount_u64(public_inputs: &[[u8; BYTES_F]], index: usize) -> Result<u64> {
    let limb = extract_public_input(public_inputs, index)?;
    let mut x = 0u64;
    for i in 0..8 {
        x |= (limb[i] as u64) << (8 * i);
    }
    Ok(x)
}

/// Parse public inputs from bytes (legacy helper).
pub fn parse_public_inputs(bytes: &[u8], expected_count: usize) -> Result<Vec<[u8; BYTES_F]>> {
    if bytes.len() != expected_count * BYTES_F {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    let mut inputs = Vec::with_capacity(expected_count);
    for i in 0..expected_count {
        let mut input = [0u8; BYTES_F];
        let start = i * BYTES_F;
        input.copy_from_slice(&bytes[start..start + BYTES_F]);
        inputs.push(input);
    }
    Ok(inputs)
}

// ========================== verifying key deserializer =======================
//
// The groth16-solana VK struct wants BE limbs for:
//   - alpha_g1 (64B), beta_g2 (128B), gamma_g2 (128B), delta_g2 (128B)
//   - vk_ic: &'static [[u8; 64]]  (G1 IC points)
// Make sure your *binary vk* comes from the crate’s parse-vk tool.
//

pub fn parse_verifying_key(vk_bytes: &[u8]) -> Result<Groth16Verifyingkey> {
    let min_size = BYTES_G1 + 3 * BYTES_G2 + BYTES_G1;
    if vk_bytes.len() < min_size {
        return Err(CipherPayError::InvalidZkProof.into());
    }

    let mut off = 0;

    let mut vk_alpha_g1 = [0u8; BYTES_G1];
    vk_alpha_g1.copy_from_slice(&vk_bytes[off..off + BYTES_G1]);
    off += BYTES_G1;

    let mut vk_beta_g2 = [0u8; BYTES_G2];
    vk_beta_g2.copy_from_slice(&vk_bytes[off..off + BYTES_G2]);
    off += BYTES_G2;

    let mut vk_gamma_g2 = [0u8; BYTES_G2];
    vk_gamma_g2.copy_from_slice(&vk_bytes[off..off + BYTES_G2]);
    off += BYTES_G2;

    let mut vk_delta_g2 = [0u8; BYTES_G2];
    vk_delta_g2.copy_from_slice(&vk_bytes[off..off + BYTES_G2]);
    off += BYTES_G2;

    let ic_bytes = &vk_bytes[off..];
    let ic_count = ic_bytes.len() / BYTES_G1;
    if ic_count == 0 || ic_count > MAX_IC {
        msg!("parse_verifying_key: invalid IC count: 0 or > {}", MAX_IC);
        return Err(CipherPayError::InvalidZkProof.into());
    }
    msg!("parse_verifying_key: IC count = {}", ic_count);

    // Build 'static vk_ic
    let mut vk_ic_vec: Vec<[u8; BYTES_G1]> = Vec::with_capacity(ic_count);
    for i in 0..ic_count {
        let mut arr = [0u8; BYTES_G1];
        let start = i * BYTES_G1;
        if start + BYTES_G1 > ic_bytes.len() {
            msg!("parse_verifying_key: IC element {} out of bounds", i);
            return Err(CipherPayError::InvalidZkProof.into());
        }
        arr.copy_from_slice(&ic_bytes[start..start + BYTES_G1]);
        vk_ic_vec.push(arr);
    }
    let vk_ic_static: &'static [[u8; BYTES_G1]] = Box::leak(vk_ic_vec.into_boxed_slice());

    Ok(Groth16Verifyingkey {
        nr_pubinputs: ic_count - 1,
        vk_alpha_g1,
        vk_beta_g2,
        vk_gamme_g2: vk_gamma_g2, // NOTE: field name as defined in the crate
        vk_delta_g2,
        vk_ic: vk_ic_static,
    })
}

// ============================== verification API ============================

/// Core verifier: accepts proof parts (BE), *LE* public inputs (we convert to BE), and VK bytes.
/// Const-generic over the number of public inputs so it matches the VK.
/// NOTE: groth16-solana expects **-A**; we negate Y coordinate byte-wise.
pub fn verify_groth16_proof<const N: usize>(
    proof_a_be: &[u8; BYTES_G1],
    proof_b_be: &[u8; BYTES_G2],
    proof_c_be: &[u8; BYTES_G1],
    public_inputs_le: &[[u8; BYTES_F]; N],
    verifying_key_bytes: &[u8],
) -> Result<()> {
    msg!("verify_groth16_proof: starting verification");
    msg!("verify_groth16_proof: public_inputs.len() = {}", N);
    msg!("verify_groth16_proof: verifying_key_bytes.len() = {}", verifying_key_bytes.len());

    // Parse VK (BE limbs)
    let vk = parse_verifying_key(verifying_key_bytes)?;
    msg!("verify_groth16_proof: verifying key parsed successfully");

    if N != vk.nr_pubinputs {
        msg!(
            "verify_groth16_proof: inputs mismatch: got {}, vk expects {}",
            N,
            vk.nr_pubinputs
        );
        return Err(CipherPayError::InvalidZkProof.into());
    }

    // Convert public inputs LE -> BE (canonical 32B)
    let mut public_inputs_be = [[0u8; BYTES_F]; N];
    for i in 0..N {
        public_inputs_be[i] = rev32(&public_inputs_le[i]);
    }
    msg!("verify_groth16_proof: converted public inputs LE->BE");

    // Negate A (A -> -A) at byte level: (x, y) -> (x, p - y), with -0 = 0
    let a_neg_be = negate_g1_a_be(proof_a_be);

    // Build verifier
    msg!(
        "verify_groth16_proof: vk.nr_pubinputs = {}, vk.vk_ic.len() = {}",
        vk.nr_pubinputs,
        vk.vk_ic.len()
    );

    let mut verifier = Groth16Verifier::new(&a_neg_be, proof_b_be, proof_c_be, &public_inputs_be, &vk)
        .map_err(|e| {
            msg!("verify_groth16_proof: Groth16Verifier::new failed: {:?}", e);
            CipherPayError::InvalidZkProof
        })?;
    msg!("verify_groth16_proof: Groth16Verifier created successfully");

    // Verify
    msg!("verify_groth16_proof: calling verifier.verify()...");
    verifier.verify().map_err(|e| {
        msg!("verify_groth16_proof: verifier.verify() failed: {:?}", e);
        CipherPayError::InvalidZkProof
    })?;
    msg!("verify_groth16_proof: verification successful!");
    Ok(())
}

/// Verify a payload = [proof(256) || public_signals(N * 32)].
/// Proof parts are **LE on the wire** (we flip to BE here); public signals are **LE on the wire**.
pub fn verify_groth16_payload<const N: usize>(payload: &[u8], verifying_key_bytes: &[u8]) -> Result<()> {
    let needed = BYTES_PROOF + N * BYTES_F;
    if payload.len() != needed {
        msg!("payload length {} != expected {}", payload.len(), needed);
        return Err(CipherPayError::InvalidZkProof.into());
    }

    let (proof, sigs_bytes) = payload.split_at(BYTES_PROOF);
    let (a_le, b_le, c_le) = parse_proof_bytes(proof)?; // LE split only

    // Flip proof limbs to BE for groth16-solana
    let a_be = le_g1_to_be(&a_le);
    let b_be = le_g2_to_be(&b_le);
    let c_be = le_g1_to_be(&c_le);

    // Public signals are LE on wire (we flip inside verify_groth16_proof)
    let sigs_le = parse_public_signals_array::<N>(sigs_bytes)?;
    verify_groth16_proof::<N>(&a_be, &b_be, &c_be, &sigs_le, verifying_key_bytes)
}

// ============================== nice wrappers ===============================

#[inline]
pub fn verify_deposit_payload(payload: &[u8]) -> Result<()> {
    verify_groth16_payload::<{ DEPOSIT_N_PUBLIC }>(payload, DEPOSIT_VK_BIN)
}

#[inline]
pub fn verify_transfer_payload(payload: &[u8]) -> Result<()> {
    verify_groth16_payload::<{ TRANSFER_N_PUBLIC }>(payload, TRANSFER_VK_BIN)
}

#[inline]
pub fn verify_withdraw_payload(payload: &[u8]) -> Result<()> {
    verify_groth16_payload::<{ WITHDRAW_N_PUBLIC }>(payload, WITHDRAW_VK_BIN)
}

#[inline]
pub fn verify_deposit(proof_bytes: &[u8], public_signals_bytes: &[u8]) -> Result<()> {
    msg!(
        "verify_deposit: proof_bytes.len() = {}, public_signals_bytes.len() = {}",
        proof_bytes.len(),
        public_signals_bytes.len()
    );

    if public_signals_bytes.len() != DEPOSIT_N_PUBLIC * BYTES_F {
        msg!(
            "deposit: unexpected public signals length: {} != {}",
            public_signals_bytes.len(),
            DEPOSIT_N_PUBLIC * BYTES_F
        );
        return Err(CipherPayError::InvalidZkProof.into());
    }

    let (a_le, b_le, c_le) = parse_proof_bytes(proof_bytes)?; // LE
    let a_be = le_g1_to_be(&a_le);
    let b_be = le_g2_to_be(&b_le);
    let c_be = le_g1_to_be(&c_le);

    let sigs_le = parse_public_signals_array::<{ DEPOSIT_N_PUBLIC }>(public_signals_bytes)?;
    verify_groth16_proof::<{ DEPOSIT_N_PUBLIC }>(&a_be, &b_be, &c_be, &sigs_le, DEPOSIT_VK_BIN)
}

#[inline]
pub fn verify_transfer(proof_bytes: &[u8], public_signals_bytes: &[u8]) -> Result<()> {
    if public_signals_bytes.len() != TRANSFER_N_PUBLIC * BYTES_F {
        msg!("transfer: unexpected public signals length");
        return Err(CipherPayError::InvalidZkProof.into());
    }

    let (a_le, b_le, c_le) = parse_proof_bytes(proof_bytes)?; // LE
    let a_be = le_g1_to_be(&a_le);
    let b_be = le_g2_to_be(&b_le);
    let c_be = le_g1_to_be(&c_le);

    let sigs_le = parse_public_signals_array::<{ TRANSFER_N_PUBLIC }>(public_signals_bytes)?;
    verify_groth16_proof::<{ TRANSFER_N_PUBLIC }>(&a_be, &b_be, &c_be, &sigs_le, TRANSFER_VK_BIN)
}

#[inline]
pub fn verify_withdraw(proof_bytes: &[u8], public_signals_bytes: &[u8]) -> Result<()> {
    if public_signals_bytes.len() != WITHDRAW_N_PUBLIC * BYTES_F {
        msg!("withdraw: unexpected public signals length");
        return Err(CipherPayError::InvalidZkProof.into());
    }

    let (a_le, b_le, c_le) = parse_proof_bytes(proof_bytes)?; // LE
    let a_be = le_g1_to_be(&a_le);
    let b_be = le_g2_to_be(&b_le);
    let c_be = le_g1_to_be(&c_le);

    let sigs_le = parse_public_signals_array::<{ WITHDRAW_N_PUBLIC }>(public_signals_bytes)?;
    verify_groth16_proof::<{ WITHDRAW_N_PUBLIC }>(&a_be, &b_be, &c_be, &sigs_le, WITHDRAW_VK_BIN)
}

// =================================== tests ==================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_split_lengths_ok() {
        let p = vec![0u8; BYTES_PROOF];
        let (a, b, c) = parse_proof_bytes(&p).unwrap();
        assert_eq!(a.len(), BYTES_G1);
        assert_eq!(b.len(), BYTES_G2);
        assert_eq!(c.len(), BYTES_G1);
    }

    #[test]
    fn signals_parse_ok() {
        let mut limbs = vec![0u8; 3 * BYTES_F];
        limbs[0] = 1;
        let v = parse_public_signals_exact(&limbs).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0][0], 1);
    }

    #[test]
    fn amount_le_ok() {
        let mut limb = [0u8; BYTES_F];
        limb[0] = 100;
        let v = vec![limb];
        assert_eq!(extract_amount_u64(&v, 0).unwrap(), 100);
    }
}

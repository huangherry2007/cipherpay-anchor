// tests/zk_verifier_tests.rs

#![allow(clippy::uninlined_format_args)]

use anchor_lang::solana_program::keccak::hash;
use cipherpay_anchor::zk_verifier::solana_verifier;

// --- VKs (BE) for quick sanity printing ---
const DEPOSIT_VK_BE:  &[u8] = include_bytes!("../src/zk_verifier/deposit_vk.bin");
const TRANSFER_VK_BE: &[u8] = include_bytes!("../src/zk_verifier/transfer_vk.bin");
const WITHDRAW_VK_BE: &[u8] = include_bytes!("../src/zk_verifier/withdraw_vk.bin");

// --- Wire blobs (LE) produced by your scripts ---
const DEPOSIT_PROOF_LE:    &[u8] = include_bytes!("../proofs/deposit_proof.bin");
const DEPOSIT_PUBLICS_LE:  &[u8] = include_bytes!("../proofs/deposit_public_signals.bin");

const TRANSFER_PROOF_LE:   &[u8] = include_bytes!("../proofs/transfer_proof.bin");
const TRANSFER_PUBLICS_LE: &[u8] = include_bytes!("../proofs/transfer_public_signals.bin");

const WITHDRAW_PROOF_LE:   &[u8] = include_bytes!("../proofs/withdraw_proof.bin");
const WITHDRAW_PUBLICS_LE: &[u8] = include_bytes!("../proofs/withdraw_public_signals.bin");

// ---------- tiny helpers ----------
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}
fn be32_to_hex_prefixed(b32: &[u8]) -> String {
    assert_eq!(b32.len(), 32);
    format!("0x{}", hex(b32))
}
fn le32_to_hex_prefixed(l32: &[u8]) -> String {
    assert_eq!(l32.len(), 32);
    let mut be = [0u8; 32];
    for i in 0..32 { be[i] = l32[31 - i]; }
    be32_to_hex_prefixed(&be)
}

/// Return a copy of `proof` with the G2 inner limbs of B pre-swapped on the **wire** (LE).
/// Layout on wire: A(0..64) | B(64..192) | C(192..256)
/// B chunks (each 32B): [ bx.c0 | bx.c1 | by.c0 | by.c1 ]
/// Implemented with split_at_mut to avoid overlapping &mut borrows.
fn preswap_b_on_wire(proof: &[u8]) -> Vec<u8> {
    assert_eq!(proof.len(), solana_verifier::BYTES_PROOF);
    let mut out = proof.to_vec();

    // Slice to B region (128 bytes)
    let b_region: &mut [u8] = &mut out[64..192];

    // Split B into bx (0..64) and by (64..128)
    let (bx, by) = b_region.split_at_mut(64);

    // bx: [c0(0..32) | c1(32..64)]
    {
        let (bx_c0, bx_c1) = bx.split_at_mut(32);
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(bx_c0);
        bx_c0.copy_from_slice(bx_c1);
        bx_c1.copy_from_slice(&tmp);
    }

    // by: [c0(0..32) | c1(32..64)]
    {
        let (by_c0, by_c1) = by.split_at_mut(32);
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(by_c0);
        by_c0.copy_from_slice(by_c1);
        by_c1.copy_from_slice(&tmp);
    }

    out
}

/// Flip one byte at `i` in a copy of `bytes`.
fn corrupt_at(bytes: &[u8], i: usize) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v[i] ^= 0x01;
    v
}

/// Corrupt exactly one 32-byte public signal limb (by index, 0-based).
fn corrupt_public_at_index(publics_le: &[u8], limb_index: usize) -> Vec<u8> {
    let mut v = publics_le.to_vec();
    let start = limb_index * solana_verifier::BYTES_F;
    assert!(start + solana_verifier::BYTES_F <= v.len());
    v[start + solana_verifier::BYTES_F - 1] ^= 0x01;
    v
}

// ======================= DEPOSIT (positive) =======================

#[test]
fn vk_endianness_sanity_and_verify_deposit() {
    assert!(DEPOSIT_VK_BE.len() >= 64, "vk.bin too short for alpha");
    let alpha_x_be = &DEPOSIT_VK_BE[0..32];
    println!("alpha.x (BE) = {}", be32_to_hex_prefixed(alpha_x_be));

    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(alpha_x_be);
    tmp.reverse();
    println!("alpha.x (LE) = {}", be32_to_hex_prefixed(&tmp));

    let vk_hash = hash(DEPOSIT_VK_BE);
    let vk_hex_arr: Vec<String> = vk_hash.0.iter().map(|b| format!("{:02x}", b)).collect();
    println!("vk.bin keccak256 = [{}]", vk_hex_arr.join(", "));

    println!("proof.len={} publics.len={}", DEPOSIT_PROOF_LE.len(), DEPOSIT_PUBLICS_LE.len());
    assert_eq!(DEPOSIT_PROOF_LE.len(), solana_verifier::BYTES_PROOF, "bad proof length");
    assert_eq!(DEPOSIT_PUBLICS_LE.len(), solana_verifier::BYTES_F * solana_verifier::DEPOSIT_N_PUBLIC, "bad publics length");

    let a0 = &DEPOSIT_PROOF_LE[0..32];
    let a1 = &DEPOSIT_PROOF_LE[32..64];
    println!("[proof[0..64]][0..32] {}", hex(a0));
    println!("[proof[0..64]][32..64] {}", hex(a1));

    let p0 = &DEPOSIT_PUBLICS_LE[0..32];
    let p1 = &DEPOSIT_PUBLICS_LE[32..64];
    println!("[publics[0..64]][0..32] {}", hex(p0));
    println!("[publics[0..64]][32..64] {}", hex(p1));

    solana_verifier::verify_deposit(DEPOSIT_PROOF_LE, DEPOSIT_PUBLICS_LE)
        .expect("off-chain verify_deposit failed");
    println!("verify_deposit: OK");
}

// ======================= DEPOSIT (negative) =======================

#[test]
fn verify_deposit_fails_if_publics_corrupted() {
    let bad_publics = corrupt_public_at_index(
        DEPOSIT_PUBLICS_LE,
        solana_verifier::DEPOSIT_N_PUBLIC - 1
    );
    let res = solana_verifier::verify_deposit(DEPOSIT_PROOF_LE, &bad_publics);
    assert!(res.is_err(), "deposit verification unexpectedly succeeded with corrupted publics");
    println!("verify_deposit (corrupted publics): {:?}", res.err());
}

#[test]
fn verify_deposit_fails_if_proof_byte_flipped() {
    let bad_proof = corrupt_at(DEPOSIT_PROOF_LE, 5);
    let res = solana_verifier::verify_deposit(&bad_proof, DEPOSIT_PUBLICS_LE);
    assert!(res.is_err(), "deposit verification unexpectedly succeeded with corrupted proof");
    println!("verify_deposit (corrupted proof): {:?}", res.err());
}

#[test]
fn verify_deposit_fails_if_b_is_preswapped() {
    let bad = preswap_b_on_wire(DEPOSIT_PROOF_LE);
    assert_eq!(bad.len(), DEPOSIT_PROOF_LE.len());
    let res = solana_verifier::verify_deposit(&bad, DEPOSIT_PUBLICS_LE);
    assert!(res.is_err(), "deposit verification unexpectedly succeeded with pre-swapped B");
    println!("verify_deposit (with pre-swapped B): {:?}", res.err());
}

// ======================= TRANSFER (positive) =======================

#[test]
fn vk_endianness_sanity_and_verify_transfer() {
    assert!(TRANSFER_VK_BE.len() >= 64, "vk.bin too short for alpha");
    let alpha_x_be = &TRANSFER_VK_BE[0..32];
    println!("alpha.x (BE) = {}", be32_to_hex_prefixed(alpha_x_be));

    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(alpha_x_be);
    tmp.reverse();
    println!("alpha.x (LE) = {}", be32_to_hex_prefixed(&tmp));

    let vk_hash = hash(TRANSFER_VK_BE);
    let vk_hex_arr: Vec<String> = vk_hash.0.iter().map(|b| format!("{:02x}", b)).collect();
    println!("vk.bin keccak256 = [{}]", vk_hex_arr.join(", "));

    println!("proof.len={} publics.len={}", TRANSFER_PROOF_LE.len(), TRANSFER_PUBLICS_LE.len());
    assert_eq!(TRANSFER_PROOF_LE.len(), solana_verifier::BYTES_PROOF, "bad proof length");
    assert_eq!(TRANSFER_PUBLICS_LE.len(), solana_verifier::BYTES_F * solana_verifier::TRANSFER_N_PUBLIC, "bad publics length");

    let a0 = &TRANSFER_PROOF_LE[0..32];
    let a1 = &TRANSFER_PROOF_LE[32..64];
    println!("[proof[0..64]][0..32] {}", hex(a0));
    println!("[proof[0..64]][32..64] {}", hex(a1));

    let p0 = &TRANSFER_PUBLICS_LE[0..32];
    let p1 = &TRANSFER_PUBLICS_LE[32..64];
    println!("[publics[0..64]][0..32] {}", hex(p0));
    println!("[publics[0..64]][32..64] {}", hex(p1));

    solana_verifier::verify_transfer(TRANSFER_PROOF_LE, TRANSFER_PUBLICS_LE)
        .expect("off-chain verify_transfer failed");
    println!("verify_transfer: OK");
}

// ======================= TRANSFER (negative) =======================

#[test]
fn verify_transfer_fails_if_b_is_preswapped() {
    let bad = preswap_b_on_wire(TRANSFER_PROOF_LE);
    assert_eq!(bad.len(), TRANSFER_PROOF_LE.len());
    let res = solana_verifier::verify_transfer(&bad, TRANSFER_PUBLICS_LE);
    assert!(res.is_err(), "transfer verification unexpectedly succeeded with pre-swapped B");
    println!("verify_transfer (with pre-swapped B): {:?}", res.err());
}

#[test]
fn verify_transfer_fails_if_publics_corrupted() {
    let bad_publics = corrupt_public_at_index(
        TRANSFER_PUBLICS_LE,
        solana_verifier::TRANSFER_N_PUBLIC - 1
    );
    let res = solana_verifier::verify_transfer(TRANSFER_PROOF_LE, &bad_publics);
    assert!(res.is_err(), "transfer verification unexpectedly succeeded with corrupted publics");
    println!("verify_transfer (corrupted publics): {:?}", res.err());
}

#[test]
fn verify_transfer_fails_if_proof_byte_flipped() {
    let bad_proof = corrupt_at(TRANSFER_PROOF_LE, 7);
    let res = solana_verifier::verify_transfer(&bad_proof, TRANSFER_PUBLICS_LE);
    assert!(res.is_err(), "transfer verification unexpectedly succeeded with corrupted proof");
    println!("verify_transfer (corrupted proof): {:?}", res.err());
}

// ======================= WITHDRAW (positive) =======================

#[test]
fn vk_endianness_sanity_and_verify_withdraw() {
    assert!(WITHDRAW_VK_BE.len() >= 64, "vk.bin too short for alpha");
    let alpha_x_be = &WITHDRAW_VK_BE[0..32];
    println!("alpha.x (BE) = {}", be32_to_hex_prefixed(alpha_x_be));

    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(alpha_x_be);
    tmp.reverse();
    println!("alpha.x (LE) = {}", be32_to_hex_prefixed(&tmp));

    let vk_hash = hash(WITHDRAW_VK_BE);
    let vk_hex_arr: Vec<String> = vk_hash.0.iter().map(|b| format!("{:02x}", b)).collect();
    println!("vk.bin keccak256 = [{}]", vk_hex_arr.join(", "));

    println!("proof.len={} publics.len={}", WITHDRAW_PROOF_LE.len(), WITHDRAW_PUBLICS_LE.len());
    assert_eq!(WITHDRAW_PROOF_LE.len(), solana_verifier::BYTES_PROOF, "bad proof length");
    assert_eq!(WITHDRAW_PUBLICS_LE.len(), solana_verifier::BYTES_F * solana_verifier::WITHDRAW_N_PUBLIC, "bad publics length");

    let a0 = &WITHDRAW_PROOF_LE[0..32];
    let a1 = &WITHDRAW_PROOF_LE[32..64];
    println!("[proof[0..64]][0..32] {}", hex(a0));
    println!("[proof[0..64]][32..64] {}", hex(a1));

    let p0 = &WITHDRAW_PUBLICS_LE[0..32];
    let p1 = &WITHDRAW_PUBLICS_LE[32..64];
    println!("[publics[0..64]][0..32] {}", hex(p0));
    println!("[publics[0..64]][32..64] {}", hex(p1));

    solana_verifier::verify_withdraw(WITHDRAW_PROOF_LE, WITHDRAW_PUBLICS_LE)
        .expect("off-chain verify_withdraw failed");
    println!("verify_withdraw: OK");
}

// ======================= WITHDRAW (negative) =======================

#[test]
fn verify_withdraw_fails_if_b_is_preswapped() {
    let bad = preswap_b_on_wire(WITHDRAW_PROOF_LE);
    assert_eq!(bad.len(), WITHDRAW_PROOF_LE.len());
    let res = solana_verifier::verify_withdraw(&bad, WITHDRAW_PUBLICS_LE);
    assert!(res.is_err(), "withdraw verification unexpectedly succeeded with pre-swapped B");
    println!("verify_withdraw (with pre-swapped B): {:?}", res.err());
}

#[test]
fn verify_withdraw_fails_if_publics_recipient_corrupted() {
    // Corrupt the recipientWalletPubKey limb (index = 2)
    let bad_publics = corrupt_public_at_index(WITHDRAW_PUBLICS_LE, 2);
    let res = solana_verifier::verify_withdraw(WITHDRAW_PROOF_LE, &bad_publics);
    assert!(res.is_err(), "withdraw verification unexpectedly succeeded with corrupted recipient pubkey");
    println!("verify_withdraw (corrupted recipient): {:?}", res.err());
}

#[test]
fn verify_withdraw_fails_if_publics_tokenid_corrupted() {
    // Corrupt the tokenId limb (index = 4)
    let bad_publics = corrupt_public_at_index(WITHDRAW_PUBLICS_LE, 4);
    let res = solana_verifier::verify_withdraw(WITHDRAW_PROOF_LE, &bad_publics);
    assert!(res.is_err(), "withdraw verification unexpectedly succeeded with corrupted tokenId");
    println!("verify_withdraw (corrupted tokenId): {:?}", res.err());
}

#[test]
fn verify_withdraw_fails_if_proof_byte_flipped() {
    let bad_proof = corrupt_at(WITHDRAW_PROOF_LE, 11);
    let res = solana_verifier::verify_withdraw(&bad_proof, WITHDRAW_PUBLICS_LE);
    assert!(res.is_err(), "withdraw verification unexpectedly succeeded with corrupted proof");
    println!("verify_withdraw (corrupted proof): {:?}", res.err());
}

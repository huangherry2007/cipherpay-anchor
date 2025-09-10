// tests/zk_verifier_tests.rs
use std::fs;
use std::path::{Path, PathBuf};

use cipherpay_anchor::zk_verifier::solana_verifier::{
    self, BYTES_F, BYTES_G1, BYTES_G2, BYTES_PROOF, DEPOSIT_N_PUBLIC,
};

fn find_build_dir() -> PathBuf {
    // Try a few common layouts:
    //  - repo_root/build/deposit
    //  - program_crate/build/deposit
    //  - ../build/deposit (when tests run in program crate)
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        base.join("proofs"),
    ];
    for p in candidates {
        if p.is_dir() && p.join("deposit_proof.bin").exists() {
            return p;
        }
    }
    panic!(
        "Could not find build/deposit folder with proof/public files.\n\
         Make sure you ran:\n  \
           node scripts/generate-bin-proofs.js deposit -i circuits/deposit/example_input.json -o build/deposit\n\
         and that tests can see that folder from CARGO_MANIFEST_DIR={}",
        env!("CARGO_MANIFEST_DIR")
    );
}

fn read(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|e| {
        panic!("Failed to read {}: {e}", path.as_ref().display());
    })
}

#[test]
fn constants_and_layout() {
    assert_eq!(BYTES_F, 32, "field limb should be 32 bytes");
    assert_eq!(BYTES_G1, 64, "G1 should be 64 bytes");
    assert_eq!(BYTES_G2, 128, "G2 should be 128 bytes");
    assert_eq!(BYTES_PROOF, 256, "Groth16 proof should be 256 bytes (A|B|C)");
    assert_eq!(DEPOSIT_N_PUBLIC, 6, "deposit circuit should expose 6 public signals");
}

#[test]
fn verify_deposit_real_proof() {
    let build = find_build_dir();
    let proof = read(build.join("deposit_proof.bin"));
    let publics = read(build.join("deposit_public_signals.bin"));

    // Basic shape checks
    assert_eq!(proof.len(), BYTES_PROOF, "proof.bin must be 256 bytes");
    assert_eq!(
        publics.len(),
        DEPOSIT_N_PUBLIC * BYTES_F,
        "public_signals.bin must be {} bytes",
        DEPOSIT_N_PUBLIC * BYTES_F
    );

    // Should pass as-is (B0 or B1 will be handled internally)
    solana_verifier::verify_deposit(&proof, &publics)
        .expect("deposit proof should verify (as written by generate-bin-proofs.js)");
}

#[test]
fn parse_public_inputs_exact_len() {
    let build = find_build_dir();
    let publics = read(build.join("deposit_public_signals.bin"));
    let sigs = solana_verifier::parse_public_signals_exact(&publics)
        .expect("parse_public_signals_exact should succeed");
    assert_eq!(
        sigs.len(),
        DEPOSIT_N_PUBLIC,
        "expected {} public signals, got {}",
        DEPOSIT_N_PUBLIC,
        sigs.len()
    );
}

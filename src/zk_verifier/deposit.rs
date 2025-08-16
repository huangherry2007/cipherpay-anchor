#[cfg(feature = "real-crypto")]
// zk_verifier/deposit.rs
// Auto-generated verifier logic for deposit.circom using arkworks (BLS12-381 Groth16)

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey, PreparedVerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;
use ark_std::io::Cursor;
use std::str::FromStr;
use crate::CipherPayError;
use crate::zk_verifier::constants_deposit::*;

// Use the type defined in the types module for Anchor compatibility
use crate::zk_verifier::types::DepositGroth16Proof;

pub fn parse_deposit_proof(bytes: &[u8]) -> Result<DepositGroth16Proof, CipherPayError> {
    // For Anchor compatibility, we return Vec<u8> but we still need to validate the proof format
    // This ensures the bytes are valid proof data even if we don't parse to complex types here
    if bytes.len() < 192 { // Minimum size for a Groth16 proof
        return Err(CipherPayError::InvalidZkProof);
    }
    Ok(bytes.to_vec())
}

// Internal function for actual ZK verification
pub fn parse_deposit_proof_internal(bytes: &[u8]) -> Result<Proof<Bls12_381>, CipherPayError> {
    Proof::deserialize_uncompressed(&mut Cursor::new(bytes)).map_err(|_| CipherPayError::InvalidZkProof)
}

// Internal function to parse public inputs to Vec<Fr> for ZK verification
pub fn parse_deposit_public_inputs_internal(bytes: &[u8]) -> Result<Vec<Fr>, CipherPayError> {
    const NUM_SIGNALS: usize = 6;
    if bytes.len() != NUM_SIGNALS * 32 {
        return Err(CipherPayError::InvalidZkProof);
    }
    let mut signals = Vec::with_capacity(NUM_SIGNALS);
    for i in 0..NUM_SIGNALS {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        signals.push(Fr::from_le_bytes_mod_order(&buf));
    }
    Ok(signals)
}

pub fn verify_deposit_groth16(
    proof: &DepositGroth16Proof, // Now takes Vec<u8> for Anchor compatibility
    public_inputs: &[u8], // Now takes Vec<u8> for Anchor compatibility
) -> Result<(), CipherPayError> {
    // Parse the proof to the complex type internally for ZK verification
    let parsed_proof = parse_deposit_proof_internal(proof)?;
    
    // Parse public inputs to Vec<Fr> internally for ZK verification
    let parsed_public_inputs = parse_deposit_public_inputs_internal(public_inputs)?;
    
    let vk = get_verifying_key()?;
    let pvk = PreparedVerifyingKey::from(vk);
    
    // Use the Groth16 struct for verification with the SNARK trait
    // Note: verify_proof returns bool, so we need to check if it's true
    if Groth16::<Bls12_381>::verify_proof(&pvk, &parsed_proof, &parsed_public_inputs).map_err(|_| CipherPayError::InvalidZkProof)? {
        Ok(())
    } else {
        Err(CipherPayError::InvalidZkProof)
    }
}

fn parse_g1(coords: [&str; 2]) -> ark_bls12_381::G1Affine {
    use ark_bls12_381::g1::G1Affine;
    use ark_bls12_381::Fq;
    let x = Fq::from_str(coords[0]).unwrap();
    let y = Fq::from_str(coords[1]).unwrap();
    G1Affine::new_unchecked(x, y)
}

fn parse_g2(coords: [[&str; 2]; 2]) -> ark_bls12_381::G2Affine {
    use ark_bls12_381::g2::G2Affine;
    use ark_bls12_381::Fq2;
    use ark_bls12_381::Fq;
    let x = Fq2::new(Fq::from_str(coords[0][0]).unwrap(), Fq::from_str(coords[0][1]).unwrap());
    let y = Fq2::new(Fq::from_str(coords[1][0]).unwrap(), Fq::from_str(coords[1][1]).unwrap());
    G2Affine::new_unchecked(x, y)
}

fn get_verifying_key() -> Result<VerifyingKey<Bls12_381>, CipherPayError> {
    let alpha_g1 = parse_g1(VK_ALPHA_G1[0]);
    let beta_g2 = parse_g2(VK_BETA_G2[0]);
    let gamma_g2 = parse_g2(VK_GAMMA_G2[0]);
    let delta_g2 = parse_g2(VK_DELTA_G2[0]);
    let gamma_abc_g1 = IC.iter().map(|coords| parse_g1(*coords)).collect();

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}
// zk_verifier/transfer.rs
// Auto-generated verifier logic for transfer.circom using arkworks (BLS12-381 Groth16)

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey, PreparedVerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;
use std::io::Cursor;
use std::str::FromStr;
use crate::CipherPayError;
use crate::zk_verifier::constants_transfer::*;

pub type TransferGroth16Proof = Proof<Bls12_381>;

pub fn parse_transfer_proof(bytes: &[u8]) -> Result<TransferGroth16Proof, CipherPayError> {
    Proof::deserialize_uncompressed(&mut Cursor::new(bytes)).map_err(|_| CipherPayError::InvalidZkProof)
}

pub fn parse_transfer_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, CipherPayError> {
    const NUM_SIGNALS: usize = 4;
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

pub fn verify_transfer_groth16(
    proof: &TransferGroth16Proof,
    public_inputs: &[Fr],
) -> Result<(), CipherPayError> {
    let vk = get_verifying_key()?;
    let pvk = PreparedVerifyingKey::from(vk);
    
    // Use the Groth16 struct for verification with the SNARK trait
    // Note: verify_proof returns bool, so we need to check if it's true
    if Groth16::<Bls12_381>::verify_proof(&pvk, proof, public_inputs).map_err(|_| CipherPayError::InvalidZkProof)? {
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
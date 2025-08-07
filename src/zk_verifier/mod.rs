#[cfg(feature = "real-crypto")]
pub mod deposit;
#[cfg(feature = "real-crypto")]
pub mod transfer;
#[cfg(feature = "real-crypto")]
pub mod withdraw;

#[cfg(feature = "real-crypto")]
pub mod constants_deposit;
#[cfg(feature = "real-crypto")]
pub mod constants_transfer;
#[cfg(feature = "real-crypto")]
pub mod constants_withdraw;

#[cfg(feature = "real-crypto")]
use ark_bls12_381::Fr;
#[cfg(feature = "real-crypto")]
use ark_ff::PrimeField;
#[cfg(feature = "real-crypto")]
use ark_groth16::Proof;
use crate::CipherPayError;

#[cfg(feature = "real-crypto")]
pub type DepositGroth16Proof = Proof<ark_bls12_381::Bls12_381>;
#[cfg(feature = "real-crypto")]
pub type TransferGroth16Proof = Proof<ark_bls12_381::Bls12_381>;
#[cfg(feature = "real-crypto")]
pub type WithdrawGroth16Proof = Proof<ark_bls12_381::Bls12_381>;

#[cfg(feature = "real-crypto")]
pub fn parse_deposit_proof(bytes: &[u8]) -> Result<DepositGroth16Proof, CipherPayError> {
    use ark_serialize::CanonicalDeserialize;
    use std::io::Cursor;
    Proof::deserialize_uncompressed(&mut Cursor::new(bytes)).map_err(|_| CipherPayError::InvalidZkProof)
}

#[cfg(feature = "real-crypto")]
pub fn parse_transfer_proof(bytes: &[u8]) -> Result<TransferGroth16Proof, CipherPayError> {
    use ark_serialize::CanonicalDeserialize;
    use std::io::Cursor;
    Proof::deserialize_uncompressed(&mut Cursor::new(bytes)).map_err(|_| CipherPayError::InvalidZkProof)
}

#[cfg(feature = "real-crypto")]
pub fn parse_withdraw_proof(bytes: &[u8]) -> Result<WithdrawGroth16Proof, CipherPayError> {
    use ark_serialize::CanonicalDeserialize;
    use std::io::Cursor;
    Proof::deserialize_uncompressed(&mut Cursor::new(bytes)).map_err(|_| CipherPayError::InvalidZkProof)
}

#[cfg(feature = "real-crypto")]
pub fn parse_deposit_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, CipherPayError> {
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

#[cfg(feature = "real-crypto")]
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

#[cfg(feature = "real-crypto")]
pub fn parse_withdraw_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, CipherPayError> {
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

#[cfg(feature = "real-crypto")]
pub fn verify_deposit_groth16(
    proof: &DepositGroth16Proof,
    public_inputs: &[Fr],
) -> Result<(), CipherPayError> {
    use crate::zk_verifier::deposit::verify_deposit_groth16 as verify;
    verify(proof, public_inputs)
}

#[cfg(feature = "real-crypto")]
pub fn verify_transfer_groth16(
    proof: &TransferGroth16Proof,
    public_inputs: &[Fr],
) -> Result<(), CipherPayError> {
    use crate::zk_verifier::transfer::verify_transfer_groth16 as verify;
    verify(proof, public_inputs)
}

#[cfg(feature = "real-crypto")]
pub fn verify_withdraw_groth16(
    proof: &WithdrawGroth16Proof,
    public_inputs: &[Fr],
) -> Result<(), CipherPayError> {
    use crate::zk_verifier::withdraw::verify_withdraw_groth16 as verify;
    verify(proof, public_inputs)
}

// Stub implementations when real-crypto feature is not enabled
#[cfg(not(feature = "real-crypto"))]
pub fn parse_deposit_proof(_bytes: &[u8]) -> Result<(), CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn parse_transfer_proof(_bytes: &[u8]) -> Result<(), CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn parse_withdraw_proof(_bytes: &[u8]) -> Result<(), CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn parse_deposit_public_inputs(_bytes: &[u8]) -> Result<Vec<()>, CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn parse_transfer_public_inputs(_bytes: &[u8]) -> Result<Vec<()>, CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn parse_withdraw_public_inputs(_bytes: &[u8]) -> Result<Vec<()>, CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn verify_deposit_groth16(_proof: &(), _public_inputs: &[()]) -> Result<(), CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn verify_transfer_groth16(_proof: &(), _public_inputs: &[()]) -> Result<(), CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

#[cfg(not(feature = "real-crypto"))]
pub fn verify_withdraw_groth16(_proof: &(), _public_inputs: &[()]) -> Result<(), CipherPayError> {
    Err(CipherPayError::InvalidZkProof)
}

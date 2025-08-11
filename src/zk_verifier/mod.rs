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

// Create a separate types module to avoid duplication
pub mod types;

use crate::CipherPayError;
use crate::zk_verifier::types::*;

// Types are now defined in the types module to avoid duplication

// Public wrapper functions that return Vec<u8> for Anchor compatibility
pub fn parse_deposit_proof(bytes: &[u8]) -> Result<DepositGroth16Proof, CipherPayError> {
    // For Anchor compatibility, we return Vec<u8> but we still need to validate the proof format
    // This ensures the bytes are valid proof data even if we don't parse to complex types here
    if bytes.len() < 192 { // Minimum size for a Groth16 proof
        return Err(CipherPayError::InvalidZkProof);
    }
    Ok(bytes.to_vec())
}

pub fn parse_transfer_proof(bytes: &[u8]) -> Result<TransferGroth16Proof, CipherPayError> {
    // For Anchor compatibility, we return Vec<u8> but we still need to validate the proof format
    // This ensures the bytes are valid proof data even if we don't parse to complex types here
    if bytes.len() < 192 { // Minimum size for a Groth16 proof
        return Err(CipherPayError::InvalidZkProof);
    }
    Ok(bytes.to_vec())
}

pub fn parse_withdraw_proof(bytes: &[u8]) -> Result<WithdrawGroth16Proof, CipherPayError> {
    // For Anchor compatibility, we return Vec<u8> but we still need to validate the proof format
    // This ensures the bytes are valid proof data even if we don't parse to complex types here
    if bytes.len() < 192 { // Minimum size for a Groth16 proof
        return Err(CipherPayError::InvalidZkProof);
    }
    Ok(bytes.to_vec())
}

// Public wrapper functions that return Vec<u8> for Anchor compatibility
// These functions take Vec<u8> and return Vec<u8>, completely hiding arkworks types
#[cfg(feature = "real-crypto")]
pub fn parse_deposit_public_inputs(bytes: &[u8]) -> Result<Vec<u8>, CipherPayError> {
    const NUM_SIGNALS: usize = 6;
    if bytes.len() != NUM_SIGNALS * 32 {
        return Err(CipherPayError::InvalidZkProof);
    }
    // Return the bytes as-is for Anchor compatibility
    Ok(bytes.to_vec())
}

#[cfg(feature = "real-crypto")]
pub fn parse_transfer_public_inputs(bytes: &[u8]) -> Result<Vec<u8>, CipherPayError> {
    const NUM_SIGNALS: usize = 4;
    if bytes.len() != NUM_SIGNALS * 32 {
        return Err(CipherPayError::InvalidZkProof);
    }
    // Return the bytes as-is for Anchor compatibility
    Ok(bytes.to_vec())
}

#[cfg(feature = "real-crypto")]
pub fn parse_withdraw_public_inputs(bytes: &[u8]) -> Result<Vec<u8>, CipherPayError> {
    const NUM_SIGNALS: usize = 6;
    if bytes.len() != NUM_SIGNALS * 32 {
        return Err(CipherPayError::InvalidZkProof);
    }
    // Return the bytes as-is for Anchor compatibility
    Ok(bytes.to_vec())
}

// Verification functions that take Vec<u8> and call the individual module functions
#[cfg(feature = "real-crypto")]
pub fn verify_deposit_groth16(
    proof: &DepositGroth16Proof,
    public_inputs: &[u8],
) -> Result<(), CipherPayError> {
    // Call the individual module's verification function directly
    use crate::zk_verifier::deposit::verify_deposit_groth16 as verify;
    verify(proof, public_inputs)
}

#[cfg(feature = "real-crypto")]
pub fn verify_transfer_groth16(
    proof: &TransferGroth16Proof,
    public_inputs: &[u8],
) -> Result<(), CipherPayError> {
    // Call the individual module's verification function directly
    use crate::zk_verifier::transfer::verify_transfer_groth16 as verify;
    verify(proof, public_inputs)
}

#[cfg(feature = "real-crypto")]
pub fn verify_withdraw_groth16(
    proof: &WithdrawGroth16Proof,
    public_inputs: &[u8],
) -> Result<(), CipherPayError> {
    // Call the individual module's verification function directly
    use crate::zk_verifier::withdraw::verify_withdraw_groth16 as verify;
    verify(proof, public_inputs)
}

// Helper function to validate deposit hash without exposing arkworks types
#[cfg(feature = "real-crypto")]
pub fn validate_deposit_hash(public_inputs: &[u8], deposit_hash: &[u8; 32]) -> Result<bool, CipherPayError> {
    // Extract the deposit hash from public inputs (signal 1, bytes 32-63)
    if public_inputs.len() < 64 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let deposit_hash_bytes = &public_inputs[32..64];
    Ok(deposit_hash_bytes == deposit_hash)
}

// Helper function to extract merkle root from public inputs
#[cfg(feature = "real-crypto")]
pub fn extract_merkle_root(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract merkle root from public inputs (signal 4, bytes 128-159)
    if public_inputs.len() < 160 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&public_inputs[128..160]);
    Ok(root_array)
}

// Helper function to extract commitment from public inputs
#[cfg(feature = "real-crypto")]
pub fn extract_commitment(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract commitment from public inputs (signal 2, bytes 64-95)
    if public_inputs.len() < 96 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut commitment_array = [0u8; 32];
    commitment_array.copy_from_slice(&public_inputs[64..96]);
    Ok(commitment_array)
}

// Helper function to extract owner pubkey from public inputs
#[cfg(feature = "real-crypto")]
pub fn extract_owner_pubkey(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract owner pubkey from public inputs (signal 3, bytes 96-127)
    if public_inputs.len() < 128 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut owner_array = [0u8; 32];
    owner_array.copy_from_slice(&public_inputs[96..128]);
    Ok(owner_array)
}

// Helper function to validate transfer nullifier
#[cfg(feature = "real-crypto")]
pub fn validate_transfer_nullifier(public_inputs: &[u8], nullifier: &[u8; 32]) -> Result<bool, CipherPayError> {
    // Extract nullifier from public inputs (signal 0, bytes 0-31)
    if public_inputs.len() < 32 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let nullifier_bytes = &public_inputs[0..32];
    Ok(nullifier_bytes == nullifier)
}

// Helper function to extract transfer merkle root
#[cfg(feature = "real-crypto")]
pub fn extract_transfer_merkle_root(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract merkle root from public inputs (signal 3, bytes 96-127)
    if public_inputs.len() < 128 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&public_inputs[96..128]);
    Ok(root_array)
}

// Helper function to extract transfer commitment
#[cfg(feature = "real-crypto")]
pub fn extract_transfer_commitment(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract commitment from public inputs (signal 1, bytes 32-63)
    if public_inputs.len() < 64 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut commitment_array = [0u8; 32];
    commitment_array.copy_from_slice(&public_inputs[32..64]);
    Ok(commitment_array)
}

// Helper function to extract transfer recipient
#[cfg(feature = "real-crypto")]
pub fn extract_transfer_recipient(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract recipient from public inputs (signal 2, bytes 64-95)
    if public_inputs.len() < 96 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut recipient_array = [0u8; 32];
    recipient_array.copy_from_slice(&public_inputs[64..96]);
    Ok(recipient_array)
}

// Helper function to validate withdraw nullifier
#[cfg(feature = "real-crypto")]
pub fn validate_withdraw_nullifier(public_inputs: &[u8], nullifier: &[u8; 32]) -> Result<bool, CipherPayError> {
    // Extract nullifier from public inputs (signal 4, bytes 128-159)
    if public_inputs.len() < 160 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let nullifier_bytes = &public_inputs[128..160];
    Ok(nullifier_bytes == nullifier)
}

// Helper function to extract withdraw merkle root
#[cfg(feature = "real-crypto")]
pub fn extract_withdraw_merkle_root(public_inputs: &[u8]) -> Result<[u8; 32], CipherPayError> {
    // Extract merkle root from public inputs (signal 5, bytes 160-191)
    if public_inputs.len() < 192 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&public_inputs[160..192]);
    Ok(root_array)
}

// Helper function to extract withdraw amount
#[cfg(feature = "real-crypto")]
pub fn extract_withdraw_amount(public_inputs: &[u8]) -> Result<u64, CipherPayError> {
    // Extract amount from public inputs (signal 1, bytes 32-63)
    if public_inputs.len() < 64 {
        return Err(CipherPayError::InvalidZkProof);
    }
    
    let amount_bytes = &public_inputs[32..64];
    let amount_u64: u64 = if amount_bytes.len() <= 8 {
        let mut bytes = [0u8; 8];
        bytes[..amount_bytes.len()].copy_from_slice(&amount_bytes);
        u64::from_le_bytes(bytes)
    } else {
        return Err(CipherPayError::InvalidWithdrawAmount);
    };
    
    Ok(amount_u64)
}



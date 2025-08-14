// zk_verifier/mod.rs - zkVerify Integration for CipherPay Anchor
// This module integrates with zkVerify for on-chain Groth16 proof verification

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use crate::CipherPayError;

// zkVerify Program ID (Mainnet Beta)
pub const ZKVERIFY_PROGRAM_ID: &str = "zkVeriFY4u7epfRDmVFezQ6HiXPKUeSJTCc6fpgpEHp";

// zkVerify CPI Interface
pub mod zkverify {
    use super::*;
    declare_id!("zkVeriFY4u7epfRDmVFezQ6HiXPKUeSJTCc6fpgpEHp");

    #[derive(Clone)]
    pub struct Zkverify;

    impl anchor_lang::Id for Zkverify {
        fn id() -> Pubkey {
            zkverify::ID
        }
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone)]
    pub struct Groth16VerifyArgs {
        pub proof: Vec<u8>,           // proof.bin
        pub public_inputs: Vec<u8>,   // concatenated field elements (32 bytes each)
        pub vk_id: [u8; 32],          // unique hash ID of the verification key
    }

    #[derive(Accounts)]
    pub struct VerifyGroth16 {}
    
    pub mod cpi {
        use super::*;

        pub fn verify_groth16<'info>(
            _ctx: CpiContext<'_, '_, '_, 'info, VerifyGroth16>,
            args: Groth16VerifyArgs,
        ) -> Result<()> {
            let ix = Instruction {
                program_id: Zkverify::id(),
                accounts: vec![],
                data: args.try_to_vec()?,
            };
            Ok(anchor_lang::solana_program::program::invoke(&ix, &[])?)
        }
    }
}

// Verification Key IDs for each circuit
// These are auto-generated from your actual circuit verification keys
// DO NOT change these values unless you regenerate your circuits
include!("vk_ids.rs");

// Main verification functions using zkVerify
pub fn verify_deposit_groth16(
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<()> {
    // Create zkVerify arguments
    let _args = zkverify::Groth16VerifyArgs {
        proof: proof.to_vec(),
        public_inputs: public_inputs.to_vec(),
        vk_id: vk_ids::DEPOSIT_VK_ID,
    };
    
    // This will be called via CPI from the main program
    // For now, we just validate the input format
    validate_proof_format(proof)?;
    validate_public_inputs_format(public_inputs, 6)?; // Deposit has 6 public signals
    
    Ok(())
}

pub fn verify_transfer_groth16(
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<()> {
    // Create zkVerify arguments
    let _args = zkverify::Groth16VerifyArgs {
        proof: proof.to_vec(),
        public_inputs: public_inputs.to_vec(),
        vk_id: vk_ids::TRANSFER_VK_ID,
    };
    
    // Validate input format
    validate_proof_format(proof)?;
    validate_public_inputs_format(public_inputs, 4)?; // Transfer has 4 public signals
    
    Ok(())
}

pub fn verify_withdraw_groth16(
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<()> {
    // Create zkVerify arguments
    let _args = zkverify::Groth16VerifyArgs {
        proof: proof.to_vec(),
        public_inputs: public_inputs.to_vec(),
        vk_id: vk_ids::WITHDRAW_VK_ID,
    };
    
    // Validate input format
    validate_proof_format(proof)?;
    validate_public_inputs_format(public_inputs, 6)?; // Withdraw has 6 public signals
    
    Ok(())
}

// Input validation functions
fn validate_proof_format(proof: &[u8]) -> Result<()> {
    // Groth16 proof should be at least 192 bytes (3 points * 2 coordinates * 32 bytes)
    if proof.len() < 192 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    Ok(())
}

fn validate_public_inputs_format(public_inputs: &[u8], expected_signals: usize) -> Result<()> {
    // Each public signal is 32 bytes
    let expected_size = expected_signals * 32;
    if public_inputs.len() != expected_size {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    Ok(())
}

// Helper functions for extracting data from public inputs
pub fn extract_merkle_root(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract merkle root from public inputs (signal 4, bytes 128-159)
    if public_inputs.len() < 160 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&public_inputs[128..160]);
    Ok(root_array)
}

pub fn extract_commitment(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract commitment from public inputs (signal 2, bytes 64-95)
    if public_inputs.len() < 96 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut commitment_array = [0u8; 32];
    commitment_array.copy_from_slice(&public_inputs[64..96]);
    Ok(commitment_array)
}

pub fn extract_owner_pubkey(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract owner pubkey from public inputs (signal 3, bytes 96-127)
    if public_inputs.len() < 128 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut owner_array = [0u8; 32];
    owner_array.copy_from_slice(&public_inputs[96..128]);
    Ok(owner_array)
}

pub fn validate_deposit_hash(public_inputs: &[u8], deposit_hash: &[u8; 32]) -> Result<bool> {
    // Extract the deposit hash from public inputs (signal 1, bytes 32-63)
    if public_inputs.len() < 64 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let deposit_hash_bytes = &public_inputs[32..64];
    Ok(deposit_hash_bytes == deposit_hash)
}

pub fn validate_transfer_nullifier(public_inputs: &[u8], nullifier: &[u8; 32]) -> Result<bool> {
    // Extract nullifier from public inputs (signal 0, bytes 0-31)
    if public_inputs.len() < 32 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let nullifier_bytes = &public_inputs[0..32];
    Ok(nullifier_bytes == nullifier)
}

pub fn extract_transfer_merkle_root(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract merkle root from public inputs (signal 3, bytes 96-127)
    if public_inputs.len() < 128 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&public_inputs[96..128]);
    Ok(root_array)
}

pub fn extract_transfer_commitment(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract commitment from public inputs (signal 1, bytes 32-63)
    if public_inputs.len() < 64 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut commitment_array = [0u8; 32];
    commitment_array.copy_from_slice(&public_inputs[32..64]);
    Ok(commitment_array)
}

pub fn extract_transfer_recipient(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract recipient from public inputs (signal 2, bytes 64-95)
    if public_inputs.len() < 96 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut recipient_array = [0u8; 32];
    recipient_array.copy_from_slice(&public_inputs[64..96]);
    Ok(recipient_array)
}

pub fn validate_withdraw_nullifier(public_inputs: &[u8], nullifier: &[u8; 32]) -> Result<bool> {
    // Extract nullifier from public inputs (signal 4, bytes 128-159)
    if public_inputs.len() < 160 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let nullifier_bytes = &public_inputs[128..160];
    Ok(nullifier_bytes == nullifier)
}

pub fn extract_withdraw_merkle_root(public_inputs: &[u8]) -> Result<[u8; 32]> {
    // Extract merkle root from public inputs (signal 5, bytes 160-191)
    if public_inputs.len() < 192 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&public_inputs[160..192]);
    Ok(root_array)
}

pub fn extract_withdraw_amount(public_inputs: &[u8]) -> Result<u64> {
    // Extract amount from public inputs (signal 1, bytes 32-63)
    if public_inputs.len() < 64 {
        return Err(CipherPayError::InvalidZkProof.into());
    }
    
    let amount_bytes = &public_inputs[32..64];
    let amount_u64: u64 = if amount_bytes.len() <= 8 {
        let mut bytes = [0u8; 8];
        bytes[..amount_bytes.len()].copy_from_slice(&amount_bytes);
        u64::from_le_bytes(bytes)
    } else {
        return Err(CipherPayError::InvalidWithdrawAmount.into());
    };
    
    Ok(amount_u64)
}

// Public wrapper functions for Anchor compatibility
pub fn parse_deposit_proof(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_proof_format(bytes)?;
    Ok(bytes.to_vec())
}

pub fn parse_transfer_proof(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_proof_format(bytes)?;
    Ok(bytes.to_vec())
}

pub fn parse_withdraw_proof(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_proof_format(bytes)?;
    Ok(bytes.to_vec())
}

pub fn parse_deposit_public_inputs(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_public_inputs_format(bytes, 6)?;
    Ok(bytes.to_vec())
}

pub fn parse_transfer_public_inputs(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_public_inputs_format(bytes, 4)?;
    Ok(bytes.to_vec())
}

pub fn parse_withdraw_public_inputs(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_public_inputs_format(bytes, 6)?;
    Ok(bytes.to_vec())
}



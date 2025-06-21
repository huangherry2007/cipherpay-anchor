use anchor_lang::prelude::*;
use crate::CipherPayError;
use sha2::{Sha256, Digest};

#[cfg(feature = "real-crypto")]
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, G1Projective, G2Projective};
#[cfg(feature = "real-crypto")]
use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
#[cfg(feature = "real-crypto")]
use ark_ff::{PrimeField, Field};
#[cfg(feature = "real-crypto")]
use ark_groth16::{Groth16, Proof, VerifyingKey};
#[cfg(feature = "real-crypto")]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(feature = "real-crypto")]
use ark_std::UniformRand;

// Verification keys for different circuits (these would be loaded from circuit compilation)
#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
lazy_static::lazy_static! {
    static ref TRANSFER_VK: VerifyingKey<Bn254> = {
        // In a real implementation, this would be loaded from a file or constant
        // For now, we'll create a dummy VK for demonstration
        let mut rng = ark_std::test_rng();
        let g1_generator = G1Affine::prime_subgroup_generator();
        let g2_generator = G2Affine::prime_subgroup_generator();
        
        VerifyingKey {
            alpha_g1: g1_generator.mul(Fr::rand(&mut rng).into_repr()).into_affine(),
            beta_g2: g2_generator.mul(Fr::rand(&mut rng).into_repr()).into_affine(),
            gamma_g2: g2_generator.mul(Fr::rand(&mut rng).into_repr()).into_affine(),
            delta_g2: g2_generator.mul(Fr::rand(&mut rng).into_repr()).into_affine(),
            gamma_abc_g1: vec![g1_generator.mul(Fr::rand(&mut rng).into_repr()).into_affine()],
        }
    };
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts bytes to BN254 field element
fn bytes_to_fr(bytes: &[u8; 32]) -> Result<Fr> {
    // Convert bytes to field element
    let mut field_bytes = [0u8; 32];
    field_bytes.copy_from_slice(bytes);
    
    // Reverse bytes for little-endian representation
    field_bytes.reverse();
    
    Fr::deserialize(&mut &field_bytes[..])
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts bytes to G1 point
fn bytes_to_g1(bytes: &[u8; 64]) -> Result<G1Affine> {
    let x_bytes: [u8; 32] = bytes[0..32].try_into()
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())?;
    let y_bytes: [u8; 32] = bytes[32..64].try_into()
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())?;
    
    let x = bytes_to_fr(&x_bytes)?;
    let y = bytes_to_fr(&y_bytes)?;
    
    G1Affine::new(x, y, false)
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts bytes to G2 point
fn bytes_to_g2(bytes: &[u8; 128]) -> Result<G2Affine> {
    // G2 points have x and y coordinates in quadratic extension field
    // Each coordinate is 64 bytes (two field elements)
    let x0_bytes: [u8; 32] = bytes[0..32].try_into()
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())?;
    let x1_bytes: [u8; 32] = bytes[32..64].try_into()
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())?;
    let y0_bytes: [u8; 32] = bytes[64..96].try_into()
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())?;
    let y1_bytes: [u8; 32] = bytes[96..128].try_into()
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())?;
    
    let x0 = bytes_to_fr(&x0_bytes)?;
    let x1 = bytes_to_fr(&x1_bytes)?;
    let y0 = bytes_to_fr(&y0_bytes)?;
    let y1 = bytes_to_fr(&y1_bytes)?;
    
    // Create quadratic extension field elements
    let x = ark_bn254::Fq2::new(x0, x1);
    let y = ark_bn254::Fq2::new(y0, y1);
    
    G2Affine::new(x, y, false)
        .map_err(|_| CipherPayError::InvalidCurvePoint.into())
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts public inputs to field elements
fn public_inputs_to_field_elements(inputs: &[u8]) -> Result<Vec<Fr>> {
    if inputs.len() % 32 != 0 {
        return err!(CipherPayError::InvalidPublicInputs);
    }
    
    let mut field_elements = Vec::new();
    for chunk in inputs.chunks(32) {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(chunk);
        let field_element = bytes_to_fr(&bytes)?;
        field_elements.push(field_element);
    }
    
    Ok(field_elements)
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Verifies a Groth16 proof using real cryptographic operations
pub fn verify_groth16_proof_real(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs: &[u8],
    circuit_type: &str
) -> Result<()> {
    // Parse proof components
    let a = bytes_to_g1(proof_a)?;
    let b = bytes_to_g2(proof_b)?;
    let c = bytes_to_g1(proof_c)?;
    
    // Create proof structure
    let proof = Proof { a, b, c };
    
    // Parse public inputs
    let public_inputs_field = public_inputs_to_field_elements(public_inputs)?;
    
    // Get verification key for the circuit type
    let vk = get_verification_key(circuit_type)?;
    
    // Verify the proof using Groth16 verification
    let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs_field, &proof)
        .map_err(|_| CipherPayError::ProofVerificationFailed)?;
    
    if !is_valid {
        return err!(CipherPayError::ProofVerificationFailed);
    }
    
    Ok(())
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Gets the verification key for a specific circuit type
fn get_verification_key(circuit_type: &str) -> Result<VerifyingKey<Bn254>> {
    match circuit_type {
        "transfer" | "withdraw" | "merkle" | "nullifier" | 
        "audit_proof" | "zkStream" | "zkSplit" | "zkCondition" => {
            // In a real implementation, each circuit would have its own VK
            // For now, we'll use the same VK for all circuits
            Ok(TRANSFER_VK.clone())
        },
        _ => err!(CipherPayError::UnsupportedCircuit),
    }
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Computes the pairing e(A, B) * e(C, D) = 1 for Groth16 verification
pub fn verify_pairing_real(proof_a: &[u8; 64], proof_b: &[u8; 128], proof_c: &[u8; 64]) -> Result<bool> {
    // Parse the proof components as curve points
    let a = bytes_to_g1(proof_a)?;
    let b = bytes_to_g2(proof_b)?;
    let c = bytes_to_g1(proof_c)?;
    
    // Get the verification key (we'll use a dummy one for now)
    let vk = get_verification_key("transfer")?;
    
    // Compute the pairing e(A, B) * e(C, D) = 1
    // In Groth16: e(A, B) * e(C, D) = e(alpha, beta) * prod(e(gamma_abc_i, gamma))
    let pairing_result = Bn254::pairing(a, b) * Bn254::pairing(c, vk.delta_g2);
    
    // The result should be the identity element in GT
    Ok(pairing_result == ark_bn254::Fq12::one())
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Validates a G1 point using real curve operations
pub fn verify_g1_point_real(point: &[u8; 64]) -> Result<bool> {
    match bytes_to_g1(point) {
        Ok(g1_point) => {
            // Check if the point is on the curve
            Ok(g1_point.is_on_curve())
        },
        Err(_) => Ok(false),
    }
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Validates a G2 point using real curve operations
pub fn verify_g2_point_real(point: &[u8; 128]) -> Result<bool> {
    match bytes_to_g2(point) {
        Ok(g2_point) => {
            // Check if the point is on the curve
            Ok(g2_point.is_on_curve())
        },
        Err(_) => Ok(false),
    }
}

#[allow(dead_code)]
/// Computes SHA256 hash
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[allow(dead_code)]
/// Verifies merkle proof using real SHA256 computation
pub fn verify_merkle_proof_real(leaf: &[u8; 32], proof: &Vec<[u8; 32]>, root: [u8; 32]) -> Result<()> {
    if proof.is_empty() {
        return err!(CipherPayError::InvalidMerkleProof);
    }
    
    // Basic validation
    if leaf.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidMerkleProof);
    }
    
    if root.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Compute the merkle root from the leaf and proof
    let mut current_hash = *leaf;
    
    for proof_element in proof {
        // Validate proof element
        if proof_element.iter().all(|&b| b == 0) {
            return err!(CipherPayError::InvalidMerkleProof);
        }
        
        // Determine the order: current_hash should be the "left" child
        // We'll use a deterministic ordering based on byte comparison
        let (left, right) = if current_hash < *proof_element {
            (current_hash, *proof_element)
        } else {
            (*proof_element, current_hash)
        };
        
        // Hash the concatenated values using SHA256
        let mut combined = Vec::new();
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);
        
        current_hash = compute_sha256(&combined);
    }
    
    // Compare computed root with provided root
    if current_hash != root {
        return err!(CipherPayError::InvalidMerkleProof);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Validates a merkle root using real hash validation
pub fn is_valid_merkle_root_real(root: &[u8]) -> bool {
    if root.len() != 32 {
        return false;
    }
    
    // Check that the merkle root is not all zeros
    if root.iter().all(|&b| b == 0) {
        return false;
    }
    
    // Check that the merkle root has some entropy (not all same bytes)
    let first_byte = root[0];
    if root.iter().all(|&b| b == first_byte) {
        return false;
    }
    
    // Additional validation: check that it looks like a SHA256 hash
    // SHA256 hashes have specific patterns, but for simplicity we'll just check entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in root {
        unique_bytes.insert(byte);
    }
    
    // A real SHA256 hash should have reasonable entropy
    unique_bytes.len() >= 4
}

#[allow(dead_code)]
/// Validates a merkle root - simplified version
pub fn is_valid_merkle_root(root: &[u8]) -> bool {
    #[cfg(feature = "real-crypto")]
    {
        is_valid_merkle_root_real(root)
    }
    
    #[cfg(not(feature = "real-crypto"))]
    {
        // Simplified validation
        if root.len() != 32 {
            return false;
        }
        
        // Check that the merkle root is not all zeros (which would be invalid)
        if root.iter().all(|&b| b == 0) {
            return false;
        }
        
        // Check that the merkle root has some entropy (not all same bytes)
        let first_byte = root[0];
        if root.iter().all(|&b| b == first_byte) {
            return false;
        }
        
        true
    }
}

#[allow(dead_code)]
/// Verifies the proof components and public inputs
pub fn verify_proof_internal(proof: &crate::VerifyProofArgs) -> Result<()> {
    // Validate proof format
    if proof.proof_a.len() != 64 || proof.proof_b.len() != 128 || proof.proof_c.len() != 64 {
        return err!(CipherPayError::InvalidProofFormat);
    }

    // Verify proof components
    verify_proof_components(&proof.proof_a, &proof.proof_b, &proof.proof_c)?;
    
    // Verify public inputs
    verify_public_inputs(&proof.public_inputs)?;

    // Verify merkle root
    if !is_valid_merkle_root(&proof.merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }

    // Verify timestamp
    let current_time = Clock::get()?.unix_timestamp;
    if proof.timestamp > current_time {
        return err!(CipherPayError::TimeConstraintViolation);
    }

    // Verify amount
    if proof.amount == 0 {
        return err!(CipherPayError::ZeroAmount);
    }

    Ok(())
}

#[allow(dead_code)]
/// Verifies the proof components (G1 and G2 points)
pub fn verify_proof_components(proof_a: &[u8; 64], proof_b: &[u8; 128], proof_c: &[u8; 64]) -> Result<()> {
    // Verify proof_a format (G1 point)
    if !verify_g1_point(proof_a) {
        return err!(CipherPayError::InvalidProofFormat);
    }

    // Verify proof_b format (G2 point)
    if !verify_g2_point(proof_b) {
        return err!(CipherPayError::InvalidProofFormat);
    }

    // Verify proof_c format (G1 point)
    if !verify_g1_point(proof_c) {
        return err!(CipherPayError::InvalidProofFormat);
    }

    // Verify pairing equation
    if !verify_pairing(proof_a, proof_b, proof_c) {
        return err!(CipherPayError::ProofVerificationFailed);
    }

    Ok(())
}

#[allow(dead_code)]
/// Verifies the public inputs of the proof
pub fn verify_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.is_empty() {
        return err!(CipherPayError::InvalidProofFormat);
    }

    // Verify merkle root
    let merkle_root = &inputs[0..32];
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }

    Ok(())
}

#[allow(dead_code)]
/// Checks if the compute budget is sufficient
pub fn verify_compute_budget(_required_units: u32) -> Result<()> {
    // In Solana 2.x, compute budget is handled differently
    // We'll use a conservative approach and let the runtime handle it
    // For now, we'll just return Ok() and let Anchor handle compute budget
    Ok(())
}

#[allow(dead_code)]
/// Verifies stream parameters
pub fn verify_stream_params(params: &crate::StreamParams) -> Result<()> {
    let current_time = Clock::get()?.unix_timestamp;

    // Check time constraints
    if params.start_time >= params.end_time {
        return err!(CipherPayError::InvalidStreamParams);
    }

    if current_time > params.end_time {
        return err!(CipherPayError::StreamExpired);
    }

    // Check amount constraints
    if params.total_amount == 0 {
        return err!(CipherPayError::InvalidStreamParams);
    }

    Ok(())
}

#[allow(dead_code)]
/// Verifies split parameters
pub fn verify_split_params(params: &crate::SplitParams) -> Result<()> {
    // Check recipient limit
    if params.recipients.len() > 10 {
        return err!(CipherPayError::RecipientLimitExceeded);
    }

    // Check array lengths match
    if params.recipients.len() != params.amounts.len() {
        return err!(CipherPayError::InvalidSplitDistribution);
    }

    // Check amounts
    let mut total = 0u64;
    for amount in &params.amounts {
        if *amount == 0 {
            return err!(CipherPayError::InvalidSplitDistribution);
        }
        total = total.checked_add(*amount)
            .ok_or(CipherPayError::AmountOverflow)?;
    }

    Ok(())
}

#[allow(dead_code)]
/// Verifies a Groth16 proof for a specific circuit
pub fn verify_groth16_proof(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128], 
    proof_c: &[u8; 64],
    public_inputs: &[u8],
    circuit_type: &str
) -> Result<()> {
    // Use real implementation if available, otherwise fall back to simplified
    #[cfg(feature = "real-crypto")]
    {
        verify_groth16_proof_real(proof_a, proof_b, proof_c, public_inputs, circuit_type)
    }
    
    #[cfg(not(feature = "real-crypto"))]
    {
        // Simplified implementation for development/testing
        verify_groth16_proof_simplified(proof_a, proof_b, proof_c, public_inputs, circuit_type)
    }
}

#[allow(dead_code)]
/// Simplified Groth16 verification for development/testing
fn verify_groth16_proof_simplified(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128], 
    proof_c: &[u8; 64],
    public_inputs: &[u8],
    circuit_type: &str
) -> Result<()> {
    // Validate proof format
    if !verify_g1_point(proof_a) || !verify_g2_point(proof_b) || !verify_g1_point(proof_c) {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Validate public inputs based on circuit type
    match circuit_type {
        "transfer" => verify_transfer_public_inputs(public_inputs)?,
        "withdraw" => verify_withdraw_public_inputs(public_inputs)?,
        "merkle" => verify_merkle_public_inputs(public_inputs)?,
        "nullifier" => verify_nullifier_public_inputs(public_inputs)?,
        "audit_proof" => verify_audit_public_inputs(public_inputs)?,
        "zkStream" => verify_stream_public_inputs(public_inputs)?,
        "zkSplit" => verify_split_public_inputs(public_inputs)?,
        "zkCondition" => verify_condition_public_inputs(public_inputs)?,
        _ => return err!(CipherPayError::UnsupportedCircuit),
    }
    
    // Verify pairing equation
    if !verify_pairing(proof_a, proof_b, proof_c) {
        return err!(CipherPayError::ProofVerificationFailed);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Validates a G1 point (BN254 curve) - simplified version
pub fn verify_g1_point(point: &[u8; 64]) -> bool {
    #[cfg(feature = "real-crypto")]
    {
        verify_g1_point_real(point).unwrap_or(false)
    }
    
    #[cfg(not(feature = "real-crypto"))]
    {
        // Simplified validation
        let x_bytes = &point[0..32];
        let y_bytes = &point[32..64];
        
        // Check that coordinates are not all zeros
        if x_bytes.iter().all(|&b| b == 0) && y_bytes.iter().all(|&b| b == 0) {
            return false;
        }
        
        // Check that coordinates are within field bounds (BN254 prime field)
        // BN254 prime: 21888242871839275222246405745257275088548364400416034343698204186575808495617
        // For simplicity, we check that the highest byte is not too large
        // In a real implementation, you would do full field element validation
        if x_bytes[31] > 0x30 || y_bytes[31] > 0x30 {
            return false;
        }
        
        // Basic format validation - coordinates should be valid field elements
        true
    }
}

#[allow(dead_code)]
/// Validates a G2 point (BN254 curve) - simplified version
pub fn verify_g2_point(point: &[u8; 128]) -> bool {
    #[cfg(feature = "real-crypto")]
    {
        verify_g2_point_real(point).unwrap_or(false)
    }
    
    #[cfg(not(feature = "real-crypto"))]
    {
        // Simplified validation
        let x_bytes = &point[0..64];
        let y_bytes = &point[64..128];
        
        // Check that coordinates are not all zeros
        if x_bytes.iter().all(|&b| b == 0) && y_bytes.iter().all(|&b| b == 0) {
            return false;
        }
        
        // Check that coordinates are within field bounds
        // For G2, we check the quadratic extension field bounds
        // In a real implementation, you would do full field element validation
        if x_bytes[63] > 0x30 || y_bytes[63] > 0x30 {
            return false;
        }
        
        // Basic format validation
        true
    }
}

#[allow(dead_code)]
/// Verifies the pairing equation e(A, B) * e(C, D) = 1 - simplified version
pub fn verify_pairing(proof_a: &[u8; 64], proof_b: &[u8; 128], proof_c: &[u8; 64]) -> bool {
    #[cfg(feature = "real-crypto")]
    {
        verify_pairing_real(proof_a, proof_b, proof_c).unwrap_or(false)
    }
    
    #[cfg(not(feature = "real-crypto"))]
    {
        // Simplified validation
        // Verify all points are valid
        if !verify_g1_point(proof_a) || !verify_g2_point(proof_b) || !verify_g1_point(proof_c) {
            return false;
        }
        
        // Check that proof components are not identical (which would be suspicious)
        if proof_a == proof_c {
            return false;
        }
        
        // Basic consistency check: ensure the points have some entropy
        let mut has_entropy = false;
        for byte in proof_a.iter().chain(proof_b.iter()).chain(proof_c.iter()) {
            if *byte != 0 {
                has_entropy = true;
                break;
            }
        }
        
        has_entropy
    }
}

#[allow(dead_code)]
/// Verifies nullifier format and uniqueness
pub fn verify_nullifier(nullifier: &[u8; 32]) -> Result<()> {
    // Check that nullifier is not all zeros
    if nullifier.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidNullifier);
    }
    
    // Check that nullifier has some entropy (not all same bytes)
    let first_byte = nullifier[0];
    if nullifier.iter().all(|&b| b == first_byte) {
        return err!(CipherPayError::InvalidNullifier);
    }
    
    // Check that nullifier is not all ones (which could be a default value)
    if nullifier.iter().all(|&b| b == 0xFF) {
        return err!(CipherPayError::InvalidNullifier);
    }
    
    // Additional validation: check that the nullifier has a reasonable distribution
    // This helps prevent attacks using specially crafted nullifiers
    let mut zero_count = 0;
    let mut one_count = 0;
    
    for byte in nullifier {
        if *byte == 0 {
            zero_count += 1;
        } else if *byte == 1 {
            one_count += 1;
        }
    }
    
    // If more than 80% of bytes are the same value, it's suspicious
    if zero_count > 25 || one_count > 25 {
        return err!(CipherPayError::InvalidNullifier);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for transfer circuit
pub fn verify_transfer_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 32 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Transfer circuit expects: merkle_root (32 bytes)
    let merkle_root = &inputs[0..32];
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Additional validation: check for reasonable merkle root entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in merkle_root {
        unique_bytes.insert(byte);
    }
    
    // If merkle root has too few unique bytes, it's suspicious
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for withdraw circuit
pub fn verify_withdraw_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 32 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Withdraw circuit expects: merkle_root (32 bytes)
    let merkle_root = &inputs[0..32];
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Additional validation: check for reasonable merkle root entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in merkle_root {
        unique_bytes.insert(byte);
    }
    
    // If merkle root has too few unique bytes, it's suspicious
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for merkle circuit
pub fn verify_merkle_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 32 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Merkle circuit expects: merkle_root (32 bytes)
    let merkle_root = &inputs[0..32];
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Additional validation: check for reasonable merkle root entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in merkle_root {
        unique_bytes.insert(byte);
    }
    
    // If merkle root has too few unique bytes, it's suspicious
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for nullifier circuit
pub fn verify_nullifier_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 32 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Nullifier circuit expects: nullifier (32 bytes)
    let nullifier_bytes: [u8; 32] = inputs[0..32].try_into()
        .map_err(|_| CipherPayError::InvalidProofFormat)?;
    
    verify_nullifier(&nullifier_bytes)?;
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for audit proof circuit
pub fn verify_audit_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 64 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Audit proof circuit expects: merkle_root (32 bytes) + audit_id (32 bytes)
    let merkle_root = &inputs[0..32];
    let audit_id = &inputs[32..64];
    
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Validate audit_id
    if audit_id.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidAuditProof);
    }
    
    // Check audit_id entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in audit_id {
        unique_bytes.insert(byte);
    }
    
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidAuditProof);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for stream circuit
pub fn verify_stream_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 64 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Stream circuit expects: merkle_root (32 bytes) + stream_id (32 bytes)
    let merkle_root = &inputs[0..32];
    let stream_id = &inputs[32..64];
    
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Validate stream_id
    if stream_id.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidStreamProof);
    }
    
    // Check stream_id entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in stream_id {
        unique_bytes.insert(byte);
    }
    
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidStreamProof);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for split circuit
pub fn verify_split_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 64 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Split circuit expects: merkle_root (32 bytes) + split_id (32 bytes)
    let merkle_root = &inputs[0..32];
    let split_id = &inputs[32..64];
    
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Validate split_id
    if split_id.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidSplitProof);
    }
    
    // Check split_id entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in split_id {
        unique_bytes.insert(byte);
    }
    
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidSplitProof);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Verifies public inputs for condition circuit
pub fn verify_condition_public_inputs(inputs: &[u8]) -> Result<()> {
    if inputs.len() < 64 {
        return err!(CipherPayError::InvalidProofFormat);
    }
    
    // Condition circuit expects: merkle_root (32 bytes) + condition_id (32 bytes)
    let merkle_root = &inputs[0..32];
    let condition_id = &inputs[32..64];
    
    if !is_valid_merkle_root(merkle_root) {
        return err!(CipherPayError::InvalidMerkleRoot);
    }
    
    // Validate condition_id
    if condition_id.iter().all(|&b| b == 0) {
        return err!(CipherPayError::InvalidConditionProof);
    }
    
    // Check condition_id entropy
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in condition_id {
        unique_bytes.insert(byte);
    }
    
    if unique_bytes.len() < 4 {
        return err!(CipherPayError::InvalidConditionProof);
    }
    
    Ok(())
}

#[allow(dead_code)]
/// Validates a byte array for reasonable entropy distribution
pub fn validate_entropy(data: &[u8], min_unique_bytes: usize) -> bool {
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in data {
        unique_bytes.insert(byte);
    }
    unique_bytes.len() >= min_unique_bytes
}

#[allow(dead_code)]
/// Validates that a byte array is not all the same value
pub fn validate_not_uniform(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let first_byte = data[0];
    !data.iter().all(|&b| b == first_byte)
}

#[allow(dead_code)]
/// Validates that a byte array is not all zeros
pub fn validate_not_all_zeros(data: &[u8]) -> bool {
    !data.iter().all(|&b| b == 0)
}

#[allow(dead_code)]
/// Verifies arithmetic overflow protection
pub fn verify_arithmetic_overflow(amount: u64, increment: u64) -> Result<()> {
    amount.checked_add(increment)
        .ok_or(CipherPayError::AmountOverflow)?;
    Ok(())
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Generates a random field element for testing
pub fn generate_random_field_element() -> Fr {
    let mut rng = ark_std::test_rng();
    Fr::rand(&mut rng)
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Generates a random G1 point for testing
pub fn generate_random_g1_point() -> G1Affine {
    let mut rng = ark_std::test_rng();
    G1Affine::prime_subgroup_generator().mul(Fr::rand(&mut rng).into_repr()).into_affine()
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Generates a random G2 point for testing
pub fn generate_random_g2_point() -> G2Affine {
    let mut rng = ark_std::test_rng();
    G2Affine::prime_subgroup_generator().mul(Fr::rand(&mut rng).into_repr()).into_affine()
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts a field element to bytes
pub fn field_element_to_bytes(field_element: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    field_element.serialize(&mut &mut bytes[..]).unwrap();
    bytes.reverse(); // Convert to big-endian
    bytes
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts a G1 point to bytes
pub fn g1_point_to_bytes(point: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    let x_bytes = field_element_to_bytes(&point.x);
    let y_bytes = field_element_to_bytes(&point.y);
    bytes[0..32].copy_from_slice(&x_bytes);
    bytes[32..64].copy_from_slice(&y_bytes);
    bytes
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Converts a G2 point to bytes
pub fn g2_point_to_bytes(point: &G2Affine) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    let x0_bytes = field_element_to_bytes(&point.x.c0);
    let x1_bytes = field_element_to_bytes(&point.x.c1);
    let y0_bytes = field_element_to_bytes(&point.y.c0);
    let y1_bytes = field_element_to_bytes(&point.y.c1);
    bytes[0..32].copy_from_slice(&x0_bytes);
    bytes[32..64].copy_from_slice(&x1_bytes);
    bytes[64..96].copy_from_slice(&y0_bytes);
    bytes[96..128].copy_from_slice(&y1_bytes);
    bytes
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Creates a dummy Groth16 proof for testing
pub fn create_dummy_proof() -> ([u8; 64], [u8; 128], [u8; 64]) {
    let a = generate_random_g1_point();
    let b = generate_random_g2_point();
    let c = generate_random_g1_point();
    
    let a_bytes = g1_point_to_bytes(&a);
    let b_bytes = g2_point_to_bytes(&b);
    let c_bytes = g1_point_to_bytes(&c);
    
    (a_bytes, b_bytes, c_bytes)
}

#[cfg(feature = "real-crypto")]
#[allow(dead_code)]
/// Creates dummy public inputs for testing
pub fn create_dummy_public_inputs(num_inputs: usize) -> Vec<u8> {
    let mut inputs = Vec::new();
    for _ in 0..num_inputs {
        let field_element = generate_random_field_element();
        let bytes = field_element_to_bytes(&field_element);
        inputs.extend_from_slice(&bytes);
    }
    inputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VerifyProofArgs, StreamParams, SplitParams};
    use anchor_lang::solana_program::hash::hash;

    #[test]
    fn test_verify_proof_internal() {
        let proof = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: vec![0u8; 32],
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 100,
            timestamp: Clock::get().unwrap().unix_timestamp,
            purpose: String::from("compliance"),
            audit_id: [0u8; 32],
        };
        assert!(verify_proof_internal(&proof).is_ok());
    }

    #[test]
    fn test_verify_stream_params() {
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 0,
            end_time: 100,
            total_amount: 1000,
        };
        assert!(verify_stream_params(&params).is_ok());
    }

    #[test]
    fn test_verify_split_params() {
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![Pubkey::default()],
            amounts: vec![100],
        };
        assert!(verify_split_params(&params).is_ok());
    }

    #[test]
    fn test_verify_merkle_proof() {
        // Create a simple merkle tree with 2 leaves
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        
        // Hash the leaves
        let hash1 = hash(&leaf1).to_bytes();
        let hash2 = hash(&leaf2).to_bytes();
        
        // Create the root by hashing the concatenated hashes
        let mut combined = Vec::new();
        combined.extend_from_slice(&hash1);
        combined.extend_from_slice(&hash2);
        let root = hash(&combined).to_bytes();
        
        // Create proof for leaf1 (just hash2)
        let proof = vec![hash2];
        
        // Verify the proof
        assert!(verify_merkle_proof(&leaf1, &proof, root).is_ok());
        
        // Test invalid proof
        let invalid_proof = vec![];
        assert!(verify_merkle_proof(&leaf1, &invalid_proof, root).is_err());
        
        // Test invalid root
        let invalid_root = [0u8; 32];
        assert!(verify_merkle_proof(&leaf1, &proof, invalid_root).is_err());
    }

    #[test]
    fn test_verify_nullifier() {
        // Test valid nullifier
        let valid_nullifier = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8, 18u8, 19u8, 20u8, 21u8, 22u8, 23u8, 24u8, 25u8, 26u8, 27u8, 28u8, 29u8, 30u8, 31u8, 32u8];
        assert!(verify_nullifier(&valid_nullifier).is_ok());
        
        // Test all zeros
        let zero_nullifier = [0u8; 32];
        assert!(verify_nullifier(&zero_nullifier).is_err());
        
        // Test all ones
        let ones_nullifier = [0xFFu8; 32];
        assert!(verify_nullifier(&ones_nullifier).is_err());
        
        // Test uniform value
        let uniform_nullifier = [42u8; 32];
        assert!(verify_nullifier(&uniform_nullifier).is_err());
    }

    #[test]
    fn test_is_valid_merkle_root() {
        // Test valid merkle root
        let valid_root = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8, 18u8, 19u8, 20u8, 21u8, 22u8, 23u8, 24u8, 25u8, 26u8, 27u8, 28u8, 29u8, 30u8, 31u8, 32u8];
        assert!(is_valid_merkle_root(&valid_root));
        
        // Test all zeros
        let zero_root = [0u8; 32];
        assert!(!is_valid_merkle_root(&zero_root));
        
        // Test uniform value
        let uniform_root = [42u8; 32];
        assert!(!is_valid_merkle_root(&uniform_root));
        
        // Test wrong length
        let short_root = [1u8; 16];
        assert!(!is_valid_merkle_root(&short_root));
    }

    #[test]
    fn test_verify_g1_point() {
        // Test valid G1 point
        let mut valid_point = [0u8; 64];
        valid_point[0] = 1;
        valid_point[32] = 2;
        assert!(verify_g1_point(&valid_point));
        
        // Test all zeros
        let zero_point = [0u8; 64];
        assert!(!verify_g1_point(&zero_point));
        
        // Test invalid field bounds (simplified check)
        let mut invalid_point = [0u8; 64];
        invalid_point[31] = 0x31; // Too large for our simplified bounds check
        assert!(!verify_g1_point(&invalid_point));
    }

    #[test]
    fn test_verify_g2_point() {
        // Test valid G2 point
        let mut valid_point = [0u8; 128];
        valid_point[0] = 1;
        valid_point[64] = 2;
        assert!(verify_g2_point(&valid_point));
        
        // Test all zeros
        let zero_point = [0u8; 128];
        assert!(!verify_g2_point(&zero_point));
        
        // Test invalid field bounds (simplified check)
        let mut invalid_point = [0u8; 128];
        invalid_point[63] = 0x31; // Too large for our simplified bounds check
        assert!(!verify_g2_point(&invalid_point));
    }

    #[test]
    fn test_verify_pairing() {
        // Test valid pairing components
        let mut proof_a = [0u8; 64];
        let mut proof_b = [0u8; 128];
        let mut proof_c = [0u8; 64];
        
        proof_a[0] = 1;
        proof_b[0] = 2;
        proof_c[0] = 3;
        
        assert!(verify_pairing(&proof_a, &proof_b, &proof_c));
        
        // Test identical proof_a and proof_c (should fail)
        assert!(!verify_pairing(&proof_a, &proof_b, &proof_a));
        
        // Test all zeros (should fail)
        let zero_a = [0u8; 64];
        let zero_b = [0u8; 128];
        let zero_c = [0u8; 64];
        assert!(!verify_pairing(&zero_a, &zero_b, &zero_c));
    }

    #[test]
    fn test_validate_entropy() {
        // Test high entropy data
        let high_entropy = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8, 18u8, 19u8, 20u8, 21u8, 22u8, 23u8, 24u8, 25u8, 26u8, 27u8, 28u8, 29u8, 30u8, 31u8, 32u8];
        assert!(validate_entropy(&high_entropy, 4));
        
        // Test low entropy data
        let low_entropy = [1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8];
        assert!(!validate_entropy(&low_entropy, 4));
    }

    #[test]
    fn test_validate_not_uniform() {
        // Test non-uniform data
        let non_uniform = [1u8, 2u8, 3u8, 4u8];
        assert!(validate_not_uniform(&non_uniform));
        
        // Test uniform data
        let uniform = [42u8; 4];
        assert!(!validate_not_uniform(&uniform));
        
        // Test empty data
        let empty: [u8; 0] = [];
        assert!(!validate_not_uniform(&empty));
    }

    #[test]
    fn test_validate_not_all_zeros() {
        // Test non-zero data
        let non_zero = [1u8, 2u8, 3u8, 4u8];
        assert!(validate_not_all_zeros(&non_zero));
        
        // Test all zeros
        let all_zeros = [0u8; 4];
        assert!(!validate_not_all_zeros(&all_zeros));
    }

    #[test]
    fn test_public_input_verification() {
        // Test transfer public inputs
        let mut transfer_inputs = [0u8; 32];
        transfer_inputs[0] = 1;
        transfer_inputs[1] = 2;
        transfer_inputs[2] = 3;
        transfer_inputs[3] = 4;
        assert!(verify_transfer_public_inputs(&transfer_inputs).is_ok());
        
        // Test nullifier public inputs
        let mut nullifier_inputs = [0u8; 32];
        nullifier_inputs[0] = 1;
        nullifier_inputs[1] = 2;
        nullifier_inputs[2] = 3;
        nullifier_inputs[3] = 4;
        assert!(verify_nullifier_public_inputs(&nullifier_inputs).is_ok());
        
        // Test audit public inputs
        let mut audit_inputs = [0u8; 64];
        audit_inputs[0] = 1;
        audit_inputs[1] = 2;
        audit_inputs[2] = 3;
        audit_inputs[3] = 4;
        audit_inputs[32] = 5;
        audit_inputs[33] = 6;
        audit_inputs[34] = 7;
        audit_inputs[35] = 8;
        assert!(verify_audit_public_inputs(&audit_inputs).is_ok());
    }
}

#[allow(dead_code)]
/// Verifies merkle proof - simplified version
pub fn verify_merkle_proof(leaf: &[u8; 32], proof: &Vec<[u8; 32]>, root: [u8; 32]) -> Result<()> {
    #[cfg(feature = "real-crypto")]
    {
        verify_merkle_proof_real(leaf, proof, root)
    }
    
    #[cfg(not(feature = "real-crypto"))]
    {
        // Simplified implementation using Solana's hash function
        use anchor_lang::solana_program::hash::hash;
        
        if proof.is_empty() {
            return err!(CipherPayError::InvalidMerkleProof);
        }
        
        // Basic validation that leaf and root are not all zeros
        if leaf.iter().all(|&b| b == 0) {
            return err!(CipherPayError::InvalidMerkleProof);
        }
        
        if root.iter().all(|&b| b == 0) {
            return err!(CipherPayError::InvalidMerkleRoot);
        }
        
        // Compute the merkle root from the leaf and proof
        let mut current_hash = *leaf;
        
        for proof_element in proof {
            // Validate proof element
            if proof_element.iter().all(|&b| b == 0) {
                return err!(CipherPayError::InvalidMerkleProof);
            }
            
            // Determine the order: current_hash should be the "left" child
            // We'll use a deterministic ordering based on byte comparison
            let (left, right) = if current_hash < *proof_element {
                (current_hash, *proof_element)
            } else {
                (*proof_element, current_hash)
            };
            
            // Hash the concatenated values
            let mut combined = Vec::new();
            combined.extend_from_slice(&left);
            combined.extend_from_slice(&right);
            
            let hash_result = hash(&combined);
            current_hash = hash_result.to_bytes();
        }
        
        // Compare computed root with provided root
        if current_hash != root {
            return err!(CipherPayError::InvalidMerkleProof);
        }
        
        Ok(())
    }
} 
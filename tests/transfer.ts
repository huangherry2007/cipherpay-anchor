import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { assert } from "chai";
import fs from "fs";
import path from "path";

import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

/**
 * TypeScript Integration Tests for Shielded Transfer
 * 
 * Purpose: Real program integration testing with actual ZK proofs
 * Focus: Client-side transfer workflows, real cryptographic validation
 * 
 * These tests complement the Rust unit tests by testing:
 * - Real program deployment and execution
 * - Actual ZK proof verification for transfers
 * - Client-side integration patterns
 * - Production-like transfer scenarios
 */

// === Utility: Load proof, inputs, and nullifier ===
function loadTransferProofAndInputs() {
  const proof = fs.readFileSync(path.resolve(__dirname, `../proofs/transfer_proof.bin`));
  const publicInputs = fs.readFileSync(path.resolve(__dirname, `../proofs/transfer_public_inputs.bin`));
  
  // Validate the new circuit structure: 6 signals for transfer circuit
  if (publicInputs.length !== 192) { // 6 signals × 32 bytes
    throw new Error(`Expected 192 bytes for transfer public inputs, got ${publicInputs.length}`);
  }
  
  // Extract nullifier from public inputs (signal 0 - index 0-31)
  // The new transfer circuit structure has 6 signals:
  // Signal 0: Nullifier (0-31)
  // Signal 1: Merkle root (32-63)
  // Signal 2: Out1 commitment (64-95)
  // Signal 3: Out2 commitment (96-127)
  // Signal 4: Out1 pubkey (128-159)
  // Signal 5: Out2 pubkey (160-191)
  const nullifier = Buffer.from(publicInputs.subarray(0, 32));
  
  return { proof, publicInputs, nullifier };
}

// === Real Program Integration Tests ===
describe("Shielded Transfer - Real Program Integration", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;

  // Test accounts
  const rootCache = Keypair.generate();
  const nullifierRecord = Keypair.generate();

  it("Executes real shielded transfer with ZK proof verification", async () => {
    const { proof, publicInputs, nullifier } = loadTransferProofAndInputs();

    console.log("🔍 REAL TRANSFER ZK PROOF VERIFICATION");
    console.log("📊 Proof size:", proof.length, "bytes");
    console.log("📋 Public inputs size:", publicInputs.length, "bytes");
    console.log("🔐 Nullifier:", nullifier.toString('hex'));

    const [vaultPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    const [nullifierRecordPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), nullifier],
      program.programId
    );

    // Core test - real ZK proof verification for transfer
    const tx = await program.methods
      .shieldedTransfer([...nullifier], [...proof], [...publicInputs])
      .accounts({
        authority: provider.wallet.publicKey,
        rootCache: rootCache.publicKey,
        nullifierRecord: nullifierRecordPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([]) // PDA accounts don't need to sign
      .rpc();

    console.log("✅ REAL transfer ZK proof verification successful:", tx);
  });

  it("Validates real transfer circuit structure and data", async () => {
    const { proof, publicInputs } = loadTransferProofAndInputs();
    
    console.log("🔍 REAL TRANSFER CIRCUIT VALIDATION");
    console.log("📏 Proof size:", proof.length, "bytes (expected: 512)");
    console.log("📏 Public inputs size:", publicInputs.length, "bytes (expected: 192)");
    
    // Validate proof structure for groth16-solana compatibility
    assert.equal(proof.length, 512, "Proof should be 512 bytes for Groth16");
    assert.equal(publicInputs.length, 192, "Public inputs should be 192 bytes (6 signals × 32 bytes)");
    
    // Extract and display real circuit signals
    const nullifier = publicInputs.subarray(0, 32);
    const merkleRoot = publicInputs.subarray(32, 64);
    const out1Commitment = publicInputs.subarray(64, 96);
    const out2Commitment = publicInputs.subarray(96, 128);
    const out1Pubkey = publicInputs.subarray(128, 160);
    const out2Pubkey = publicInputs.subarray(160, 192);
    
    console.log("📋 Real transfer circuit signals:");
    console.log("   Signal 0 (Nullifier):", nullifier.toString('hex'));
    console.log("   Signal 1 (Merkle Root):", merkleRoot.toString('hex'));
    console.log("   Signal 2 (Out1 Commitment):", out1Commitment.toString('hex'));
    console.log("   Signal 3 (Out2 Commitment):", out2Commitment.toString('hex'));
    console.log("   Signal 4 (Out1 Pubkey):", out1Pubkey.toString('hex'));
    console.log("   Signal 5 (Out2 Pubkey):", out2Pubkey.toString('hex'));
    
    console.log("✅ Real transfer circuit validation passed");
  });
});

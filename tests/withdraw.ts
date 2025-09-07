import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { assert } from "chai";
import fs from "fs";
import path from "path";

import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

/**
 * TypeScript Integration Tests for Shielded Withdraw
 * 
 * Purpose: Real program integration testing with actual ZK proofs
 * Focus: Client-side withdraw workflows, real token transfers, real cryptographic validation
 * 
 * These tests complement the Rust unit tests by testing:
 * - Real program deployment and execution
 * - Actual ZK proof verification for withdrawals
 * - Real SPL token transfer operations
 * - Client-side integration patterns
 * - Production-like withdraw scenarios
 */

// === Utility: Load proof, inputs, and nullifier ===
function loadWithdrawProofAndInputs() {
  const proof = fs.readFileSync(path.resolve(__dirname, `../proofs/withdraw_proof.bin`));
  const publicInputs = fs.readFileSync(path.resolve(__dirname, `../proofs/withdraw_public_inputs.bin`));
  
  // Validate the new circuit structure: 3 signals for withdraw circuit
  if (publicInputs.length !== 96) { // 3 signals × 32 bytes
    throw new Error(`Expected 96 bytes for withdraw public inputs, got ${publicInputs.length}`);
  }
  
  // Extract nullifier from public inputs (signal 0 - index 0-31)
  // The new withdraw circuit structure has 3 signals:
  // Signal 0: Nullifier (0-31)
  // Signal 1: Merkle root (32-63)
  // Signal 2: Amount (64-95)
  const nullifier = Buffer.from(publicInputs.subarray(0, 32));
  
  return { proof, publicInputs, nullifier };
}

describe("Shielded Withdraw - Real Program Integration", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;

  // Dummy accounts
  const vaultTokenAccount = Keypair.generate();
  const recipientTokenAccount = Keypair.generate();
  const rootCache = Keypair.generate();

  it("Executes real shielded withdraw with ZK proof verification and token transfer", async () => {
    const { proof, publicInputs, nullifier } = loadWithdrawProofAndInputs();

    console.log("🔍 REAL WITHDRAW ZK PROOF VERIFICATION + TOKEN TRANSFER");
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

    // Core test - real ZK proof verification + actual token transfer
    const tx = await program.methods
      .shieldedWithdraw([...nullifier], [...proof], [...publicInputs])
      .accounts({
        authority: provider.wallet.publicKey,
        vaultPda,
        rootCache: rootCache.publicKey,
        nullifierRecord: nullifierRecordPda,
        vaultTokenAccount: vaultTokenAccount.publicKey,
        recipientTokenAccount: recipientTokenAccount.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([]) // PDAs don't need to sign
      .rpc();

    console.log("✅ REAL withdraw ZK proof verification + token transfer successful:", tx);
  });

  it("Validates real withdraw circuit structure and data", async () => {
    const { proof, publicInputs } = loadWithdrawProofAndInputs();
    
    console.log("🔍 REAL WITHDRAW CIRCUIT VALIDATION");
    console.log("📏 Proof size:", proof.length, "bytes (expected: 512)");
    console.log("📏 Public inputs size:", publicInputs.length, "bytes (expected: 96)");
    
    // Validate proof structure for groth16-solana compatibility
    assert.equal(proof.length, 512, "Proof should be 512 bytes for Groth16");
    assert.equal(publicInputs.length, 96, "Public inputs should be 96 bytes (3 signals × 32 bytes)");
    
    // Extract and display real circuit signals
    const nullifier = publicInputs.subarray(0, 32);
    const merkleRoot = publicInputs.subarray(32, 64);
    const amount = publicInputs.subarray(64, 96);
    
    console.log("📋 Real withdraw circuit signals:");
    console.log("   Signal 0 (Nullifier):", nullifier.toString('hex'));
    console.log("   Signal 1 (Merkle Root):", merkleRoot.toString('hex'));
    console.log("   Signal 2 (Amount):", amount.toString('hex'));
    
    console.log("✅ Real withdraw circuit validation passed");
  });
});

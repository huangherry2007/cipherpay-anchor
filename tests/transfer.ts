import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { assert } from "chai";
import fs from "fs";
import path from "path";

import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

// === Utility: Load proof, inputs, and nullifier ===
function loadTransferProofAndInputs() {
  const proof = fs.readFileSync(path.resolve(__dirname, `../proofs/transfer_proof.bin`));
  const publicInputs = fs.readFileSync(path.resolve(__dirname, `../proofs/transfer_public_inputs.bin`));
  const nullifier = Buffer.from(publicInputs.subarray(0, 32)); // publicInputs[0]
  return { proof, publicInputs, nullifier };
}

// === Anchor Test ===
describe("cipherpay-anchor → shielded_transfer", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;

  // Test accounts
  const rootCache = Keypair.generate();
  const nullifierRecord = Keypair.generate();

  it("should verify transfer ZK proof and emit event", async () => {
    const { proof, publicInputs, nullifier } = loadTransferProofAndInputs();

    const [vaultPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    const [nullifierRecordPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), nullifier],
      program.programId
    );

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

    console.log("✅ Transfer successful:", tx);

    // TODO: add validation checks for on-chain nullifier record
  });
});

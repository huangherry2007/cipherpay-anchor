import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { assert } from "chai";
import fs from "fs";
import path from "path";

import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

// === Utility: Load proof and inputs ===
function loadProofAndInputs(circuitName: string) {
  const proof = fs.readFileSync(path.resolve(__dirname, `../proofs/${circuitName}_proof.bin`));
  const publicInputs = fs.readFileSync(path.resolve(__dirname, `../proofs/${circuitName}_public_inputs.bin`));
  const depositHash = Buffer.from(publicInputs.subarray(0, 32)); // publicInputs[0]
  return { proof, publicInputs, depositHash };
}

// === Anchor Test ===
describe("cipherpay-anchor → shielded_deposit", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;

  // Example test accounts
  const vault = Keypair.generate();
  const rootCache = Keypair.generate();

  it("should verify deposit ZK proof and emit event", async () => {
    const user = provider.wallet;
    const { proof, publicInputs, depositHash } = loadProofAndInputs("deposit");

    // Derive PDAs (replace with your actual seeds)
    const [vaultPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    // Send the transaction
    const tx = await program.methods
      .shieldedDeposit([...depositHash], [...proof], [...publicInputs])
      .accounts({
        authority: user.publicKey,
        vault: vault.publicKey,
        vaultPda,
        rootCache: rootCache.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([vault, rootCache])
      .rpc();

    console.log("✅ Transaction successful:", tx);

    // TODO: optionally fetch on-chain state or events to verify
  });
});

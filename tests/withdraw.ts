import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { assert } from "chai";
import fs from "fs";
import path from "path";

import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

// === Utility: Load proof, inputs, and nullifier ===
function loadWithdrawProofAndInputs() {
  const proof = fs.readFileSync(path.resolve(__dirname, `../proofs/withdraw_proof.bin`));
  const publicInputs = fs.readFileSync(path.resolve(__dirname, `../proofs/withdraw_public_inputs.bin`));
  const nullifier = Buffer.from(publicInputs.subarray(128, 160)); // publicInputs[4]
  return { proof, publicInputs, nullifier };
}

describe("cipherpay-anchor → shielded_withdraw", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;

  // Dummy accounts
  const vaultTokenAccount = Keypair.generate();
  const recipientTokenAccount = Keypair.generate();
  const rootCache = Keypair.generate();

  it("should verify withdraw ZK proof and transfer tokens", async () => {
    const { proof, publicInputs, nullifier } = loadWithdrawProofAndInputs();

    const [vaultPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    const [nullifierRecordPda] = await PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), nullifier],
      program.programId
    );

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

    console.log("✅ Withdraw transaction successful:", tx);

    // Optionally verify balances or nullifier record state
  });
});

// tests/withdraw.ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair, Connection } from "@solana/web3.js";
import { assert } from "chai";
import fs from "fs";
import path from "path";

import {
  getAssociatedTokenAddressSync,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createMint,
} from "@solana/spl-token";

import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

// === Utility: Load proof, public signals, and nullifier ===
function loadWithdrawProofAndSignals() {
  const proof = fs.readFileSync(
    path.resolve(__dirname, "../proofs/withdraw_proof.bin")
  );
  const publicSignals = fs.readFileSync(
    path.resolve(__dirname, "../proofs/withdraw_public_signals.bin")
  );

  // Your generator writes a 256-byte Groth16 proof
  if (proof.length !== 256) {
    throw new Error(`Expected 256-byte Groth16 proof, got ${proof.length}`);
  }

  // Withdraw circuit: 5 public signals -> 160 bytes
  if (publicSignals.length !== 5 * 32) {
    throw new Error(
      `Expected 160 bytes for withdraw public signals, got ${publicSignals.length}`
    );
  }

  // Signal order: [nullifier, merkleRoot, recipientWalletPubKey, amount, tokenId]
  const nullifier = publicSignals.subarray(0, 32);

  return { proof, publicSignals, nullifier };
}

describe("Shielded Withdraw - Real Program Integration", () => {
  // near the top of the test file (before anchor.setProvider)
  const RPC_URL =
    process.env.SOLANA_URL ||
    process.env.ANCHOR_PROVIDER_URL ||
    "http://127.0.0.1:8899";

  const KEYPAIR_PATH =
    process.env.ANCHOR_WALLET ||
    `${process.env.HOME}/.config/solana/id.json`;

  const payer = Keypair.fromSecretKey(
    Buffer.from(JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf8")))
  );

  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = new anchor.Wallet(payer);
  const provider = new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });

  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;

  // NOTE: these are placeholders; real test should use real SPL token accounts
  const vaultTokenAccount = Keypair.generate();
  const recipientTokenAccount = Keypair.generate();
  const rootCache = Keypair.generate();
  
  it("Executes shielded withdraw with ZK proof verification", async () => {
    const { proof, publicSignals, nullifier } = loadWithdrawProofAndSignals();
  
    // --- derive PDAs & create a real mint/ATAs (do this in your beforeAll in practice) ---
    // 1) Create a mint for the test (or reuse the one from your deposit/transfer test)
    const tokenMint = await createMint(
      provider.connection,
      (provider.wallet as any).payer,
      provider.wallet.publicKey, // mint authority
      null,                      // freeze authority
      0                          // decimals
    );
  
    // 2) Program vault PDA
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );
  
    // 3) Vault ATA (must be the true ATA PDA)
    const vaultTokenAccount = getAssociatedTokenAddressSync(
      tokenMint,
      vaultPda,
      true,                      // ATA for a PDA owner
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
  
    // 4) Recipient owner + ATA
    const recipientOwner = provider.wallet.publicKey; // withdraw to the test wallet
    const recipientTokenAccount = getAssociatedTokenAddressSync(
      tokenMint,
      recipientOwner,
      false,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
  
    // 5) Nullifier PDA (IDL wants it in accounts)
    const [nullifierRecord] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), Buffer.from(nullifier)],
      program.programId
    );
  
    // NOTE: make sure rootCache exists & contains the withdraw merkle root.
    // Typically: run deposit -> transfer first (which updates rootCache),
    // or include those steps here. Otherwise you’ll hit UnknownMerkleRoot.
  
    // --- call the instruction (use accountsPartial while iterating) ---
    const sig = await program.methods
      .shieldedWithdraw(Array.from(nullifier), proof, publicSignals)
      .accountsPartial({
        nullifierRecord,
        rootCache: rootCache.publicKey, // ensure you've created it with initializeRootCache
        authority: provider.wallet.publicKey,
        vaultPda,
        vaultTokenAccount,
        recipientTokenAccount,
        recipientOwner,
        tokenMint,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .rpc();
  
    console.log("✅ withdraw sent:", sig);
  });
  
  it("Validates withdraw circuit outputs & sizes", async () => {
    const { proof, publicSignals } = loadWithdrawProofAndSignals();

    console.log("🔍 WITHDRAW CIRCUIT VALIDATION");
    console.log("📏 Proof size:", proof.length, "(expected: 256)");
    console.log("📏 Public signals size:", publicSignals.length, "(expected: 160)");

    assert.equal(proof.length, 256, "Groth16 proof should be 256 bytes");
    assert.equal(
      publicSignals.length,
      160,
      "Withdraw public signals should be 160 bytes (5 × 32)"
    );

    const s0_nullifier = publicSignals.subarray(0, 32);
    const s1_merkleRoot = publicSignals.subarray(32, 64);
    const s2_recipientWalletPubKey = publicSignals.subarray(64, 96);
    const s3_amount = publicSignals.subarray(96, 128);
    const s4_tokenId = publicSignals.subarray(128, 160);

    console.log("📋 Signals (LE hex):");
    console.log("   0 nullifier              :", Buffer.from(s0_nullifier).toString("hex"));
    console.log("   1 merkleRoot             :", Buffer.from(s1_merkleRoot).toString("hex"));
    console.log("   2 recipientWalletPubKey  :", Buffer.from(s2_recipientWalletPubKey).toString("hex"));
    console.log("   3 amount                 :", Buffer.from(s3_amount).toString("hex"));
    console.log("   4 tokenId                :", Buffer.from(s4_tokenId).toString("hex"));

    console.log("✅ Withdraw circuit validation passed");
  });
});

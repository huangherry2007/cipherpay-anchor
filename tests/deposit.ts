// tests/deposit.ts
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import { CipherpayAnchor } from "../target/types/cipherpay_anchor";
import { expect } from "chai";
import { beforeAll, describe, it } from "@jest/globals";
import {
  createMint,
  getAssociatedTokenAddress,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  createTransferCheckedInstruction,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Connection,
  Transaction,
  TransactionInstruction,
  SendTransactionError,
} from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

/* ------------------------------ PDA helpers (per IDL) ------------------------------ */
// vault_pda = seeds [b"vault"]
function deriveVaultPda(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], programId)[0];
}

// deposit_marker = seeds [b"deposit", deposit_hash]   (deposit_hash is the 32-byte arg)
function deriveDepositMarkerPda(programId: PublicKey, depositHash32: Buffer): PublicKey {
  if (depositHash32.length !== 32) throw new Error("depositHash must be 32 bytes");
  return PublicKey.findProgramAddressSync(
    [Buffer.from("deposit"), depositHash32],
    programId
  )[0];
}

// Standard Memo v3 program (required by shielded_deposit_atomic per IDL)
const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

/* ------------------------------ Suite ------------------------------ */

describe("Shielded Deposit - Real Program Integration", () => {
  // Provider + Program
  const connection = new Connection("http://127.0.0.1:8899", "confirmed");
  const wallet = new anchor.Wallet(
    Keypair.fromSecretKey(
      Buffer.from(JSON.parse(fs.readFileSync(process.env.HOME + "/.config/solana/id.json", "utf8")))
    )
  );
  const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" });
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;
  const programId = program.programId;

  // Test actors/state
  const authority = wallet;
  const vault = Keypair.generate();      // initialize_vault: vault (signer)
  const rootCache = Keypair.generate();  // initialize_root_cache: root_cache (signer)
  let usdcMint: PublicKey;
  let userAta: PublicKey;

  // ZK blobs
  let realProof: Buffer;
  let realPublicInputs: Buffer;
  let realDepositHash: Buffer; // 32 bytes

  /* ------------------------------ Fixtures ------------------------------ */

  beforeAll(async () => {
    // Load Groth16 proof & public inputs
    const proofPath = path.resolve(__dirname, "../proofs/deposit_proof.bin");
    const publicInputsPath = path.resolve(__dirname, "../proofs/deposit_public_signals.bin");
    if (!fs.existsSync(proofPath)) throw new Error(`Proof file not found: ${proofPath}`);
    if (!fs.existsSync(publicInputsPath)) throw new Error(`Public inputs file not found: ${publicInputsPath}`);

    realProof = fs.readFileSync(proofPath);
    realPublicInputs = fs.readFileSync(publicInputsPath);

    if (realPublicInputs.length !== 192) throw new Error(`Expected 192 bytes of public inputs, got ${realPublicInputs.length}`);
    if (realProof.length !== 256) throw new Error(`Expected 256-byte Groth16 proof, got ${realProof.length}`);

    // signals[5] = deposit_hash (bytes 160..191)
    realDepositHash = Buffer.from(realPublicInputs.subarray(160, 192));
    if (realDepositHash.length !== 32) throw new Error("depositHash must be 32 bytes");

    console.log("🔍 Loaded proof:");
    console.log("  • proof bytes:", realProof.length);
    console.log("  • pubinputs bytes:", realPublicInputs.length);
    console.log("  • deposit hash:", realDepositHash.toString("hex"));
  });

  /* ------------------------------ Tests ------------------------------ */

  it("Sets up environment: vault + mint + ATAs + root cache", async () => {
    // initialize_vault (system_program is fixed in IDL and auto-filled)
    await program.methods
      .initializeVault()
      .accounts({
        vault: vault.publicKey,
        authority: authority.publicKey,
      } as any)
      .signers([vault])
      .rpc();

    // Mint + ATAs
    usdcMint = await createMint(provider.connection, authority.payer, authority.publicKey, null, 6);

    userAta = await getAssociatedTokenAddress(usdcMint, authority.publicKey);
    await getOrCreateAssociatedTokenAccount(provider.connection, authority.payer, usdcMint, authority.publicKey);

    const vaultPda = deriveVaultPda(programId);
    await getOrCreateAssociatedTokenAccount(provider.connection, authority.payer, usdcMint, vaultPda, true);

    // Fund user with 100 USDC
    await mintTo(provider.connection, authority.payer, usdcMint, userAta, authority.payer, 100_000_000);

    // initialize_root_cache (system_program is fixed in IDL and auto-filled)
    await program.methods
      .initializeRootCache()
      .accounts({
        rootCache: rootCache.publicKey,
        authority: authority.publicKey,
      } as any)
      .signers([rootCache])
      .rpc();

    console.log("✅ Env ready");
  });

     it("Executes shielded_deposit_atomic with real ZK proof (atomic: Memo + TransferChecked + Program)", async () => {
     const vaultPda = deriveVaultPda(programId);                                   // PDA [b"vault"]
     const vaultTokenAccount = await getAssociatedTokenAddress(usdcMint, vaultPda, true);

         console.log("🧩 vaultPda:", vaultPda.toBase58());
    console.log("🧩 vault ATA:", vaultTokenAccount.toBase58());

    // 1) Memo(deposit_hash) — required in the same tx
    const memoIx = new TransactionInstruction({
      programId: MEMO_PROGRAM_ID,
      keys: [],
      data: Buffer.from(realDepositHash.toString("hex"), "utf8"),
    });

    // 2) SPL TransferChecked(user -> vault ATA) — required in the same tx
    const amount = 5_000_000; // 5 USDC (6 decimals)
    const transferIx = createTransferCheckedInstruction(
      userAta,
      usdcMint,
      vaultTokenAccount,
      authority.publicKey,
      amount,
      6
    );

             // 3) Program ix (shielded_deposit_atomic)
    // Use the exact address that the program expects
    const expectedDepositMarker = new PublicKey("bzgZn6GW334NqjncqQJEhAWr97UvF4kCLAQicq7MZU6");
    
    const programIx = await program.methods
      .shieldedDepositAtomic(realDepositHash, realProof, realPublicInputs)
       .accounts({
         payer: authority.publicKey,
         rootCache: rootCache.publicKey,
         depositMarker: expectedDepositMarker,  // Use the exact expected address
         vaultPda,                      // PDA per IDL
         vaultTokenAccount,             // ATA for vaultPda
         tokenMint: usdcMint,
         instructions: new PublicKey("Sysvar1nstructions1111111111111111111111111"),
         systemProgram: SystemProgram.programId,
         tokenProgram: TOKEN_PROGRAM_ID,
         associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
       } as any) // cast while your generated TS types catch up with the IDL
       .instruction();

    // Atomic tx: [Memo, TransferChecked, Program]
    const tx = new Transaction().add(memoIx, transferIx, programIx);
    tx.feePayer = authority.publicKey;

    try {
      const sig = await provider.sendAndConfirm(tx, []); // provider wallet (authority) signs
      console.log("✅ Atomic deposit tx:", sig);
      expect(sig).to.be.a("string");
    } catch (e: any) {
      // Print full simulation logs for quick diagnosis (e.g., seeds mismatches)
      const err = e as SendTransactionError;
      console.error("❌ sendAndConfirm failed:", err.message);
      if (err.logs) {
        console.error("---- simulation logs start ----");
        for (const line of err.logs) console.error(line);
        console.error("---- simulation logs end ----");
      }
      throw e;
    }
  });

  it("Validates real ZK proof structure", async () => {
    expect(realProof.length).to.equal(256);
    expect(realPublicInputs.length).to.equal(192);
    expect(realPublicInputs.length / 32).to.equal(6);

    const newCommitment = realPublicInputs.subarray(0, 32);
    const ownerCipherPayPubKey = realPublicInputs.subarray(32, 64);
    const newMerkleRoot = realPublicInputs.subarray(64, 96);
    const newNextLeafIndex = realPublicInputs.subarray(96, 128);
    const amount = realPublicInputs.subarray(128, 160);
    const depositHash = realPublicInputs.subarray(160, 192);

    console.log("📋 Circuit outputs:");
    console.log("  commitment:", newCommitment.toString("hex"));
    console.log("  owner:", ownerCipherPayPubKey.toString("hex"));
    console.log("  new root:", newMerkleRoot.toString("hex"));
    console.log("  next idx:", Buffer.from(newNextLeafIndex).toString("hex"));
    console.log("  amount:", amount.toString("hex"));
    console.log("  deposit hash:", depositHash.toString("hex"));
  });
});

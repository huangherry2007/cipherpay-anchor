// tests/withdraw.ts
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import {
  PublicKey,
  SystemProgram,
  Keypair,
  Connection,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { assert } from "chai";
import fs from "fs";
import path from "path";
import {
  getAssociatedTokenAddressSync,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createMint,
  getAccount,
  getOrCreateAssociatedTokenAccount,
  mintTo,
} from "@solana/spl-token";
import dotenv from "dotenv";
dotenv.config();

// 👇 NEW: helper to rebuild base58 from limbs
import { limbsToRecipientOwnerBase58 } from "./recipientOwnerLimbs";

// ---------- IDL helpers (same pattern as deposit/transfer) ----------
type AnyIdl = Record<string, any>;
function loadIdl(): AnyIdl {
  const IDL_PATH = path.resolve(__dirname, "../target/idl/cipherpay_anchor.json");
  const raw = fs.readFileSync(IDL_PATH, "utf8");
  const idl = JSON.parse(raw);
  if (!idl || typeof idl !== "object" || !Array.isArray(idl.instructions)) {
    throw new Error(`IDL at ${IDL_PATH} is invalid (missing instructions[])`);
  }
  return idl;
}
function makeProgram(provider: AnchorProvider) {
  const idl = loadIdl() as any;
  const programIdStr: string | undefined = process.env.PROGRAM_ID || idl.address;
  if (!programIdStr) throw new Error("PROGRAM_ID not set and IDL.address missing.");
  if (idl.address !== programIdStr) idl.address = programIdStr;
  return new Program(idl as unknown as anchor.Idl, provider);
}

// ---------- Constants ----------
const RPC_URL =
  process.env.SOLANA_URL ||
  process.env.ANCHOR_PROVIDER_URL ||
  "http://127.0.0.1:8899";

const KEYPAIR_PATH =
  process.env.ANCHOR_WALLET ||
  `${process.env.HOME}/.config/solana/id.json`;

// NEW: variant selector (defaults to 'withdraw')
const WITHDRAW_VARIANT = (process.env.WITHDRAW_VARIANT || "withdraw").trim();

// File paths depend on WITHDRAW_VARIANT
const PROOF_PATH = path.resolve(__dirname, `../proofs/${WITHDRAW_VARIANT}_proof.bin`);
const PUBSIG_PATH = path.resolve(__dirname, `../proofs/${WITHDRAW_VARIANT}_public_signals.bin`);

// ✅ UPDATED public signals layout (7 × 32):
// [0] nullifier,
// [1] merkleRoot,
// [2] recipientOwner_lo,
// [3] recipientOwner_hi,
// [4] recipientWalletPubKey,
// [5] amount,
// [6] tokenId
const PUBSIG_COUNT = 7;
const FIELD_BYTES = 32;
const PROOF_BYTES = 256;
const PUBSIG_BYTES = PUBSIG_COUNT * FIELD_BYTES;

// ---------- Small Utils ----------
function loadBin(file: string): Buffer {
  if (!fs.existsSync(file)) throw new Error(`Missing file: ${file}`);
  return fs.readFileSync(file);
}
function split32(buf: Buffer, idx: number): Buffer {
  const start = idx * FIELD_BYTES;
  return buf.subarray(start, start + FIELD_BYTES);
}
function toBigIntLE(buf: Buffer): bigint {
  return buf.reduceRight(
    (acc, byte) => (acc << BigInt(8)) + BigInt(byte),
    BigInt(0)
  );
}
function bigIntToNumberSafe(x: bigint): number {
  if (x > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`BigInt too large for JS number: ${x.toString()}`);
  }
  return Number(x);
}
async function airdropIfNeeded(connection: Connection, pubkey: PublicKey, minLamports = 2 * LAMPORTS_PER_SOL) {
  const bal = await connection.getBalance(pubkey, "confirmed");
  if (bal < minLamports) {
    const sig = await connection.requestAirdrop(pubkey, 3 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig, "confirmed");
  }
}

// ---------- Load proof & signals ----------
function loadWithdrawProofAndSignals() {
  const proof = loadBin(PROOF_PATH);
  const publicSignals = loadBin(PUBSIG_PATH);

  if (proof.length !== PROOF_BYTES) {
    throw new Error(`Expected ${PROOF_BYTES}-byte Groth16 proof, got ${proof.length}`);
  }
  if (publicSignals.length !== PUBSIG_BYTES) {
    throw new Error(`Expected ${PUBSIG_BYTES} bytes for public signals, got ${publicSignals.length}`);
  }

  const s0_nullifier = split32(publicSignals, 0);
  const s1_merkleRoot = split32(publicSignals, 1);
  const s2_recipientOwner_lo = split32(publicSignals, 2);      // NEW
  const s3_recipientOwner_hi = split32(publicSignals, 3);      // NEW
  const s4_recipientWalletPubKey = split32(publicSignals, 4);
  const s5_amount = split32(publicSignals, 5);                 // shifted (+1)
  const s6_tokenId = split32(publicSignals, 6);                // shifted (+1)

  return {
    proof,
    publicSignals,
    fields: {
      nullifier: s0_nullifier,
      merkleRoot: s1_merkleRoot,
      recipientOwner_lo: s2_recipientOwner_lo,                 // NEW
      recipientOwner_hi: s3_recipientOwner_hi,                 // NEW
      recipientWalletPubKey: s4_recipientWalletPubKey,
      amount: s5_amount,
      tokenId: s6_tokenId,
    },
  };
}

// ---------- Test Suite ----------
describe("Shielded Withdraw - Real Program Integration", () => {
  // Provider & program
  const payer = Keypair.fromSecretKey(
    Buffer.from(JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf8")))
  );
  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = new anchor.Wallet(payer);
  const provider = new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
  anchor.setProvider(provider);

  const program = makeProgram(provider);

  // Shared state
  let tokenMint: PublicKey;
  let vaultPda: PublicKey;
  let vaultTokenAccount: PublicKey;
  let recipientOwner: PublicKey;
  let recipientTokenAccount: PublicKey;
  let nullifierRecord: PublicKey;
  let rootCachePda: PublicKey;

  let withdrawAmount = 0;

  beforeAll(async () => {
    console.log("📁 using proof files:", { PROOF_PATH, PUBSIG_PATH });
    await airdropIfNeeded(connection, provider.wallet.publicKey);

    // 1) Fresh test mint (0 decimals)
    tokenMint = await createMint(
      provider.connection,
      (provider.wallet as any).payer,
      provider.wallet.publicKey,
      null,
      0
    );

    // 2) Vault PDA (seed "vault" per IDL)
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    // 3) Vault ATA for the mint (owner = vaultPda)
    vaultTokenAccount = getAssociatedTokenAddressSync(
      tokenMint,
      vaultPda,
      true,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (provider.wallet as any).payer,
      tokenMint,
      vaultPda,
      true
    );

    // 4) Recipient = test wallet (or ENV override to match proof)
    const envRecipient = process.env.RECIPIENT_OWNER_SOL_B58;
    console.log("envRecipient", envRecipient);
    recipientOwner = envRecipient
      ? new PublicKey(envRecipient)
      : Keypair.generate().publicKey;
    
    const recipientAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (provider.wallet as any).payer,
      tokenMint,
      recipientOwner
    );
    recipientTokenAccount = recipientAta.address;

    // 5) Load signals: derive nullifier PDA + amount
    const { fields } = loadWithdrawProofAndSignals();

    [nullifierRecord] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), Buffer.from(fields.nullifier)],
      program.programId
    );

    withdrawAmount = bigIntToNumberSafe(toBigIntLE(fields.amount));

    // 6) Initialize root cache (seed "root_cache" per IDL)
    [rootCachePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("root_cache")],
      program.programId
    );

    if ((program.methods as any).initializeRootCache) {
      try {
        await (program.methods as any)
          .initializeRootCache()
          .accounts({
            rootCache: rootCachePda,
            authority: provider.wallet.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
      } catch (_) {
        // likely already initialized — ignore
      }
    }

    // 7) Seed vault with enough tokens
    const preVaultAcc = await getAccount(provider.connection, vaultTokenAccount).catch(() => null);
    const needsMint = preVaultAcc === null || Number(preVaultAcc.amount) < withdrawAmount;
    if (withdrawAmount > 0 && needsMint) {
      await mintTo(
        provider.connection,
        (provider.wallet as any).payer,
        tokenMint,
        vaultTokenAccount,
        provider.wallet.publicKey,
        withdrawAmount
      );
    }
  });

  it("Validates withdraw circuit outputs & sizes", async () => {
    const { proof, publicSignals } = loadWithdrawProofAndSignals();
    assert.equal(proof.length, PROOF_BYTES, "Groth16 proof should be 256 bytes");
    assert.equal(publicSignals.length, PUBSIG_BYTES, "Withdraw public signals should be 224 bytes (7 × 32)");
  });

  it("Executes shielded withdraw with ZK proof verification", async () => {
    const { proof, publicSignals, fields } = loadWithdrawProofAndSignals();

    // ✅ Rebuild base58 from limbs in public signals (LE → BigInt)
    const lo = toBigIntLE(fields.recipientOwner_lo);
    const hi = toBigIntLE(fields.recipientOwner_hi);
    const recipientOwnerFromProofB58 = limbsToRecipientOwnerBase58(lo, hi);
    const recipientOwnerFromProof = new PublicKey(recipientOwnerFromProofB58);

    // Sanity: recipientOwner (proof) must equal our recipientOwner account
    assert.strictEqual(
      recipientOwnerFromProof.toBase58(),
      recipientOwner.toBase58(),
      "recipientOwner (from limbs) in public signals must equal recipientOwner account"
    );

    // Ensure recipient ATA exists
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (provider.wallet as any).payer,
      tokenMint,
      recipientOwner
    );

    const preRecipient = await getAccount(provider.connection, recipientTokenAccount);
    const preAmount = Number(preRecipient.amount);

    let sig: string;
    try {
      sig = await (program.methods as any)
        .shieldedWithdraw(Buffer.from(fields.nullifier), proof, publicSignals)
        .accounts({
          payer: provider.wallet.publicKey,
          rootCache: rootCachePda,
          nullifierRecord,
          vaultPda,
          vaultTokenAccount,
          recipientOwner,
          recipientTokenAccount,
          tokenMint,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .rpc();
    } catch (e: any) {
      if (e?.logs) console.error("❌ Program logs:", e.logs);
      if (typeof e?.getLogs === "function") {
        try {
          const moreLogs = await e.getLogs(connection);
          console.error("❌ More logs:", moreLogs);
        } catch {}
      }
      throw e;
    }

    console.log("✅ withdraw sent:", sig);

    const postRecipient = await getAccount(provider.connection, recipientTokenAccount);
    const postAmount = Number(postRecipient.amount);

    // This will only pass if the root in publicSignals exists in root_cache.
    assert.equal(
      postAmount,
      preAmount + withdrawAmount,
      `Recipient ATA should increase by ${withdrawAmount} (ensure root_cache contains the merkleRoot used by the proof).`
    );
  });
});

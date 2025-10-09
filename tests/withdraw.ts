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

// File paths now depend on WITHDRAW_VARIANT (logic unchanged)
const PROOF_PATH = path.resolve(__dirname, `../proofs/${WITHDRAW_VARIANT}_proof.bin`);
const PUBSIG_PATH = path.resolve(__dirname, `../proofs/${WITHDRAW_VARIANT}_public_signals.bin`);

// Public signals layout (5 × 32): [nullifier, merkleRoot, recipientWalletPubKey, amount, tokenId]
const PUBSIG_COUNT = 5;
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
  const s2_recipientWalletPubKey = split32(publicSignals, 2);
  const s3_amount = split32(publicSignals, 3);
  const s4_tokenId = split32(publicSignals, 4);

  return {
    proof,
    publicSignals,
    fields: {
      nullifier: s0_nullifier,
      merkleRoot: s1_merkleRoot,
      recipientWalletPubKey: s2_recipientWalletPubKey,
      amount: s3_amount,
      tokenId: s4_tokenId,
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

    // 4) Recipient = test wallet
    recipientOwner = provider.wallet.publicKey;
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

    // initialize_root_cache(authority = payer)
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
    assert.equal(publicSignals.length, PUBSIG_BYTES, "Withdraw public signals should be 160 bytes (5 × 32)");
  });

  it("Executes shielded withdraw with ZK proof verification", async () => {
    const { proof, publicSignals, fields } = loadWithdrawProofAndSignals();

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

// tests/deposit.ts
import * as fs from "fs";
import * as path from "path";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, web3 } from "@coral-xyz/anchor";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createMint,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
  mintTo,
  createTransferCheckedInstruction,
} from "@solana/spl-token";
import { CipherpayAnchor } from "../target/types/cipherpay_anchor";
import { createMemoInstruction } from "@solana/spl-memo";

// ───────────────────────── helpers ─────────────────────────
function readBin(p: string): Buffer {
  return fs.readFileSync(path.resolve(p));
}
function toHexLE(b: Buffer): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function slice32(buf: Buffer, i: number): Buffer {
  const off = i * 32;
  return buf.subarray(off, off + 32);
}
async function ensureAirdrop(
  connection: web3.Connection,
  pubkey: web3.PublicKey,
  wantLamports = 10 * web3.LAMPORTS_PER_SOL
) {
  const before = await connection.getBalance(pubkey);
  if (before >= wantLamports) return before;
  const sig = await connection.requestAirdrop(pubkey, wantLamports - before);
  await connection.confirmTransaction(sig, "confirmed");
  return await connection.getBalance(pubkey);
}
async function ensureAtaIx(
  connection: web3.Connection,
  ata: web3.PublicKey,
  payer: web3.PublicKey,
  owner: web3.PublicKey,
  mint: web3.PublicKey
): Promise<web3.TransactionInstruction | null> {
  const info = await connection.getAccountInfo(ata);
  if (info) return null;
  return createAssociatedTokenAccountInstruction(
    payer,
    ata,
    owner,
    mint,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
  );
}

// ───────────────────────── config ─────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);

// proofs dir (override with env if desired)
const buildDir = process.env.DEPOSIT_BUILD_DIR
  ? path.resolve(process.env.DEPOSIT_BUILD_DIR)
  : path.resolve("proofs");
const proofPath = path.join(buildDir, "deposit_proof.bin");
const publicsPath = path.join(buildDir, "deposit_public_signals.bin");

// circuit ordering: [newCommitment, owner, newRoot, nextIdx, amount, depositHash]
const DEPOSIT_IDX = { AMOUNT: 4, DEPOSIT_HASH: 5 };

// PDA seeds (must match on-chain constants)
const VAULT_SEED = Buffer.from("vault");
const DEPOSIT_SEED = Buffer.from("deposit");

// mint config — we use 0 decimals to keep amounts simple
const MINT_DECIMALS = 0 as const;

// ───────────────────────── tests ─────────────────────────
describe("shielded_deposit_atomic (end-to-end)", () => {
  const connection = new web3.Connection(RPC_URL, "confirmed");
  const wallet = new anchor.Wallet(
    web3.Keypair.fromSecretKey(
      Buffer.from(
        JSON.parse(
          fs.readFileSync(
            process.env.HOME + "/.config/solana/id.json",
            "utf8"
          )
        )
      )
    )
  );
  const provider = new AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
  anchor.setProvider(provider);

  const program = anchor.workspace
    .CipherpayAnchor as Program<CipherpayAnchor>;
  const programId = program.programId;
  const payer = wallet.publicKey;

  // will be populated in tests
  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;
  let depositHash: Buffer; // 32B (LE)
  let amountU64: number;   // parsed to JS number

  // token + PDAs
  let tokenMint!: web3.PublicKey;
  let payerAta!: web3.PublicKey;
  let vaultPda!: web3.PublicKey;
  let vaultAta!: web3.PublicKey;

  // accounts
  const rootCache = web3.Keypair.generate(); // signer init account

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);

    // load proof + publics
    proofBytes = readBin(proofPath);
    publicInputsBytes = readBin(publicsPath);
    expect(proofBytes.length).toBe(256);
    expect(publicInputsBytes.length).toBe(6 * 32);

    // extract fields
    depositHash = slice32(publicInputsBytes, DEPOSIT_IDX.DEPOSIT_HASH);
    console.log("🔑 depositHash (LE):", toHexLE(depositHash));

    const amountFe = slice32(publicInputsBytes, DEPOSIT_IDX.AMOUNT);
    // little-endian u64 in first 8 bytes → JS number (assumes it fits)
    amountU64 =
      amountFe[0] |
      (amountFe[1] << 8) |
      (amountFe[2] << 16) |
      (amountFe[3] << 24) |
      (amountFe[4] * 2 ** 32) +
      (amountFe[5] * 2 ** 40) +
      (amountFe[6] * 2 ** 48) +
      (amountFe[7] * 2 ** 56);
    console.log(`💵 amount (u64) = ${amountU64}`);

    // init root cache once (per test run) — DO NOT pass systemProgram (auto-resolved)
    try {
      await program.methods
        .initializeRootCache()
        .accounts({
          rootCache: rootCache.publicKey,
          authority: payer,
        })
        .signers([rootCache])
        .rpc();
      console.log("✅ initialize_root_cache ok");
    } catch (e: any) {
      if (!/already in use/i.test(String(e?.message ?? e))) throw e;
      console.log("ℹ️ root_cache already exists");
    }

    // create a fresh mint with 0 decimals
    tokenMint = await createMint(
      connection,
      wallet.payer, // fee payer
      payer,        // mint authority
      null,         // freeze authority
      MINT_DECIMALS
    );
    console.log("✅ token mint:", tokenMint.toBase58());

    // derive PDAs + ATAs
    [vaultPda] = web3.PublicKey.findProgramAddressSync([VAULT_SEED], programId);
    payerAta = getAssociatedTokenAddressSync(
      tokenMint,
      payer,
      false,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    vaultAta = getAssociatedTokenAddressSync(
      tokenMint,
      vaultPda,
      true,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    // ensure ATAs exist (payer + vault)
    const createPayerAtaIx = await ensureAtaIx(
      connection,
      payerAta,
      payer,
      payer,
      tokenMint
    );
    const createVaultAtaIx = await ensureAtaIx(
      connection,
      vaultAta,
      payer,
      vaultPda,
      tokenMint
    );
    const ixs: web3.TransactionInstruction[] = [];
    if (createPayerAtaIx) ixs.push(createPayerAtaIx);
    if (createVaultAtaIx) ixs.push(createVaultAtaIx);
    if (ixs.length) {
      const tx = new web3.Transaction().add(...ixs);
      await provider.sendAndConfirm(tx);
      console.log("✅ created missing ATAs");
    }

    // mint funds to payer to cover transfer
    await mintTo(
      connection,
      wallet.payer,
      tokenMint,
      payerAta,
      payer, // authority
      amountU64
    );
    console.log("✅ minted amount to payer ATA");
  });

  it("verifies on-chain via shielded_deposit_atomic", async () => {
    // the PDA for the per-deposit idempotent marker
    const [depositMarkerPda] = web3.PublicKey.findProgramAddressSync(
      [DEPOSIT_SEED, depositHash],
      programId
    );

    // pre-ixs: CU, transferChecked, memo(32B raw)
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({
      units: CU_LIMIT,
    });
    const feeIx = web3.ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: 0,
    });

    const transferIx = createTransferCheckedInstruction(
      payerAta,
      tokenMint,
      vaultAta,
      payer,
      amountU64,
      MINT_DECIMALS,
      [],
      TOKEN_PROGRAM_ID
    );

    // Encode 32B depositHash as UTF-8 text for the Memo program
    const memoHex = "deposit:" + Buffer.from(depositHash).toString("hex");
    const memoIx = createMemoInstruction(memoHex, [payer]); // signer optional but useful

    try {
      const txSig = await program.methods
        .shieldedDepositAtomic(depositHash, proofBytes, publicInputsBytes)
        // Use accountsPartial to be robust if the generated TS type is stale.
        .accountsPartial({
          payer,
          rootCache: rootCache.publicKey,
          depositMarker: depositMarkerPda,     // required by runtime IDL
          vaultPda,
          vaultTokenAccount: vaultAta,
          tokenMint,
          instructions: web3.SYSVAR_INSTRUCTIONS_PUBKEY,
          // systemProgram omitted on purpose (auto-resolved)
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .preInstructions([cuIx, feeIx, transferIx, memoIx])
        .rpc();

      console.log("✅ shielded_deposit_atomic tx:", txSig);
    } catch (e: any) {
      console.error("❌ sendAndConfirm failed:", e?.message ?? e);
      if (e?.logs) {
        console.error("---- logs start ----");
        for (const line of e.logs) console.error(line);
        console.error("---- logs end ----");
      }
      throw e;
    }
  });

  it("sanity: proof structure", () => {
    const a = proofBytes.subarray(0, 64);
    const b = proofBytes.subarray(64, 192);
    const c = proofBytes.subarray(192, 256);
    expect(a.length).toBe(64);
    expect(b.length).toBe(128);
    expect(c.length).toBe(64);
  });
});

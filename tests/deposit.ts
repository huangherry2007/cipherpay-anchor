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
import { createMemoInstruction } from "@solana/spl-memo";

// ───────────────────────── IDL loader (with signer sanitizer) ─────────────────────────
type AnyIdl = Record<string, any>;

function loadIdl(): AnyIdl {
  const IDL_PATH = path.resolve(__dirname, "../target/idl/cipherpay_anchor.json");
  const raw = fs.readFileSync(IDL_PATH, "utf8");
  const idl = JSON.parse(raw);
  if (!idl || typeof idl !== "object" || !Array.isArray(idl.instructions)) {
    throw new Error(`IDL at ${IDL_PATH} is invalid (missing instructions[])`);
  }

  // Ensure only `payer` is a signer for shielded_deposit_atomic
  const depIx = idl.instructions.find((ix: any) => ix.name === "shielded_deposit_atomic");
  const forceOnlyPayerSigns = (arr: any[]) => {
    if (!Array.isArray(arr)) return;
    for (const acc of arr) {
      if (!acc) continue;
      acc.isSigner = acc.name === "payer";
      if (Array.isArray(acc.accounts)) forceOnlyPayerSigns(acc.accounts);
    }
  };
  if (depIx) forceOnlyPayerSigns(depIx.accounts);

  return idl;
}

function makeProgram(provider: AnchorProvider) {
  const idl = loadIdl() as any;
  const programIdStr: string | undefined = process.env.PROGRAM_ID || idl.address;
  if (!programIdStr) {
    throw new Error(
      "PROGRAM_ID not set and IDL.address missing. Set PROGRAM_ID or add `address` to the IDL."
    );
  }
  if (idl.address !== programIdStr) idl.address = programIdStr;
  return new Program(idl as unknown as anchor.Idl, provider); // Program reads address from idl.address
}

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
    payer, ata, owner, mint, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
  );
}

// ───────────────────────── config ─────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);

// PDA seeds (must match on-chain constants)
const TREE_SEED = Buffer.from("tree");
const ROOT_CACHE_SEED = Buffer.from("root_cache");
const VAULT_SEED = Buffer.from("vault");
const DEPOSIT_SEED = Buffer.from("deposit");

// proofs dir (override with env if desired)
const buildDir = process.env.DEPOSIT_BUILD_DIR
  ? path.resolve(process.env.DEPOSIT_BUILD_DIR)
  : path.resolve("proofs");
const proofPath = path.join(buildDir, "deposit_proof.bin");
const publicsPath = path.join(buildDir, "deposit_public_signals.bin");

// public signal order used by your circuit export:
const DEPOSIT_IDX = {
  NEW_COMMITMENT: 0,
  OWNER: 1,
  NEW_ROOT: 2,
  NEW_NEXT_IDX: 3,
  AMOUNT: 4,
  DEPOSIT_HASH: 5,
  OLD_ROOT: 6,
} as const;

// mint config — 0 decimals to keep amounts simple
const MINT_DECIMALS = 0 as const;

// Memo program id (for pretty printing)
const MEMO_PROGRAM_ID = new web3.PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
);

// ───────────────────────── tests ─────────────────────────
describe("shielded_deposit_atomic (end-to-end) — assumes PDAs pre-initialized", () => {
  const connection = new web3.Connection(RPC_URL, "confirmed");

  // concrete wallet so provider.wallet.payer exists
  const wallet = new anchor.Wallet(
    web3.Keypair.fromSecretKey(
      Buffer.from(
        JSON.parse(
          fs.readFileSync(process.env.HOME + "/.config/solana/id.json", "utf8")
        )
      )
    )
  );
  const provider = new AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
  anchor.setProvider(provider);

  const program = makeProgram(provider);
  const programId = program.programId;
  const payer = wallet.publicKey;

  console.log("🧭 programId:", programId.toBase58());
  console.log("👛 payer:", payer.toBase58());

  // populated in tests
  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;
  let depositHash: Buffer;
  let amountU64: number;

  // token + PDAs
  let tokenMint!: web3.PublicKey;
  let payerAta!: web3.PublicKey;
  let vaultPda!: web3.PublicKey;
  let vaultAta!: web3.PublicKey;

  // global tree & root cache PDAs (pre-initialized by migration)
  let treePda!: web3.PublicKey;
  let rootCachePda!: web3.PublicKey;

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);

    // load proof + publics
    proofBytes = readBin(proofPath);
    publicInputsBytes = readBin(publicsPath);
    expect(proofBytes.length).toBe(256);
    expect(publicInputsBytes.length).toBe(7 * 32);

    // extract fields
    depositHash = slice32(publicInputsBytes, DEPOSIT_IDX.DEPOSIT_HASH);
    console.log("🔑 depositHash (LE, hex):", toHexLE(depositHash));

    const amountFe = slice32(publicInputsBytes, DEPOSIT_IDX.AMOUNT);
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

    // ---- Derive PDAs (must already exist, created by migrations/01_init.ts)
    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);
    [rootCachePda] = web3.PublicKey.findProgramAddressSync(
      [ROOT_CACHE_SEED],
      programId
    );
    console.log("🌲 tree PDA:", treePda.toBase58());
    console.log("🗃️ rootCache PDA:", rootCachePda.toBase58());

    // Sanity checks: both accounts must exist
    const treeInfo = await connection.getAccountInfo(treePda);
    const rcInfo = await connection.getAccountInfo(rootCachePda);
    if (!treeInfo) throw new Error("TreeState PDA missing. Run `anchor run init` first.");
    if (!rcInfo) throw new Error("RootCache PDA missing. Run `anchor run init` first.");

    // ---- SPL Mint & ATAs ----
    tokenMint = await createMint(
      connection,
      wallet.payer, // fee payer
      payer, // mint authority
      null, // freeze authority
      MINT_DECIMALS
    );
    console.log("✅ token mint:", tokenMint.toBase58());

    [vaultPda] = web3.PublicKey.findProgramAddressSync([VAULT_SEED], programId);
    console.log("🏦 vaultPda:", vaultPda.toBase58());

    payerAta = getAssociatedTokenAddressSync(
      tokenMint, payer, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
    );
    vaultAta = getAssociatedTokenAddressSync(
      tokenMint, vaultPda, true, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const createPayerAtaIx = await ensureAtaIx(connection, payerAta, payer, payer, tokenMint);
    const createVaultAtaIx = await ensureAtaIx(connection, vaultAta, payer, vaultPda, tokenMint);
    const ixs: web3.TransactionInstruction[] = [];
    if (createPayerAtaIx) ixs.push(createPayerAtaIx);
    if (createVaultAtaIx) ixs.push(createVaultAtaIx);
    if (ixs.length) {
      const tx = new web3.Transaction().add(...ixs);
      await provider.sendAndConfirm(tx);
      console.log("✅ created missing ATAs");
    }

    await mintTo(connection, wallet.payer, tokenMint, payerAta, payer, amountU64);
    console.log("✅ minted amount to payer ATA");
  });

  it("verifies on-chain via shielded_deposit_atomic (PDA root_cache, only payer signs)", async () => {
    const [depositMarkerPda] = web3.PublicKey.findProgramAddressSync(
      [DEPOSIT_SEED, depositHash],
      programId
    );
    console.log("🏷️ depositMarkerPda:", depositMarkerPda.toBase58());

    // pre-ixs: budget, memo, token transfer
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });

    const transferIx = createTransferCheckedInstruction(
      payerAta, tokenMint, vaultAta, payer, amountU64, MINT_DECIMALS, [], TOKEN_PROGRAM_ID
    );

    const memoIx = createMemoInstruction("deposit:" + toHexLE(depositHash), [payer]);

    // Build program ix
    const anchorIx = await program.methods
      .shieldedDepositAtomic(depositHash, proofBytes, publicInputsBytes)
      .accountsPartial({
        payer,
        tree: treePda,
        rootCache: rootCachePda, // ✅ PDA (pre-initialized)
        depositMarker: depositMarkerPda,
        vaultPda,
        vaultTokenAccount: vaultAta,
        tokenMint,
        instructions: web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .instruction();

    // sanity — should be only `payer`
    const signers = anchorIx.keys.filter(k => k.isSigner).map(k => k.pubkey.toBase58());
    console.log("🧪 required signers (program ix):", signers);
    if (!(signers.length === 1 && signers[0] === payer.toBase58())) {
      throw new Error("IDL requires unexpected signers: " + JSON.stringify(signers));
    }

    // Final tx: SPL transfer & memo immediately before our program ix
    const tx = new web3.Transaction().add(cuIx, memoIx, transferIx, anchorIx);

    // Pretty-print the built transaction
    console.log("🔎 full tx instructions:");
    tx.instructions.forEach((ix, i) => {
      const pid = ix.programId.toBase58();
      const tag =
        pid === TOKEN_PROGRAM_ID.toBase58()
          ? "spl-token"
          : pid === MEMO_PROGRAM_ID.toBase58()
          ? "memo"
          : pid === programId.toBase58()
          ? "cipherpay-anchor"
          : pid === web3.SystemProgram.programId.toBase58()
          ? "system"
          : "other";
      console.log(`  [${i}] program=${pid} (${tag})`);
      if (pid === TOKEN_PROGRAM_ID.toBase58()) {
        const k = ix.keys.map((m) => m.pubkey.toBase58());
        console.log(
          `      token.keys: src=${k[0]} mint=${k[1]} dst=${k[2]} auth=${k[3]}`
        );
      }
    });

    try {
      const sig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
      console.log("✅ shielded_deposit_atomic tx:", sig);

      const res = await connection.getTransaction(sig, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      console.log("---- on-chain logs ----");
      res?.meta?.logMessages?.forEach((l) => console.log(l));
      console.log("---- end logs ----");
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      console.warn("⚠️ send failed:", msg);
      if (e?.logs) {
        console.warn("---- logs ----");
        for (const line of e.logs) console.warn(line);
        console.warn("---- end logs ----");
      }
      throw e;
    }
  });

  it("sanity: proof structure", () => {
    const a = publicInputsBytes.subarray(0, 32); // small extra check on inputs
    expect(a.length).toBe(32);
    const pA = proofBytes.subarray(0, 64);
    const pB = proofBytes.subarray(64, 192);
    const pC = proofBytes.subarray(192, 256);
    expect(pA.length).toBe(64);
    expect(pB.length).toBe(128);
    expect(pC.length).toBe(64);
  });
});

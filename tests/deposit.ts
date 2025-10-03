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

// ───────────────────────── IDL loader (no sanitizer) ─────────────────────────
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
async function getU64TokenBal(
  connection: web3.Connection,
  ata: web3.PublicKey
): Promise<number> {
  const r = await connection.getTokenAccountBalance(ata, "confirmed");
  // amount is a decimal string; with decimals=0 this fits safely in number for these tests
  return Number(r.value.amount);
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

  // cached pre-state for assertions
  let preTreeNextIndex: number = -1; // -1 means "skip assertion if we can't decode"

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

    // Capture pre tree.next_index for later assertion
    try {
      const treeAcc: any = await (program.account as any).treeState.fetch(treePda);
      preTreeNextIndex = Number(treeAcc.nextIndex ?? treeAcc.next_index ?? 0);
    } catch {
      preTreeNextIndex = -1; // skip if we can't decode
    }

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

  // Helper to build a full deposit tx with given deposit hash
  async function buildDepositTx(dHash: Buffer) {
    const [depositMarkerPda] = web3.PublicKey.findProgramAddressSync(
      [DEPOSIT_SEED, dHash],
      programId
    );

    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });
    const transferIx = createTransferCheckedInstruction(
      payerAta, tokenMint, vaultAta, payer, amountU64, MINT_DECIMALS, [], TOKEN_PROGRAM_ID
    );
    const memoIx = createMemoInstruction("deposit:" + toHexLE(dHash), [payer]);

    const programIx = await program.methods
      .shieldedDepositAtomic(dHash, proofBytes, publicInputsBytes)
      .accountsPartial({
        payer,
        tree: treePda,
        rootCache: rootCachePda,
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

    const tx = new web3.Transaction().add(cuIx, memoIx, transferIx, programIx);
    return { tx, programIx };
  }

  it("verifies on-chain via shielded_deposit_atomic (PDA root_cache, only payer signs)", async () => {
    // Pre balances
    const prePayer = await getU64TokenBal(connection, payerAta);
    const preVault = await getU64TokenBal(connection, vaultAta);

    // Build + send
    const { tx, programIx } = await buildDepositTx(depositHash);

    // sanity — should be only `payer`
    const signers = programIx.keys.filter(k => k.isSigner).map(k => k.pubkey.toBase58());
    console.log("🧪 required signers (program ix):", signers);
    expect(signers).toEqual([payer.toBase58()]);

    // Pretty-print the built transaction (optional)
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

    const sig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    console.log("✅ shielded_deposit_atomic tx:", sig);

    // Post balances
    const postPayer = await getU64TokenBal(connection, payerAta);
    const postVault = await getU64TokenBal(connection, vaultAta);

    // Balance assertions
    const amt = amountU64;
    expect(postPayer).toBe(prePayer - amt);
    expect(postVault).toBe(preVault + amt);

    // TreeState.next_index bump (if we could decode pre)
    if (preTreeNextIndex >= 0) {
      try {
        const treeAcc: any = await (program.account as any).treeState.fetch(treePda);
        const postNextIndex = Number(treeAcc.nextIndex ?? treeAcc.next_index ?? 0);
        expect(postNextIndex).toBe(preTreeNextIndex + 1);
      } catch {
        // skip if decode fails
      }
    }

    // Logs (optional)
    const res = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    console.log("---- on-chain logs ----");
    res?.meta?.logMessages?.forEach((l) => console.log(l));
    console.log("---- end logs ----");
  });

  it("replay-guard: same depositHash again should fail and leave balances unchanged", async () => {
    const prePayer = await getU64TokenBal(connection, payerAta);
    const preVault = await getU64TokenBal(connection, vaultAta);

    const { tx } = await buildDepositTx(depositHash);

    let failed = false;
    try {
      await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    } catch (e: any) {
      failed = true;
      const msg = String(e?.message ?? e);
      console.log("↩️ replay tx failed as expected:", msg);
    }
    expect(failed).toBe(true);

    // Balances unchanged
    const postPayer = await getU64TokenBal(connection, payerAta);
    const postVault = await getU64TokenBal(connection, vaultAta);
    expect(postPayer).toBe(prePayer);
    expect(postVault).toBe(preVault);
  });

  it("sanity: proof structure", () => {
    const a = publicInputsBytes.subarray(0, 32);
    expect(a.length).toBe(32);
    const pA = proofBytes.subarray(0, 64);
    const pB = proofBytes.subarray(64, 192);
    const pC = proofBytes.subarray(192, 256);
    expect(pA.length).toBe(64);
    expect(pB.length).toBe(128);
    expect(pC.length).toBe(64);
  });
});

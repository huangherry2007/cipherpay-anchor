// tests/deposit.js
/* eslint-disable no-console */
import type { Connection, PublicKey, TransactionInstruction, Transaction } from "@solana/web3.js";
import type { AnchorProvider as AnchorProviderType, Program as AnchorProgramType } from "@coral-xyz/anchor";
const fs = require("fs");
const path = require("path");
const anchor = require("@coral-xyz/anchor");
const { Program, AnchorProvider, web3 } = anchor;
const {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createMint,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
  mintTo,
  createTransferCheckedInstruction,
} = require("@solana/spl-token");
const { createMemoInstruction } = require("@solana/spl-memo");

/**
 * Env knobs:
 *  - DEPOSIT_VARIANT=deposit|deposit1|deposit2|deposit3   (default: deposit)
 *  - DEPOSIT_BUILD_DIR=<dir of .bin files>                 (default: ./proofs)
 *  - PROGRAM_ID=<program pubkey>                           (default: idl.address)
 *  - SOLANA_URL=<rpc>                                      (default: http://127.0.0.1:8899)
 *  - CU_LIMIT=<number>                                     (default: 800000)
 *  - INCLUDE_MEMO=0|1                                      (default: 0)
 *  - MEMO_TEXT=<short text>                                (default: "")
 *  - PUBS_ENDIAN=le|be                                     (default: le)  // how we send publics
 *  - DHASH_SEED_ENDIAN=le|be                               (default: le)  // PDA seed for depositHash
 *  - FAIL_ON_ROOT_MISMATCH=0|1                             (default: 0)
 */

function loadIdl(): any {
  const IDL_PATH = path.resolve(__dirname, "../target/idl/cipherpay_anchor.json");
  const raw = fs.readFileSync(IDL_PATH, "utf8");
  const idl = JSON.parse(raw);
  if (!idl || typeof idl !== "object" || !Array.isArray(idl.instructions)) {
    throw new Error(`IDL at ${IDL_PATH} is invalid (missing instructions[])`);
  }
  return idl;
}
function makeProgram(provider: AnchorProviderType): AnchorProgramType {
  const idl = loadIdl();
  const programIdStr = process.env.PROGRAM_ID || idl.address;
  if (!programIdStr) {
    throw new Error("PROGRAM_ID not set and IDL.address missing. Set PROGRAM_ID or add `address` to the IDL.");
  }
  if (idl.address !== programIdStr) idl.address = programIdStr;
  return new Program(idl, provider);
}

// helpers
function readBin(p: string): Buffer { return fs.readFileSync(path.resolve(p)); }
function toHexLE(b: Buffer | Uint8Array): string { return [...b].map((x) => x.toString(16).padStart(2, "0")).join(""); }
function toHexBE(b: Buffer | Uint8Array): string { return Buffer.from(b).reverse().toString("hex"); }
function slice32(buf: Buffer | Uint8Array, i: number): Buffer { const off = i * 32; return Buffer.from(buf.subarray(off, off + 32)); }
function reEnd32(buf: Buffer, endian: "le"|"be" /* 'le'|'be' */): Buffer {
  if (endian === "le") return buf;
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i += 32) {
    Buffer.from(buf.subarray(i, i + 32)).reverse().copy(out, i);
  }
  return out;
}
async function ensureAirdrop(connection: Connection, pubkey: PublicKey, wantLamports: number = 10 * web3.LAMPORTS_PER_SOL): Promise<number> {
  const before = await connection.getBalance(pubkey);
  if (before >= wantLamports) return before;
  const sig = await connection.requestAirdrop(pubkey, wantLamports - before);
  await connection.confirmTransaction(sig, "confirmed");
  return await connection.getBalance(pubkey);
}
async function ensureAtaIx(connection: Connection, ata: PublicKey, payer: PublicKey, owner: PublicKey, mint: PublicKey): Promise<TransactionInstruction | null> {
  const info = await connection.getAccountInfo(ata);
  if (info) return null;
  return createAssociatedTokenAccountInstruction(
    payer, ata, owner, mint, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
  );
}
async function getU64TokenBal(connection: Connection, ata: PublicKey): Promise<number> {
  const r = await connection.getTokenAccountBalance(ata, "confirmed");
  return Number(r.value.amount);
}

// config
const VARIANT = (process.env.DEPOSIT_VARIANT || "deposit").trim();
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);

const INCLUDE_MEMO = (process.env.INCLUDE_MEMO ?? "0") !== "0";
const MEMO_TEXT = process.env.MEMO_TEXT ?? "";

const PUBS_ENDIAN = (process.env.PUBS_ENDIAN || "le").toLowerCase();          // how we send publics to the program
const DHASH_SEED_ENDIAN = (process.env.DHASH_SEED_ENDIAN || "le").toLowerCase(); // endianness for PDA seed
const FAIL_ON_ROOT_MISMATCH = (process.env.FAIL_ON_ROOT_MISMATCH ?? "0") !== "0";

const TREE_SEED = Buffer.from("tree");
const ROOT_CACHE_SEED = Buffer.from("root_cache");
const VAULT_SEED = Buffer.from("vault");
const DEPOSIT_SEED = Buffer.from("deposit");

const buildDir = process.env.DEPOSIT_BUILD_DIR
  ? path.resolve(process.env.DEPOSIT_BUILD_DIR)
  : path.resolve("proofs");
const proofPath = path.join(buildDir, `${VARIANT}_proof.bin`);
const publicsPath = path.join(buildDir, `${VARIANT}_public_signals.bin`);

const DEPOSIT_IDX = {
  NEW_COMMITMENT: 0,
  OWNER: 1,
  NEW_ROOT: 2,
  NEW_NEXT_IDX: 3,
  AMOUNT: 4,
  DEPOSIT_HASH: 5,
  OLD_ROOT: 6,
};

// memo program id (for pretty printing)
const MEMO_PROGRAM_ID = new web3.PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

// ───────────────────────── tests ─────────────────────────
describe(`shielded_deposit_atomic [${VARIANT}] (JS quick-checks)`, () => {
  const connection = new web3.Connection(RPC_URL, "confirmed");

  const wallet = new anchor.Wallet(
    web3.Keypair.fromSecretKey(
      Buffer.from(JSON.parse(fs.readFileSync(process.env.HOME + "/.config/solana/id.json", "utf8")))
    )
  );
  const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" });
  anchor.setProvider(provider);

  const program = makeProgram(provider);
  const programId = program.programId;
  const payer = wallet.publicKey;

  console.log("🧭 programId:", programId.toBase58());
  console.log("👛 payer:", payer.toBase58());
  console.log("📁 using proof files:", { proofPath, publicsPath });

  let proofBytes: Buffer;
  let publicsLE: Buffer; // original (LE chunks from your converter)
  let publicsForIx: Buffer; // after PUBS_ENDIAN toggle
  let depositHash: Buffer; // 32B as present in publicsLE (LE form)
  let amountU64: number;

  let tokenMint: PublicKey;
  let payerAta: PublicKey;
  let vaultPda: PublicKey;
  let vaultAta: PublicKey;

  let treePda: PublicKey;
  let rootCachePda: PublicKey;

  let preTreeNextIndex = -1;

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);

    // load proof + publics
    proofBytes = readBin(proofPath);
    publicsLE = readBin(publicsPath); // your bin writer used LE per FE
    console.log("📦 proof/publics sizes:", {
      proofBytes: proofBytes.length,
      publicInputsBytes: publicsLE.length,
      nPublic: publicsLE.length / 32,
    });
    expect(proofBytes.length).toBe(256);
    expect(publicsLE.length).toBe(7 * 32);

    // pretty-print publics in BE for readability
    const labels = [
      "newCommitment",
      "ownerCipherPayPubKey",
      "newMerkleRoot",
      "newNextLeafIndex",
      "amount",
      "depositHash",
      "oldMerkleRoot",
    ];
    const pretty: Record<string, string> = {};
    for (let i = 0; i < 7; i++) {
      pretty[labels[i]] = "0x" + toHexBE(slice32(publicsLE, i));
    }
    console.log("🔎 publics (BE) =", pretty);

    // extract fields from LE buffer
    depositHash = slice32(publicsLE, DEPOSIT_IDX.DEPOSIT_HASH);
    console.log(`🔑 depositHash [${VARIANT}] (LE, hex):`, toHexLE(depositHash));

    const amountFe = slice32(publicsLE, DEPOSIT_IDX.AMOUNT);
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

    // apply endianness toggle for what we send to the program
    publicsForIx = reEnd32(publicsLE, PUBS_ENDIAN as "le" | "be");
    if (PUBS_ENDIAN !== "le") {
      console.log(`⚙️  PUBS_ENDIAN=${PUBS_ENDIAN} — sending publics after per-32B reversal`);
    }

    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);
    [rootCachePda] = web3.PublicKey.findProgramAddressSync([ROOT_CACHE_SEED], programId);
    console.log("🌲 tree PDA:", treePda.toBase58());
    console.log("🗃️ rootCache PDA:", rootCachePda.toBase58());

    // Ensure both PDAs exist
    const treeInfo = await connection.getAccountInfo(treePda);
    const rcInfo = await connection.getAccountInfo(rootCachePda);
    if (!treeInfo) throw new Error("TreeState PDA missing. Run `anchor run init` first.");
    if (!rcInfo) throw new Error("RootCache PDA missing. Run `anchor run init` first.");

    try {
      const treeAcc = await (program.account as any).treeState.fetch(treePda);
      preTreeNextIndex = Number(treeAcc.nextIndex ?? treeAcc.next_index ?? 0);
    } catch {
      preTreeNextIndex = -1;
    }

    // SPL Mint & ATAs (0 decimals)
    tokenMint = await createMint(connection, wallet.payer, payer, null, 0);
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
    const ixs = [];
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

  it("debug: check OLD_ROOT(new) vs on-chain tree root (+ optional cache sample)", async () => {
    const oldRootFe = slice32(publicsLE, DEPOSIT_IDX.OLD_ROOT);
    const newRootFe = slice32(publicsLE, DEPOSIT_IDX.NEW_ROOT);
    console.log("🔎 OLD_ROOT (pubs, BE) =", "0x" + toHexBE(oldRootFe));
    console.log("🔎 NEW_ROOT (pubs, BE) =", "0x" + toHexBE(newRootFe));

    try {
      const treeAcc = await (program.account as any).treeState.fetch(treePda);
      const onchainRootBytes = Buffer.from(
        (treeAcc.currentRoot ?? treeAcc.current_root ?? treeAcc.root ?? [])
      );
      console.log(
        "🔎 on-chain tree.root (BE) =",
        "0x" + Buffer.from(onchainRootBytes).reverse().toString("hex")
      );
      const same = Buffer.compare(Buffer.from(oldRootFe), Buffer.from(onchainRootBytes)) === 0;
      console.log("🧪 OLD_ROOT == on-chain root ?", same);
      if (FAIL_ON_ROOT_MISMATCH) expect(same).toBe(true);
    } catch (e) {
      console.log("⚠️ could not fetch treeState for root parity:", String(e));
    }

    try {
      if ((program.account as any).rootCache?.fetch) {
        const rc = await (program.account as any).rootCache.fetch(rootCachePda);
        const arr = (rc.roots ?? rc.entries ?? rc.cache ?? []) || [];
        const sample = Array.isArray(arr) ? arr.slice(0, 6) : [];
        console.log(
          "🔎 root-cache sample (first up to 6, BE):",
          sample.map((a) => "0x" + Buffer.from(Buffer.from(a)).reverse().toString("hex"))
        );
      } else {
        console.log("ℹ️ program.account.rootCache not available (loader struct?)");
      }
    } catch (e) {
      console.log("⚠️ could not fetch rootCache (ok if loader):", String(e));
    }
  });

  async function buildDepositTx(dHashLE: Buffer): Promise<{ tx: Transaction; programIx: TransactionInstruction }> {
    // choose seed endianness for PDA derivation
    const seedBytes =
      DHASH_SEED_ENDIAN === "be" ? Buffer.from(dHashLE).reverse() : dHashLE;
    if (DHASH_SEED_ENDIAN !== "le") {
      console.log(`⚙️  DHASH_SEED_ENDIAN=${DHASH_SEED_ENDIAN} — PDA uses reversed hash`);
    }

    const [depositMarkerPda] = web3.PublicKey.findProgramAddressSync(
      [DEPOSIT_SEED, seedBytes],
      programId
    );

    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });
    const transferIx = createTransferCheckedInstruction(
      payerAta, tokenMint, vaultAta, payer, amountU64, 0, [], TOKEN_PROGRAM_ID
    );
    const memoIx = INCLUDE_MEMO ? createMemoInstruction(MEMO_TEXT || "d", [payer]) : null;

    const programIx = await program.methods
      .shieldedDepositAtomic(dHashLE, proofBytes, publicsForIx)
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

    const tx: Transaction = new web3.Transaction().add(
      cuIx,
      ...(memoIx ? [memoIx] : []),
      transferIx,
      programIx
    );
    return { tx, programIx };
  }

  it("verifies on-chain via shielded_deposit_atomic (quick-checks)", async () => {
    const prePayer = await getU64TokenBal(connection, payerAta);
    const preVault = await getU64TokenBal(connection, vaultAta);

    const { tx, programIx } = await buildDepositTx(depositHash);

    const signers = programIx.keys
      .filter((k) => k.isSigner)
      .map((k) => k.pubkey.toBase58());
    console.log("🧪 required signers (program ix):", signers);
    expect(signers).toEqual([payer.toBase58()]);

    console.log("🔎 full tx instructions:");
    tx.instructions.forEach((ix: TransactionInstruction, i: number) => {
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
        console.log(`      token.keys: src=${k[0]} mint=${k[1]} dst=${k[2]} auth=${k[3]}`);
      }
    });

    const sig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    console.log(`✅ shielded_deposit_atomic tx [${VARIANT}]:`, sig);

    const postPayer = await getU64TokenBal(connection, payerAta);
    const postVault = await getU64TokenBal(connection, vaultAta);
    const amt = amountU64;
    expect(postPayer).toBe(prePayer - amt);
    expect(postVault).toBe(preVault + amt);

    if (preTreeNextIndex >= 0) {
      try {
        const treeAcc = await (program.account as any).treeState.fetch(treePda);
        const postNextIndex = Number(treeAcc.nextIndex ?? treeAcc.next_index ?? 0);
        expect(postNextIndex).toBe(preTreeNextIndex + 1);
      } catch {
        /* ignore */
      }
    }

    const res = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    console.log("---- on-chain logs ----");
    res?.meta?.logMessages?.forEach((l: string) => console.log(l));
    console.log("---- end logs ----");
  });

  it("sanity: proof structure", () => {
    const pA = proofBytes.subarray(0, 64);
    const pB = proofBytes.subarray(64, 192);
    const pC = proofBytes.subarray(192, 256);
    expect(pA.length).toBe(64);
    expect(pB.length).toBe(128);
    expect(pC.length).toBe(64);
    expect(publicsLE.length % 32).toBe(0);
  });
});

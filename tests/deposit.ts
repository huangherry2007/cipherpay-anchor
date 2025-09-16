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
function toHexBE(b: Buffer): string {
  const r = Buffer.from(b);
  r.reverse();
  return toHexLE(r);
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

// Poseidon zero-root helpers (BigInt-safe: no literals)
function toLeBytes32FromBig(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  const EIGHT = BigInt(8);
  const FF = BigInt(0xff);
  for (let i = 0; i < 32; i++) {
    const shift = BigInt(i) * EIGHT;
    out[i] = Number((n >> shift) & FF);
  }
  return out;
}
async function computeZeroRoot(depth: number): Promise<Uint8Array> {
  // @ts-ignore: circomlibjs has no types
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const F = (poseidon as any).F;
  const H2 = (a: bigint, b: bigint) => F.toObject(poseidon([a, b])) as bigint;
  let node = BigInt(0); // zero leaf
  for (let i = 0; i < depth; i++) node = H2(node, node);
  return toLeBytes32FromBig(node);
}

// FE decoders for 32-byte arrays (avoid BigInt literals for ES<2020)
function fromLeBytes32(u8: Uint8Array): bigint {
  let x = BigInt(0);
  const EIGHT = BigInt(8);
  for (let i = 31; i >= 0; i--) {
    x = (x << EIGHT) + BigInt(u8[i]);
  }
  return x;
}
function fromBeBytes32(u8: Uint8Array): bigint {
  let x = BigInt(0);
  const EIGHT = BigInt(8);
  for (let i = 0; i < 32; i++) {
    x = (x << EIGHT) + BigInt(u8[i]);
  }
  return x;
}

// ───────────────────────── config ─────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);
const DEFAULT_DEPTH = Number(process.env.CP_TREE_DEPTH ?? 16);
const TREE_SEED = Buffer.from("tree");

// proofs dir (override with env if desired)
const buildDir = process.env.DEPOSIT_BUILD_DIR
  ? path.resolve(process.env.DEPOSIT_BUILD_DIR)
  : path.resolve("proofs");
const proofPath = path.join(buildDir, "deposit_proof.bin");
const publicsPath = path.join(buildDir, "deposit_public_signals.bin");

// public signal order used by your circuit export:
// newCommitment, ownerCipherPayPubKey, newMerkleRoot, newNextLeafIndex,
// amount, depositHash, oldMerkleRoot
const DEPOSIT_IDX = {
  NEW_COMMITMENT: 0,
  OWNER: 1,
  NEW_ROOT: 2,
  NEW_NEXT_IDX: 3,
  AMOUNT: 4,
  DEPOSIT_HASH: 5,
  OLD_ROOT: 6,
};

// PDA seeds (must match on-chain constants)
const VAULT_SEED = Buffer.from("vault");
const DEPOSIT_SEED = Buffer.from("deposit");

// mint config — we use 0 decimals to keep amounts simple
const MINT_DECIMALS = 0 as const;

// Memo program id (for pretty printing)
const MEMO_PROGRAM_ID = new web3.PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
);

// ───────────────────────── tests ─────────────────────────
describe("shielded_deposit_atomic (end-to-end) — seeds debug (auto-match Right)", () => {
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

  console.log("🧭 programId:", programId.toBase58());

  // will be populated in tests
  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;
  let depositHash: Buffer; // 32B (LE)
  let amountU64: number; // parsed to JS number

  // token + PDAs
  let tokenMint!: web3.PublicKey;
  let payerAta!: web3.PublicKey;
  let vaultPda!: web3.PublicKey;
  let vaultAta!: web3.PublicKey;

  // global tree & root cache
  let treePda!: web3.PublicKey;
  const rootCache = web3.Keypair.generate(); // signer init account

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

    // ---- Initialize global TreeState (idempotent, same seeds as on-chain) ----
    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);
    console.log("🌲 tree PDA:", treePda.toBase58());

    const preInfo = await connection.getAccountInfo(treePda);
    console.log("📦 tree exists before init?", !!preInfo);

    if (!preInfo) {
      const genesisRoot = await computeZeroRoot(DEFAULT_DEPTH);
      try {
        await program.methods
          .initializeTreeState(DEFAULT_DEPTH, Array.from(genesisRoot))
          .accountsPartial({
            tree: treePda,
            authority: payer,
            systemProgram: web3.SystemProgram.programId,
          })
          .rpc();
        console.log("✅ initialize_tree_state ok");
      } catch (e: any) {
        const msg = String(e?.message ?? e);
        if (/already.*in use/i.test(msg)) {
          console.log("ℹ️ tree already exists (race)");
        } else {
          console.error("❌ initialize_tree_state failed:", msg);
          throw e;
        }
      }
    } else {
      console.log("ℹ️ tree already exists");
    }

    // verify it really exists now
    const postInfo = await connection.getAccountInfo(treePda);
    if (!postInfo) {
      throw new Error(
        `TreeState PDA ${treePda.toBase58()} is still missing after init`
      );
    }

    // ---- Initialize Root Cache (idempotent) ----
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

  it("verifies on-chain via shielded_deposit_atomic (auto-match seeds)", async () => {
    // the PDA for the per-deposit idempotent marker
    const [depositMarkerPda] = web3.PublicKey.findProgramAddressSync(
      [DEPOSIT_SEED, depositHash],
      programId
    );

    // pre-ixs
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({
      units: CU_LIMIT,
    });

    // SPL transfer (payer ATA -> vault ATA)
    const transferIx = createTransferCheckedInstruction(
      payerAta,
      tokenMint,
      vaultAta,
      payer, // owner/authority of payerAta
      amountU64,
      MINT_DECIMALS,
      [],
      TOKEN_PROGRAM_ID
    );

    const memoIx = createMemoInstruction(
      "deposit:" + toHexLE(depositHash),
      [payer]
    );

    // Build the program instruction (Anchor)
    const mb = program.methods
      .shieldedDepositAtomic(depositHash, proofBytes, publicInputsBytes)
      .accountsPartial({
        payer,
        tree: treePda, // REQUIRED by #[account(seeds=[TREE_SEED], bump)]
        rootCache: rootCache.publicKey,
        depositMarker: depositMarkerPda,
        vaultPda,
        vaultTokenAccount: vaultAta,
        tokenMint,
        instructions: web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      });

    const anchorIx = await mb.instruction();

    // IMPORTANT: Token transfer **immediately before** our program ix
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

    // (Optional) Anchor ix account metas
    console.log("🔎 ix.accounts:");
    anchorIx.keys.forEach((k, i) => {
      const w = k.isWritable ? " (writable)" : "";
      const s = k.isSigner ? " (signer)" : "";
      console.log(`  [${i}] ${k.pubkey.toBase58()}${s}${w}`);
    });

    // ── On-chain root vs. proof oldMerkleRoot sanity check ─────────────
    {
      // oldMerkleRoot (field element) as the circuit produced it (LE in your bin)
      const oldRootBytesLE = slice32(publicInputsBytes, DEPOSIT_IDX.OLD_ROOT);
      const oldRootFE = fromLeBytes32(new Uint8Array(oldRootBytesLE));

      // fetch on-chain bytes from TreeState (your IDL shows 'currentRoot')
      const acc = await program.account.treeState.fetch(treePda);
      const rootBytesArr = new Uint8Array(acc.currentRoot as number[]);
      const rootBuf = Buffer.from(rootBytesArr);

      const feLE = fromLeBytes32(rootBytesArr);
      const feBE = fromBeBytes32(rootBytesArr);

      console.log("🌲 on-chain root (LE hex):", toHexLE(rootBuf));
      console.log("🌲 on-chain root (BE hex):", toHexBE(rootBuf));
      console.log("   on-chain FE (LE decode):", feLE.toString());
      console.log("   on-chain FE (BE decode):", feBE.toString());
      console.log("   proof oldMerkleRoot FE :", oldRootFE.toString());

      const matchesBE = feBE === oldRootFE;
      const matchesLE = feLE === oldRootFE;

      if (!matchesBE && !matchesLE) {
        throw new Error(
          "On-chain root bytes do not decode to the proof's oldMerkleRoot (neither BE nor LE)."
        );
      }
      if (matchesBE && !matchesLE) {
        console.log("✅ oldMerkleRoot matches on-chain (BE decode).");
      } else if (!matchesBE && matchesLE) {
        console.log("✅ oldMerkleRoot matches on-chain (LE decode).");
      } else {
        console.log("✅ oldMerkleRoot matches on-chain (both BE & LE decode).");
      }
    }
    // ───────────────────────────────────────────────────────────────────

    try {
      const sig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
      console.log("✅ shielded_deposit_atomic tx:", sig);

      // show on-chain logs even on success
      const res = await connection.getTransaction(sig, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      console.log("---- on-chain logs ----");
      res?.meta?.logMessages?.forEach((l) => console.log(l));
      console.log("---- end logs ----");
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      console.warn("⚠️ first attempt failed:", msg);
      if (e?.logs) {
        console.warn("---- logs (attempt 1) ----");
        for (const line of e.logs) console.warn(line);
        console.warn("---- end logs ----");
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

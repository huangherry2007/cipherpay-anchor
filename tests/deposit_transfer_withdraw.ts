// tests/deposit_transfer_withdraw.ts
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

// (optional) pull in your generator to auto-fix withdraw artifacts when needed
// eslint-disable-next-line @typescript-eslint/no-var-requires
const genBin = require("../../cipherpay-circuits/scripts/generate-bin-proofs.js");

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

// Poseidon zero-root helpers (BigInt-safe)
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
  // @ts-ignore
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const F = (poseidon as any).F;
  const H2 = (a: bigint, b: bigint) => F.toObject(poseidon([a, b])) as bigint;
  let node = BigInt(0);
  for (let i = 0; i < depth; i++) node = H2(node, node);
  return toLeBytes32FromBig(node);
}
function fromLeBytes32(u8: Uint8Array): bigint {
  let x = BigInt(0);
  for (let i = 31; i >= 0; i--) x = (x << BigInt(8)) + BigInt(u8[i]);
  return x;
}

// ───────────────────────── config ─────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);
const DEFAULT_DEPTH = Number(process.env.CP_TREE_DEPTH ?? 16);

const TREE_SEED = Buffer.from("tree");
const VAULT_SEED = Buffer.from("vault");
const DEPOSIT_SEED = Buffer.from("deposit");
const NULLIFIER_SEED = Buffer.from("nullifier");

const MINT_DECIMALS = 0 as const;

// proofs dir (all three)
const proofsDir = process.env.PROOFS_DIR
  ? path.resolve(process.env.PROOFS_DIR)
  : path.resolve("proofs");

// deposit files
const depProofPath = path.join(proofsDir, "deposit_proof.bin");
const depPublicsPath = path.join(proofsDir, "deposit_public_signals.bin");

// transfer files
const xferProofPath = path.join(proofsDir, "transfer_proof.bin");
const xferPublicsPath = path.join(proofsDir, "transfer_public_signals.bin");

// withdraw files
const wdrProofPath = path.join(proofsDir, "withdraw_proof.bin");
const wdrPublicsPath = path.join(proofsDir, "withdraw_public_signals.bin");

// public signal orders
const DEPOSIT_IDX = {
  NEW_COMMITMENT: 0,
  OWNER: 1,
  NEW_ROOT: 2,
  NEW_NEXT_IDX: 3,
  AMOUNT: 4,
  DEPOSIT_HASH: 5,
  OLD_ROOT: 6,
};
const TRANSFER_IDX = {
  OUT1: 0,
  OUT2: 1,
  NULLIFIER: 2,
  MERKLE_ROOT: 3,
  NEW_ROOT1: 4,
  NEW_ROOT2: 5,
  NEW_NEXT_IDX: 6,
  ENC1: 7,
  ENC2: 8,
};
const WITHDRAW_IDX = {
  NULLIFIER: 0,
  MERKLE_ROOT: 1,
  RECIPIENT_WPK: 2,
  AMOUNT: 3,
  TOKEN_ID: 4,
};

// ───────────────────────── tests ─────────────────────────
describe("deposit → transfer → withdraw (strict sync end-to-end)", () => {
  const connection = new web3.Connection(RPC_URL, "confirmed");
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

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;
  const programId = program.programId;
  const payer = wallet.publicKey;

  console.log("🧭 programId:", programId.toBase58());

  // populated during test
  let tokenMint!: web3.PublicKey;
  let payerAta!: web3.PublicKey;
  let vaultPda!: web3.PublicKey;
  let vaultAta!: web3.PublicKey;
  let treePda!: web3.PublicKey;
  const rootCache = web3.Keypair.generate();

  let depProof!: Buffer;
  let depPublics!: Buffer;
  let xferProof!: Buffer;
  let xferPublics!: Buffer;

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);

    // Load deposit & transfer proofs/public signals from disk
    depProof = readBin(depProofPath);
    depPublics = readBin(depPublicsPath);
    xferProof = readBin(xferProofPath);
    xferPublics = readBin(xferPublicsPath);

    expect(depProof.length).toBe(256);
    expect(depPublics.length).toBe(7 * 32);
    expect(xferProof.length).toBe(256);
    expect(xferPublics.length).toBe(9 * 32);

    // ---- Initialize TreeState if missing ----
    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);
    const pre = await connection.getAccountInfo(treePda);
    if (!pre) {
      const genesisRoot = await computeZeroRoot(DEFAULT_DEPTH);
      await program.methods
        .initializeTreeState(DEFAULT_DEPTH, Array.from(genesisRoot))
        .accountsPartial({
          tree: treePda,
          authority: payer,
          systemProgram: web3.SystemProgram.programId,
        })
        .rpc();
      console.log("✅ initialize_tree_state ok");
    } else {
      console.log("ℹ️ tree already exists");
    }

    // ---- Initialize Root Cache ----
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

    // ---- SPL mint + ATAs ----
    tokenMint = await createMint(
      connection,
      wallet.payer,
      payer,
      null,
      MINT_DECIMALS
    );

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
    const preIxs: web3.TransactionInstruction[] = [];
    if (createPayerAtaIx) preIxs.push(createPayerAtaIx);
    if (createVaultAtaIx) preIxs.push(createVaultAtaIx);
    if (preIxs.length) {
      await provider.sendAndConfirm(new web3.Transaction().add(...preIxs));
      console.log("✅ created missing ATAs");
    }

    // Mint enough tokens for deposit
    const depAmtFe = slice32(depPublics, DEPOSIT_IDX.AMOUNT);
    const amountU64 =
      depAmtFe[0] |
      (depAmtFe[1] << 8) |
      (depAmtFe[2] << 16) |
      (depAmtFe[3] << 24) |
      (depAmtFe[4] * 2 ** 32) +
      (depAmtFe[5] * 2 ** 40) +
      (depAmtFe[6] * 2 ** 48) +
      (depAmtFe[7] * 2 ** 56);

    await mintTo(connection, wallet.payer, tokenMint, payerAta, payer, amountU64);
    console.log("✅ minted deposit amount to payer ATA");
  });

  it("end-to-end: deposit → transfer → withdraw (strict sync)", async () => {
    // -------------------- DEPOSIT --------------------
    const depositHash = slice32(depPublics, DEPOSIT_IDX.DEPOSIT_HASH);
    const amountFe = slice32(depPublics, DEPOSIT_IDX.AMOUNT);
    const amountU64 =
      amountFe[0] |
      (amountFe[1] << 8) |
      (amountFe[2] << 16) |
      (amountFe[3] << 24) |
      (amountFe[4] * 2 ** 32) +
      (amountFe[5] * 2 ** 40) +
      (amountFe[6] * 2 ** 48) +
      (amountFe[7] * 2 ** 56);

    console.log("🔑 depositHash (LE, hex):", toHexLE(depositHash));

    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({
      units: CU_LIMIT,
    });
    const memoIx = createMemoInstruction("deposit:" + toHexLE(depositHash), [
      payer,
    ]);
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

    const depIx = await program.methods
      .shieldedDepositAtomic(depositHash, depProof, depPublics)
      .accountsPartial({
        payer,
        tree: treePda,
        rootCache: rootCache.publicKey,
        depositMarker: web3.PublicKey.findProgramAddressSync(
          [DEPOSIT_SEED, depositHash],
          programId
        )[0],
        vaultPda,
        vaultTokenAccount: vaultAta,
        tokenMint,
        instructions: web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .instruction();

    const depTx = new web3.Transaction().add(cuIx, memoIx, transferIx, depIx);
    const depSig = await provider.sendAndConfirm(depTx, [], {
      skipPreflight: false,
    });
    console.log("✅ shielded_deposit_atomic tx:", depSig);

    // Tree after deposit
    const treeAfterDeposit: any = await program.account.treeState.fetch(treePda);
    const curRoot = new Uint8Array(treeAfterDeposit.currentRoot as number[]);
    const curRootBig = fromLeBytes32(curRoot);
    console.log(
      "🌳 tree after deposit — root(LE)=",
      Buffer.from(curRoot).toString("hex"),
      " nextIndex=",
      treeAfterDeposit.nextIndex
    );

    // -------------------- TRANSFER --------------------
    const xNullifier = slice32(xferPublics, TRANSFER_IDX.NULLIFIER);
    const spentRoot = slice32(xferPublics, TRANSFER_IDX.MERKLE_ROOT);
    console.log("🔒 transfer nullifier (LE, hex):", toHexLE(xNullifier));
    console.log("🌲 spent merkle root (LE, hex):", toHexLE(spentRoot));

    // strict sync: spent root must equal current on-chain root
    expect(fromLeBytes32(spentRoot)).toEqual(curRootBig);

    const [xferNullifierPda] = web3.PublicKey.findProgramAddressSync(
      [NULLIFIER_SEED, xNullifier],
      programId
    );

    const xferSig = await program.methods
      .shieldedTransfer(Array.from(xNullifier), xferProof, xferPublics)
      .accountsPartial({
        tree: treePda,
        rootCache: rootCache.publicKey,
        nullifierRecord: xferNullifierPda,
        payer,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    console.log("✅ shielded_transfer tx:", xferSig);

    // Tree after transfer
    const treeAfterTransfer: any = await program.account.treeState.fetch(
      treePda
    );
    const curRootAfterTransfer = new Uint8Array(
      treeAfterTransfer.currentRoot as number[]
    );
    const curRootAfterTransferBig = fromLeBytes32(curRootAfterTransfer);
    console.log(
      "🌳 tree after transfer — root(LE)=",
      Buffer.from(curRootAfterTransfer).toString("hex"),
      " nextIndex=",
      treeAfterTransfer.nextIndex
    );

    // -------------------- WITHDRAW --------------------
    // Load withdraw artifacts; if their merkle root doesn't match the current on-chain root,
    // try to auto-regenerate from the labeled transfer outputs.
    let wdrProof = readBin(wdrProofPath);
    let wdrPublics = readBin(wdrPublicsPath);

    expect(wdrProof.length).toBe(256);
    expect(wdrPublics.length).toBe(5 * 32);

    let wdrNullifier = slice32(wdrPublics, WITHDRAW_IDX.NULLIFIER);
    let wdrMerkleRoot = slice32(wdrPublics, WITHDRAW_IDX.MERKLE_ROOT);

    if (fromLeBytes32(wdrMerkleRoot) !== curRootAfterTransferBig) {
      console.warn("⚠️ withdraw publics root != on-chain root. attempting to regenerate...");
      try {
        await genBin.generateBinaryProofs("withdraw"); // uses exampleInputs + auto-derive
        wdrProof = readBin(wdrProofPath);
        wdrPublics = readBin(wdrPublicsPath);
        wdrNullifier = slice32(wdrPublics, WITHDRAW_IDX.NULLIFIER);
        wdrMerkleRoot = slice32(wdrPublics, WITHDRAW_IDX.MERKLE_ROOT);
      } catch (e: any) {
        console.error("regeneration failed:", e?.message ?? e);
      }
    }

    console.log("🔍 WITHDRAW ARTIFACTS");
    console.log("   proof bytes:", wdrProof.length);
    console.log("   publics bytes:", wdrPublics.length);
    console.log("   nullifier (LE hex):", toHexLE(wdrNullifier));
    console.log("   merkleRoot (LE hex):", toHexLE(wdrMerkleRoot));

    // strict sync: withdraw must target the current root
    expect(fromLeBytes32(wdrMerkleRoot)).toEqual(curRootAfterTransferBig);

    // PDAs for withdraw: use withdraw's nullifier (different from transfer's)
    const [wdrNullifierPda] = web3.PublicKey.findProgramAddressSync(
      [NULLIFIER_SEED, wdrNullifier],
      programId
    );

    // Ensure recipient ATA exists (withdraw to payer)
    const recipientOwner = payer;
    const recipientAta = getAssociatedTokenAddressSync(
      tokenMint,
      recipientOwner,
      false,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    const maybeCreateRecipientAtaIx = await ensureAtaIx(
      connection,
      recipientAta,
      payer,
      recipientOwner,
      tokenMint
    );
    if (maybeCreateRecipientAtaIx) {
      await provider.sendAndConfirm(
        new web3.Transaction().add(maybeCreateRecipientAtaIx)
      );
    }

    // Compute-budget bump for withdraw as well
    const cuIx2 = web3.ComputeBudgetProgram.setComputeUnitLimit({
      units: CU_LIMIT,
    });

    const wdrIx = await program.methods
      .shieldedWithdraw(Array.from(wdrNullifier), wdrProof, wdrPublics)
      .accountsPartial({
        nullifierRecord: wdrNullifierPda,
        rootCache: rootCache.publicKey,
        authority: payer, // payer covers rent if nullifier PDA needs create
        vaultPda,
        vaultTokenAccount: vaultAta,
        recipientTokenAccount: recipientAta,
        recipientOwner,
        tokenMint,
        systemProgram: web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .instruction();

    const wdrTx = new web3.Transaction().add(cuIx2, wdrIx);
    const wdrSig = await provider.sendAndConfirm(wdrTx);
    console.log("✅ shielded_withdraw tx:", wdrSig);
  });

  it("sanity: proof/publics lengths (dep/xfer)", () => {
    expect(depProof.length).toBe(256);
    expect(depPublics.length).toBe(7 * 32);
    expect(xferProof.length).toBe(256);
    expect(xferPublics.length).toBe(9 * 32);
  });
});

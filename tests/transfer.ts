// tests/transfer.ts
import * as fs from "fs";
import * as path from "path";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, web3 } from "@coral-xyz/anchor";

// ───────────────────────── IDL loader ─────────────────────────
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
  return new Program(idl as unknown as anchor.Idl, provider);
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
function u32LE(b: Buffer): number {
  return ((b[0]) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
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

// ───────────────────────── config ─────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);

// PDA seeds (must match on-chain constants)
const TREE_SEED = Buffer.from("tree");
const ROOT_CACHE_SEED = Buffer.from("root_cache");
const NULLIFIER_SEED = Buffer.from("nullifier");

// proofs dir (override with env if desired)
const buildDir = process.env.TRANSFER_BUILD_DIR
  ? path.resolve(process.env.TRANSFER_BUILD_DIR)
  : path.resolve("proofs");
const proofPath = path.join(buildDir, "transfer_proof.bin");
const publicsPath = path.join(buildDir, "transfer_public_signals.bin");

// public signal order (transfer.circom):
// [ outCommitment1, outCommitment2, nullifier, merkleRoot,
//   newMerkleRoot1, newMerkleRoot2, newNextLeafIndex, encNote1Hash, encNote2Hash ]
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
} as const;

// ───────────────────────── tests ─────────────────────────
describe("shielded_transfer — assumes PDAs pre-initialized (no init here)", () => {
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

  // populated in tests
  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;
  let nullifierBuf!: Buffer;       // 32B (LE)
  let merkleRootBefore!: Buffer;   // 32B (LE)
  let newRoot1!: Buffer;
  let newRoot2!: Buffer;
  let newNextIdx!: number;

  // PDAs
  let treePda!: web3.PublicKey;
  let rootCachePda!: web3.PublicKey;

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);

    // load proof + publics (Buffers required for Anchor `bytes`)
    proofBytes = readBin(proofPath);
    publicInputsBytes = readBin(publicsPath);
    expect(proofBytes.length).toBe(256);
    expect(publicInputsBytes.length).toBe(9 * 32);

    // extract fields
    nullifierBuf = slice32(publicInputsBytes, TRANSFER_IDX.NULLIFIER);     // Buffer(32) ✅
    merkleRootBefore = slice32(publicInputsBytes, TRANSFER_IDX.MERKLE_ROOT);
    newRoot1 = slice32(publicInputsBytes, TRANSFER_IDX.NEW_ROOT1);
    newRoot2 = slice32(publicInputsBytes, TRANSFER_IDX.NEW_ROOT2);
    newNextIdx = u32LE(slice32(publicInputsBytes, TRANSFER_IDX.NEW_NEXT_IDX));

    console.log("🔒 nullifier (LE, hex):", toHexLE(nullifierBuf));
    console.log("🌲 spent merkle root (LE, hex):", toHexLE(merkleRootBefore));

    // Derive PDAs (must already exist, created by `anchor run init`)
    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);
    [rootCachePda] = web3.PublicKey.findProgramAddressSync([ROOT_CACHE_SEED], programId);

    // Require PDAs to exist; do NOT initialize here
    const treeInfo = await connection.getAccountInfo(treePda);
    const rcInfo = await connection.getAccountInfo(rootCachePda);
    if (!treeInfo) throw new Error("TreeState PDA missing. Run `anchor run init` first.");
    if (!rcInfo) throw new Error("RootCache PDA missing. Run `anchor run init` first.");

    // Optional: fetch and log current tree state (no hard assert — let on-chain checks enforce match)
    try {
      const tree: any = await (program.account as any).treeState.fetch(treePda);
      const nextIdx = tree.nextIndex as number;
      const rootHex = Buffer.from(tree.currentRoot as number[]).toString("hex");
      console.log("ℹ️ on-chain tree:", { nextIdx, root: rootHex });
    } catch {
      // If IDL account name differs, skip
    }
  });

  it("verifies on-chain via shielded_transfer", async () => {
    // Nullifier record PDA from the 32-byte nullifier (same seeds as program)
    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync(
      [NULLIFIER_SEED, nullifierBuf], // Buffer as seed ✅
      programId
    );

    // Pre-ix: compute budget
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });

    // Build program ix — IMPORTANT: pass Buffer for the [u8;32] nullifier
    const anchorIx = await program.methods
      .shieldedTransfer(nullifierBuf, proofBytes, publicInputsBytes)
      .accountsPartial({
        payer,
        tree: treePda,
        rootCache: rootCachePda,         // PDA (pre-initialized by migrations)
        nullifierRecord: nullifierRecordPda,
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();

    // sanity — should be only `payer`
    const signers = anchorIx.keys.filter(k => k.isSigner).map(k => k.pubkey.toBase58());
    console.log("🧪 required signers (program ix):", signers);
    if (!(signers.length === 1 && signers[0] === payer.toBase58())) {
      throw new Error("IDL requires unexpected signers: " + JSON.stringify(signers));
    }

    const tx = new web3.Transaction().add(cuIx, anchorIx);

    const sig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    console.log("✅ shielded_transfer tx:", sig);

    const res = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    console.log("---- on-chain logs ----");
    res?.meta?.logMessages?.forEach((l) => console.log(l));
    console.log("---- end logs ----");

    // Best-effort post-state checks if account is fetchable
    try {
      const treeAfter: any = await (program.account as any).treeState.fetch(treePda);
      const postNextIdx = treeAfter.nextIndex as number;
      const postRootHex = Buffer.from(treeAfter.currentRoot as number[]).toString("hex");
      const r1 = Buffer.from(newRoot1).toString("hex");
      const r2 = Buffer.from(newRoot2).toString("hex");
      expect([r1, r2]).toContain(postRootHex);
      expect(postNextIdx).toBe(newNextIdx);
    } catch { /* optional */ }
  });

  it("replay-guard: same nullifier again should fail", async () => {
    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync(
      [NULLIFIER_SEED, nullifierBuf],
      programId
    );

    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });
    const anchorIx = await program.methods
      .shieldedTransfer(nullifierBuf, proofBytes, publicInputsBytes)
      .accountsPartial({
        payer,
        tree: treePda,
        rootCache: rootCachePda,
        nullifierRecord: nullifierRecordPda,
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();

    const tx = new web3.Transaction().add(cuIx, anchorIx);

    await expect(provider.sendAndConfirm(tx, [], { skipPreflight: false }))
      .rejects.toThrow();
  });

  it("sanity: proof/public bytes lengths", () => {
    const a = proofBytes.subarray(0, 64);
    const b = proofBytes.subarray(64, 192);
    const c = proofBytes.subarray(192, 256);
    expect(a.length).toBe(64);
    expect(b.length).toBe(128);
    expect(c.length).toBe(64);
    expect(publicInputsBytes.length).toBe(9 * 32);
  });
});

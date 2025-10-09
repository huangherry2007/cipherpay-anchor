// tests/transfer.ts
import * as fs from "fs";
import * as path from "path";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, web3 } from "@coral-xyz/anchor";

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

function readBin(p: string): Buffer { return fs.readFileSync(path.resolve(p)); }
function toHexLE(b: Buffer): string { return [...b].map((x) => x.toString(16).padStart(2, "0")).join(""); }
function slice32(buf: Buffer, i: number): Buffer { const off = i * 32; return buf.subarray(off, off + 32); }
async function ensureAirdrop(connection: web3.Connection, pubkey: web3.PublicKey, wantLamports = 10 * web3.LAMPORTS_PER_SOL) {
  const before = await connection.getBalance(pubkey);
  if (before >= wantLamports) return before;
  const sig = await connection.requestAirdrop(pubkey, wantLamports - before);
  await connection.confirmTransaction(sig, "confirmed");
  return await connection.getBalance(pubkey);
}
const toNum = (x: any) => (typeof x === "number" ? x : Number(x?.toString?.() ?? x));

// ── config ────────────────────────────────────────────────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);

// NEW: variant selector (defaults to 'transfer')
const TRANSFER_VARIANT = (process.env.TRANSFER_VARIANT || "transfer").trim();

const TREE_SEED = Buffer.from("tree");
const ROOT_CACHE_SEED = Buffer.from("root_cache");
const NULLIFIER_SEED = Buffer.from("nullifier");

// proofs dir (override with env if desired)
const buildDir = process.env.TRANSFER_BUILD_DIR ? path.resolve(process.env.TRANSFER_BUILD_DIR) : path.resolve("proofs");

// UPDATED: pick files based on TRANSFER_VARIANT (logic unchanged elsewhere)
const proofPath = path.join(buildDir, `${TRANSFER_VARIANT}_proof.bin`);
const publicsPath = path.join(buildDir, `${TRANSFER_VARIANT}_public_signals.bin`);

const TRANSFER_IDX = { OUT1: 0, OUT2: 1, NULLIFIER: 2, MERKLE_ROOT: 3, NEW_ROOT1: 4, NEW_ROOT2: 5, NEW_NEXT_IDX: 6, ENC1: 7, ENC2: 8 } as const;

describe("shielded_transfer — assumes PDAs pre-initialized (no init here)", () => {
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
  console.log("📁 using proof files:", { proofPath, publicsPath });

  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;
  let nullifierBuf!: Buffer;
  let merkleRootBefore!: Buffer;
  let newRoot1!: Buffer;
  let newRoot2!: Buffer;

  let treePda!: web3.PublicKey;
  let rootCachePda!: web3.PublicKey;

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);
    proofBytes = readBin(proofPath);
    publicInputsBytes = readBin(publicsPath);
    expect(proofBytes.length).toBe(256);
    expect(publicInputsBytes.length).toBe(9 * 32);

    nullifierBuf = slice32(publicInputsBytes, TRANSFER_IDX.NULLIFIER);
    merkleRootBefore = slice32(publicInputsBytes, TRANSFER_IDX.MERKLE_ROOT);
    newRoot1 = slice32(publicInputsBytes, TRANSFER_IDX.NEW_ROOT1);
    newRoot2 = slice32(publicInputsBytes, TRANSFER_IDX.NEW_ROOT2);

    console.log("🔒 nullifier (LE, hex):", toHexLE(nullifierBuf));
    console.log("🌲 spent merkle root (LE, hex):", toHexLE(merkleRootBefore));

    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);
    [rootCachePda] = web3.PublicKey.findProgramAddressSync([ROOT_CACHE_SEED], programId);

    const accountsAny = program.account as any;
    const treeAcc: any = await accountsAny["treeState"].fetch(treePda);
    const preNextIdx = toNum(treeAcc.nextIndex);
    const preRootBuf = Buffer.from(treeAcc.currentRoot as number[]);
    console.log("ℹ️ on-chain tree:", { nextIdx: preNextIdx, root: toHexLE(preRootBuf) });
    expect(toHexLE(preRootBuf)).toBe(toHexLE(merkleRootBefore));
  });

  it("verifies on-chain via shielded_transfer (+2 next_index; cache has both roots)", async () => {
    const accountsAny = program.account as any;

    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync([NULLIFIER_SEED, nullifierBuf], programId);
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });

    const treeBefore: any = await accountsAny["treeState"].fetch(treePda);
    const preNextIdx = toNum(treeBefore.nextIndex);

    // ⬇️ PASS A 32-BYTE BUFFER (IDL expects [u8; 32])
    // IMPORTANT: keep the original argument order and logic
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

    const signers = anchorIx.keys.filter(k => k.isSigner).map(k => k.pubkey.toBase58());
    console.log("🧪 required signers (program ix):", signers);
    if (!(signers.length === 1 && signers[0] === payer.toBase58())) {
      throw new Error("IDL requires unexpected signers: " + JSON.stringify(signers));
    }

    const tx = new web3.Transaction().add(cuIx, anchorIx);
    const sig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    console.log("✅ shielded_transfer tx:", sig);

    const treeAfter: any = await accountsAny["treeState"].fetch(treePda);
    const postNextIdx = toNum(treeAfter.nextIndex);
    const postRootBuf = Buffer.from(treeAfter.currentRoot as number[]);
    expect(postNextIdx).toBe(preNextIdx + 2);
    expect(toHexLE(postRootBuf)).toBe(toHexLE(newRoot2));

    const rc: any = await (program.account as any)["merkleRootCache"].fetch(rootCachePda);
    const count = toNum(rc.count);
    const rootsArr = rc.roots as number[][];
    const cachedRootsHex: string[] = rootsArr
      .slice(0, Math.max(count, rootsArr.length))
      .map(arr => toHexLE(Buffer.from(arr)));

    const hex1 = toHexLE(newRoot1);
    const hex2 = toHexLE(newRoot2);
    expect(cachedRootsHex.includes(hex1)).toBe(true);
    expect(cachedRootsHex.includes(hex2)).toBe(true);

    const res = await connection.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    console.log("---- on-chain logs ----");
    res?.meta?.logMessages?.forEach((l) => console.log(l));
    console.log("---- end logs ----");
  });

  it("replay-guard: same nullifier again should fail", async () => {
    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync([NULLIFIER_SEED, nullifierBuf], programId);
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });

    // ⬇️ Buffer again (keep order)
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
    await expect(provider.sendAndConfirm(tx, [], { skipPreflight: true })).rejects.toThrow();
  });

  it("sanity: proof/public bytes lengths", () => {
    const a = publicInputsBytes.subarray(0, 32);
    expect(a.length).toBe(32);
    const pA = proofBytes.subarray(0, 64);
    const pB = proofBytes.subarray(64, 192);
    const pC = proofBytes.subarray(192, 256);
    expect(pA.length).toBe(64);
    expect(pB.length).toBe(128);
    expect(pC.length).toBe(64);
    expect(publicInputsBytes.length).toBe(9 * 32);
  });
});

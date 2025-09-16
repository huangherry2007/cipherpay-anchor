// tests/transfer.ts
import * as fs from "fs";
import * as path from "path";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, web3 } from "@coral-xyz/anchor";
import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

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

// ───────────────────────── config ─────────────────────────
const RPC_URL = process.env.SOLANA_URL || "http://127.0.0.1:8899";
const DEFAULT_DEPTH = Number(process.env.CP_TREE_DEPTH ?? 16);
const TREE_SEED = Buffer.from("tree");
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
};

// ───────────────────────── tests ─────────────────────────
describe("shielded_transfer — strict sync", () => {
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

  // will be populated in tests
  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;
  let nullifierBuf!: Buffer;      // 32B (LE)
  let merkleRootBefore!: Buffer;  // 32B (LE)

  // PDAs & accounts
  let treePda!: web3.PublicKey;
  const rootCache = web3.Keypair.generate(); // signer for init

  beforeAll(async () => {
    await ensureAirdrop(connection, payer);

    // load proof + publics (MUST be Buffers for Anchor `bytes`)
    proofBytes = readBin(proofPath);
    publicInputsBytes = readBin(publicsPath);
    expect(proofBytes.length).toBe(256);
    expect(publicInputsBytes.length).toBe(9 * 32);

    // extract fields we need
    nullifierBuf = slice32(publicInputsBytes, TRANSFER_IDX.NULLIFIER);
    merkleRootBefore = slice32(publicInputsBytes, TRANSFER_IDX.MERKLE_ROOT);

    console.log("🔒 nullifier (LE, hex):", toHexLE(nullifierBuf));
    console.log("🌲 spent merkle root (LE, hex):", toHexLE(merkleRootBefore));

    // ---- Initialize global TreeState to the *spent* root (strict sync) ----
    [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], programId);

    const preInfo = await connection.getAccountInfo(treePda);
    if (!preInfo) {
      // Initialize with depth and the spent root from the proof
      await program.methods
        .initializeTreeState(DEFAULT_DEPTH, Array.from(merkleRootBefore))
        .accountsPartial({
          tree: treePda,
          authority: payer,
          systemProgram: web3.SystemProgram.programId,
        })
        .rpc();
      console.log("✅ initialize_tree_state ok (bootstrapped to spent root)");
    } else {
      console.log("ℹ️ tree already exists — make sure it matches your spent root.");
    }

    // ---- Initialize Root Cache (idempotent) ----
    try {
      await program.methods
        .initializeRootCache()
        .accounts({
          rootCache: rootCache.publicKey,
          authority: payer,
          // ⬅️ DO NOT pass systemProgram here (Anchor treats it as constant)
        })
        .signers([rootCache])
        .rpc();
      console.log("✅ initialize_root_cache ok");
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      if (!/already in use/i.test(msg)) throw e;
      console.log("ℹ️ root_cache already exists");
    }
  });

  it("verifies on-chain via shielded_transfer (strict sync)", async () => {
    // Derive nullifier record PDA from the 32-byte nullifier (same seeds as program)
    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync(
      [NULLIFIER_SEED, nullifierBuf],
      programId
    );

    // Build & send (IMPORTANT: `proofBytes` and `publicInputsBytes` are Buffers)
    const sig = await program.methods
      .shieldedTransfer(Array.from(nullifierBuf), proofBytes, publicInputsBytes)
      .accountsPartial({
        tree: treePda,
        rootCache: rootCache.publicKey,
        nullifierRecord: nullifierRecordPda,
        payer,
        // systemProgram omitted: Anchor knows the constant id
      })
      .rpc();

    console.log("✅ shielded_transfer tx:", sig);

    // show on-chain logs even on success
    const res = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    console.log("---- on-chain logs ----");
    res?.meta?.logMessages?.forEach((l) => console.log(l));
    console.log("---- end logs ----");
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

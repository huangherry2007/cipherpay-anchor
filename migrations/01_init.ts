// migrations/01_init.ts
import * as anchor from "@coral-xyz/anchor";
import { Program, web3 } from "@coral-xyz/anchor";
import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

const DEFAULT_DEPTH = Number(process.env.CP_TREE_DEPTH ?? 16);
const GENESIS_ROOT_OVERRIDE = process.env.CP_GENESIS_ROOT ?? "";

// ---- helpers (no BigInt literals; avoid ES2020 requirement) ----
function toLeBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  const FF = BigInt(0xff);
  const EIGHT = BigInt(8);
  for (let i = 0; i < 32; i++) {
    // eslint-disable-next-line @typescript-eslint/no-loss-of-precision
    out[i] = Number(x & FF);
    x = x >> EIGHT;
  }
  return out;
}

function bigFromString(s: string): bigint {
  const t = s.trim();
  if (t.length === 0) return BigInt(0);
  if (t.startsWith("0x") || t.startsWith("0X")) return BigInt(t);
  return BigInt(t);
}

async function computeZeroRoot(depth: number): Promise<Uint8Array> {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore - circomlibjs has no types
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const F = (poseidon as any).F;

  const H2 = (a: bigint, b: bigint) =>
    F.toObject(poseidon([a, b])) as bigint;

  let node = BigInt(0); // zero leaf
  for (let i = 0; i < depth; i++) node = H2(node, node);
  return toLeBytes32(node);
}

export default async function (provider: anchor.AnchorProvider) {
  anchor.setProvider(provider);
  const program = anchor.workspace
    .CipherpayAnchor as Program<CipherpayAnchor>;

  console.log("⚙️  network:", provider.connection.rpcEndpoint);
  console.log("🧭 programId:", program.programId.toBase58());

  // PDA for TreeState: seeds must match on-chain TREE_SEED (b"tree")
  const [treePda] = web3.PublicKey.findProgramAddressSync(
    [Buffer.from("tree")],
    program.programId
  );

  const rootCacheKp = web3.Keypair.generate();

  // ---- compute genesis root ----
  const depth = DEFAULT_DEPTH;
  let genesisRoot: Uint8Array;
  if (GENESIS_ROOT_OVERRIDE) {
    const n = bigFromString(GENESIS_ROOT_OVERRIDE);
    genesisRoot = toLeBytes32(n);
    console.log(
      "🌱 using overridden genesis root:",
      "0x" + Buffer.from(genesisRoot).reverse().toString("hex")
    );
  } else {
    genesisRoot = await computeZeroRoot(depth);
    console.log(
      "🌱 computed zero-tree root:",
      "0x" + Buffer.from(genesisRoot).reverse().toString("hex")
    );
  }

  // ---- Initialize TreeState (idempotent-ish: ignore 'already in use') ----
  try {
    console.log("📦 initializeTreeState...");
    await program.methods
      .initializeTreeState(depth, Array.from(genesisRoot))
      // use accountsPartial to avoid strict TS IDL checks if your generated types are stale
      .accountsPartial({
        tree: treePda,
        authority: provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    console.log("✅ tree =", treePda.toBase58());
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    if (!/already.*in use/i.test(msg)) throw e;
    console.log("ℹ️ tree already exists:", treePda.toBase58());
  }

  // ---- Initialize Root Cache ----
  try {
    console.log("📦 initializeRootCache...");
    await program.methods
      .initializeRootCache()
      .accountsPartial({
        rootCache: rootCacheKp.publicKey,
        authority: provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .signers([rootCacheKp])
      .rpc();
    console.log("✅ root_cache =", rootCacheKp.publicKey.toBase58());
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    if (!/already.*in use/i.test(msg)) throw e;
    console.log("ℹ️ root_cache already exists");
  }

  console.log("🎉 init complete");
}

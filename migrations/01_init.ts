/* eslint-disable @typescript-eslint/no-floating-promises */
import * as anchor from "@coral-xyz/anchor";
import { Program, web3, Idl } from "@coral-xyz/anchor";
import idlJson from "../target/idl/cipherpay_anchor.json";

const ROOT_CACHE_SEED = Buffer.from("root_cache");
const TREE_SEED = Buffer.from("tree");
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
  // @ts-ignore - circomlibjs has no types
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const F = (poseidon as any).F;
  const H2 = (a: bigint, b: bigint) => F.toObject(poseidon([a, b])) as bigint;

  let node = BigInt(0); // zero leaf
  for (let i = 0; i < depth; i++) node = H2(node, node);
  return toLeBytes32(node);
}

// ---------- exported entry (used by Anchor runner) ----------
export default async function run(provider: anchor.AnchorProvider) {
  anchor.setProvider(provider);

  // Choose program id: env override > IDL.address
  const idl = idlJson as unknown as Idl & { address?: string };
  const programIdStr = process.env.PROGRAM_ID || idl.address;
  if (!programIdStr) throw new Error("PROGRAM_ID not set and IDL.address missing.");
  (idl as any).address = programIdStr;

  const program = new Program(idl, provider);

  console.log("⚙️  network:", provider.connection.rpcEndpoint);
  console.log("🧭 programId:", program.programId.toBase58());

  const [treePda] = web3.PublicKey.findProgramAddressSync([TREE_SEED], program.programId);
  const [rootCachePda] = web3.PublicKey.findProgramAddressSync([ROOT_CACHE_SEED], program.programId);

  // ---- compute genesis root ----
  const depth = DEFAULT_DEPTH;
  let genesisRoot: Uint8Array;
  if (GENESIS_ROOT_OVERRIDE) {
    const n = bigFromString(GENESIS_ROOT_OVERRIDE);
    genesisRoot = toLeBytes32(n);
    console.log("🌱 using overridden genesis root:", "0x" + Buffer.from(genesisRoot).reverse().toString("hex"));
  } else {
    genesisRoot = await computeZeroRoot(depth);
    console.log("🌱 computed zero-tree root:", "0x" + Buffer.from(genesisRoot).reverse().toString("hex"));
  }

  // ---- Initialize TreeState (idempotent-ish) ----
  try {
    console.log("📦 initializeTreeState...");
    await program.methods
      .initializeTreeState(depth, Array.from(genesisRoot))
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

  // ---- Initialize Root Cache (PDA; zero-copy) ----
  // This uses `#[account(init, space=8+...)]` on an AccountLoader in Rust.
  try {
    console.log("📦 initializeRootCache (PDA)...");
    await program.methods
      .initializeRootCache()
      .accountsPartial({
        rootCache: rootCachePda,
        authority: provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    console.log("✅ root_cache =", rootCachePda.toBase58());
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    // If you prefer strict "first time only", drop this branch.
    if (!/already.*in use/i.test(msg)) throw e;
    console.log("ℹ️ root_cache already exists:", rootCachePda.toBase58());
  }

  console.log("🎉 init complete");
}

// ---------- CLI wrapper so `anchor run init` prints logs ----------
if (require.main === module) {
  (async () => {
    try {
      const provider = anchor.AnchorProvider.env();
      await run(provider);
    } catch (e) {
      console.error("❌ init script failed:", e);
      process.exit(1);
    }
  })();
}

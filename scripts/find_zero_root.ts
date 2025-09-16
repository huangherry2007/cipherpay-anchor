// scripts/find_zero_root.ts
// Usage: TS_NODE_TRANSPILE_ONLY=1 npx ts-node scripts/find_zero_root.ts 16
// Or compile with tsc and run `node`.

const depthArg = Number(process.argv[2] ?? 16);

function toLeBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  const FF = BigInt(0xff), E = BigInt(8);
  for (let i = 0; i < 32; i++) { out[i] = Number(x & FF); x >>= E; }
  return out;
}
const hexLE = (u8: Uint8Array) => "0x" + Buffer.from(u8).toString("hex");
const hexBE = (u8: Uint8Array) => "0x" + Buffer.from(u8).reverse().toString("hex");

// Try to build both Poseidon variants from circomlibjs
async function buildPoseidonVariant(variant: "poseidon" | "poseidon2") {
  // @ts-ignore
  const m = await import("circomlibjs");
  if (variant === "poseidon2") {
    if (typeof (m as any).buildPoseidon2 === "function") {
      return await (m as any).buildPoseidon2();
    }
    if (typeof (m as any).buildPoseidonReference === "function" && (m as any).poseidon2) {
      return await (m as any).buildPoseidonReference();
    }
    throw new Error("Poseidon2 builder not found in circomlibjs.");
  } else {
    if (typeof (m as any).buildPoseidon === "function") {
      return await (m as any).buildPoseidon();
    }
    if (typeof (m as any).buildPoseidonReference === "function") {
      return await (m as any).buildPoseidonReference();
    }
    throw new Error("Poseidon (classic) builder not found in circomlibjs.");
  }
}

async function computeZeroRoot(depth: number, variant: "poseidon" | "poseidon2") {
  const poseidon = await buildPoseidonVariant(variant);
  const F = (poseidon as any).F;
  const H2 = (a: bigint, b: bigint) => F.toObject(poseidon([a, b])) as bigint;

  const zeros: bigint[] = [BigInt(0)];
  for (let i = 1; i <= depth; i++) zeros[i] = H2(zeros[i - 1], zeros[i - 1]);

  const root = zeros[depth];
  const le = toLeBytes32(root);
  return { root, le, beHex: hexBE(le), leHex: hexLE(le) };
}

(async () => {
  console.log(`🔢 depth = ${depthArg}`);
  for (const v of ["poseidon", "poseidon2"] as const) {
    try {
      const { beHex, leHex } = await computeZeroRoot(depthArg, v);
      console.log(`\n— ${v.toUpperCase()} —`);
      console.log(`  zero-tree root (BE): ${beHex}`);
      console.log(`  zero-tree root (LE): ${leHex}`);
      console.log(`  exports to try:`);
      console.log(`    export CP_TREE_DEPTH=${depthArg}`);
      console.log(`    export CP_HASH_VARIANT=${v}`);
      console.log(`    export CP_GENESIS_ROOT=${beHex}`);
    } catch (e: any) {
      console.log(`\n— ${v.toUpperCase()} —`);
      console.log(`  ${e?.message ?? e}`);
    }
  }
})();

// scripts/find_zero_root.mjs
// Usage (from repo root):
//   node scripts/find_zero_root.mjs 16

const depthArg = Number(process.argv[2] ?? 16);

function toLeBytes32(n) {
  const out = new Uint8Array(32);
  let x = BigInt(n);
  const FF = 0xffn, E = 8n;
  for (let i = 0; i < 32; i++) { out[i] = Number(x & FF); x >>= E; }
  return out;
}
const hexLE = (u8) => "0x" + Buffer.from(u8).toString("hex");
const hexBE = (u8) => "0x" + Buffer.from(u8).reverse().toString("hex");

async function buildPoseidonVariant(variant) {
  const m = await import("circomlibjs");
  if (variant === "poseidon2") {
    if (typeof m.buildPoseidon2 === "function") return m.buildPoseidon2();
    if (typeof m.buildPoseidonReference === "function" && m.poseidon2) return m.buildPoseidonReference();
    throw new Error("Poseidon2 builder not found in circomlibjs.");
  } else {
    if (typeof m.buildPoseidon === "function") return m.buildPoseidon();
    if (typeof m.buildPoseidonReference === "function") return m.buildPoseidonReference();
    throw new Error("Poseidon (classic) builder not found in circomlibjs.");
  }
}

async function computeZeroRoot(depth, variant) {
  const poseidon = await buildPoseidonVariant(variant);
  const F = poseidon.F;
  const H2 = (a, b) => F.toObject(poseidon([a, b]));
  const zeros = [0n];
  for (let i = 1; i <= depth; i++) zeros[i] = H2(zeros[i - 1], zeros[i - 1]);
  const le = toLeBytes32(zeros[depth]);
  return { beHex: hexBE(le), leHex: hexLE(le) };
}

console.log(`🔢 depth = ${depthArg}`);
for (const v of ["poseidon", "poseidon2"]) {
  try {
    const { beHex, leHex } = await computeZeroRoot(depthArg, v);
    console.log(`\n— ${v.toUpperCase()} —`);
    console.log(`  zero-tree root (BE): ${beHex}`);
    console.log(`  zero-tree root (LE): ${leHex}`);
    console.log(`  exports to try:`);
    console.log(`    export CP_TREE_DEPTH=${depthArg}`);
    console.log(`    export CP_HASH_VARIANT=${v}`);
    console.log(`    export CP_GENESIS_ROOT=${beHex}`);
  } catch (e) {
    console.log(`\n— ${v.toUpperCase()} —`);
    console.log(`  ${e.message || e}`);
  }
}

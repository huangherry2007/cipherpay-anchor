// tests/deposit.ts
import * as fs from "fs";
import * as path from "path";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, web3 } from "@coral-xyz/anchor";
import { CipherpayAnchor } from "../target/types/cipherpay_anchor";

function readBin(p: string): Buffer {
  const abs = path.resolve(p);
  return fs.readFileSync(abs);
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
  const after = await connection.getBalance(pubkey);
  console.log(
    `✅ Airdropped ${((after - before) / web3.LAMPORTS_PER_SOL).toFixed(
      2
    )} SOL to test account, balance: ${(after / web3.LAMPORTS_PER_SOL).toFixed(
      2
    )} SOL`
  );
  return after;
}

describe("Shielded Deposit - Minimal ZK verification", () => {
  // Provider + Program
  const connection = new web3.Connection("http://127.0.0.1:8899", "confirmed");
  const wallet = new anchor.Wallet(
    web3.Keypair.fromSecretKey(
      Buffer.from(JSON.parse(fs.readFileSync(process.env.HOME + "/.config/solana/id.json", "utf8")))
    )
  );
  const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" });
  anchor.setProvider(provider);

  const program = anchor.workspace.CipherpayAnchor as Program<CipherpayAnchor>;
  const programId = program.programId;
  const payer = wallet.publicKey;

  // Paths (override via env if needed)
  const buildDir = process.env.DEPOSIT_BUILD_DIR
    ? path.resolve(process.env.DEPOSIT_BUILD_DIR)
    : path.resolve("proofs");
  const proofPath = path.join(buildDir, "deposit_proof.bin");
  const publicsPath = path.join(buildDir, "deposit_public_signals.bin");

  // CU limit (override via env CU_LIMIT)
  const CU_LIMIT = Number(process.env.CU_LIMIT ?? 800_000);

  let proofBytes: Buffer;
  let publicInputsBytes: Buffer;

  beforeAll(async () => {
    // Airdrop for local validator so fees & rent aren't an issue
    await ensureAirdrop(connection, payer, 10 * web3.LAMPORTS_PER_SOL);
    const bal = await connection.getBalance(payer);
    console.log(`💰 Current balance: ${(bal / web3.LAMPORTS_PER_SOL).toFixed(0)} SOL`);
  });

  it("loads proof & publics", () => {
    proofBytes = readBin(proofPath);
    publicInputsBytes = readBin(publicsPath);

    console.log("🔍 Loaded proof:\n");
    console.log("  • proof bytes:", proofBytes.length);
    console.log("  • pubinputs bytes:", publicInputsBytes.length);

    // Public signals (6): [newCommitment, owner, newRoot, nextIdx, amount, depositHash]
    const depositHashLE = slice32(publicInputsBytes, 5);
    console.log("  • deposit hash:", toHexLE(Buffer.from(depositHashLE)));

    expect(proofBytes.length).toBe(256);
    expect(publicInputsBytes.length).toBe(6 * 32);
  });

  it("verifies on-chain via shielded_deposit_atomic", async () => {
    const cuIx = web3.ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT });
    const feeIx = web3.ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 0 });

    try {
      const txSig = await program.methods
        .shieldedDepositAtomic(proofBytes, publicInputsBytes)
        .accounts({
          payer,
          // systemProgram is fixed in IDL; do not pass explicitly
        })
        .preInstructions([cuIx, feeIx])
        .rpc();

      console.log("✅ tx:", txSig);
    } catch (e: any) {
      console.error("❌ sendAndConfirm failed:", e?.message ?? e);
      if (e?.logs) {
        console.error("---- simulation logs start ----");
        for (const line of e.logs) console.error(line);
        console.error("---- simulation logs end ----");
      }
      throw e;
    }
  });

  it("validates real ZK proof structure (sanity)", () => {
    const a = proofBytes.subarray(0, 64);
    const b = proofBytes.subarray(64, 192);
    const c = proofBytes.subarray(192, 256);
    expect(a.length).toBe(64);
    expect(b.length).toBe(128);
    expect(c.length).toBe(64);
  });
});

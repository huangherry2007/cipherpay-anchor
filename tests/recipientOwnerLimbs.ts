// recipientOwnerLimbs.ts
import bs58 from "bs58";

/** Convert 16 bytes (little-endian) → bigint */
function leBytesToBigint(bytes: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < bytes.length; i++) {
    x += BigInt(bytes[i]) << (8n * BigInt(i));
  }
  return x;
}

/** Convert bigint → 16 bytes (little-endian) */
function bigintToLe16(x: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let v = x;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Split a base58 Solana pubkey (32 bytes) into two LE 128-bit limbs.
 * Returns decimal strings by default (what Circom JSON likes).
 */
export function recipientOwnerToLimbsLE(
  base58Pk: string,
  opts?: { as?: "string" | "bigint" }
): { lo: string | bigint; hi: string | bigint } {
  const as = opts?.as ?? "string";
  const raw = bs58.decode(base58Pk);
  if (raw.length !== 32) throw new Error("recipientOwner must decode to 32 bytes");

  // First 16 bytes = lo limb (LE); next 16 bytes = hi limb (LE)
  const loBi = leBytesToBigint(raw.slice(0, 16));
  const hiBi = leBytesToBigint(raw.slice(16, 32));

  if (as === "bigint") return { lo: loBi, hi: hiBi };
  return { lo: loBi.toString(10), hi: hiBi.toString(10) };
}

/**
 * Rebuild base58 pubkey from two LE 128-bit limbs (decimal strings or bigints).
 * Mirrors on-chain: bytes = lo[0..16] || hi[0..16]
 */
export function limbsToRecipientOwnerBase58(
  lo: string | bigint,
  hi: string | bigint
): string {
  const loBi = typeof lo === "bigint" ? lo : BigInt(lo);
  const hiBi = typeof hi === "bigint" ? hi : BigInt(hi);

  const lo16 = bigintToLe16(loBi);
  const hi16 = bigintToLe16(hiBi);

  const full = new Uint8Array(32);
  full.set(lo16, 0);
  full.set(hi16, 16);
  return bs58.encode(full);
}

/* --------- convenience helpers for circuit JSON wiring ---------- */

/** Produce fields ready to inject into your withdraw input JSON */
export function limbsForWithdrawInput(base58Pk: string) {
  const { lo, hi } = recipientOwnerToLimbsLE(base58Pk, { as: "string" });
  return { recipientOwner_lo: lo, recipientOwner_hi: hi };
}

/**
import { limbsForWithdrawInput, limbsToRecipientOwnerBase58 } from "./recipientOwnerLimbs";

const ownerB58 = "8VMCHPzwug9rYYudXkLNYTtAGN96ht4mXaqrxHrTijRg";

// → put these into the circuit input
const { recipientOwner_lo, recipientOwner_hi } = limbsForWithdrawInput(ownerB58);

// inverse check (optional)
const roundtrip = limbsToRecipientOwnerBase58(recipientOwner_lo, recipientOwner_hi);
console.log(roundtrip === ownerB58); // true
 
*/
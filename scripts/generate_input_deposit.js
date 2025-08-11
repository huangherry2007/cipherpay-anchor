// scripts/generate_input_deposit.js
// Run with: node scripts/generate_input_deposit.js

const fs = require("fs");
const { buildPoseidon } = require("circomlibjs");

// === CONFIG ===
const AMOUNT = "1000";
const NONCE = "12345"; // used as randomness
const TOKEN_ID = "1";
const MEMO = "42";
const OWNER_WALLET_PRIV_KEY = "3"; // string or hex
const OWNER_WALLET_PUB_KEY = "12345678901234567890123456789012"; // dummy pub key

// Helper function to calculate proper Merkle tree with actual internal node values
async function calculateValidMerkleTree(poseidon) {
  const F = poseidon.F;
  const fieldElementToBigIntString = (fe) => F.toString(fe);

  const DEPTH = 16;
  const TREE_SIZE = 2 ** DEPTH; // 65536 leaves
  
  console.log("🌳 Calculating Merkle tree with actual internal node values...");
  console.log(`   Tree depth: ${DEPTH}, Total leaves: ${TREE_SIZE}`);
  
  // Initialize all leaves as 0 (empty note commitments)
  const leaves = Array(TREE_SIZE).fill(BigInt(0));
  console.log("   All leaves initialized to 0 (empty note commitments)");
  
  // Calculate the complete tree level by level
  let currentLevel = leaves;
  const levels = [currentLevel]; // Store all levels for path calculation
  
  for (let level = 0; level < DEPTH; level++) {
    const nextLevel = [];
    console.log(`   Calculating level ${level + 1}...`);
    
    // Hash pairs of nodes to create the next level
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = currentLevel[i + 1];
      const hashResult = poseidon([left, right]);
      const hashValue = BigInt(fieldElementToBigIntString(hashResult));
      nextLevel.push(hashValue);
    }
    
    currentLevel = nextLevel;
    levels.push(currentLevel);
  }
  
  const merkleRoot = currentLevel[0].toString();
  console.log(`   ✅ Merkle root calculated: ${merkleRoot}`);
  
  // Calculate the path for inserting at index 0 (leftmost leaf)
  const leafIndex = 0;
  const pathElements = [];
  const pathIndices = [];
  
  console.log("🔍 Calculating Merkle path for leaf index 0...");
  
  let currentIndex = leafIndex;
  for (let level = 0; level < DEPTH; level++) {
    const isRightChild = currentIndex % 2 === 1;
    const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;
    const sibling = levels[level][siblingIndex];
    pathElements.push(sibling.toString());
    pathIndices.push(isRightChild ? "1" : "0");
    currentIndex = Math.floor(currentIndex / 2);
  }
  
  console.log(`   ✅ Path calculated with ${pathElements.length} elements`);
  
  return { pathElements, pathIndices, merkleRoot };
}

// === Step 1: Initialize Poseidon hash and calculate real values ===
async function generateInput() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const fieldElementToBigIntString = (fe) => F.toString(fe);
  
  // === Step 2: Calculate ownerCipherPayPubKey using Poseidon ===
  // This matches the circuit: ownerCipherPayPubKey = Poseidon(ownerWalletPubKey, ownerWalletPrivKey)
  const ownerCipherPayPubKeyResult = poseidon([
    BigInt(OWNER_WALLET_PUB_KEY), 
    BigInt(OWNER_WALLET_PRIV_KEY)
  ]);
  const ownerCipherPayPubKey = fieldElementToBigIntString(ownerCipherPayPubKeyResult);

  // === Step 3: Calculate randomness using Poseidon (optional mapping from nonce) ===
  // If you want randomness = NONCE directly, set: const randomness = NONCE;
  const randomness = NONCE;

  // === Step 4: Calculate depositHash using Poseidon ===
  // This matches the circuit: depositHash = Poseidon(ownerCipherPayPubKey, amount, nonce)
  // Use the field element result directly
  const depositHashResult = poseidon([
    ownerCipherPayPubKeyResult,
    BigInt(AMOUNT),
    BigInt(NONCE)
  ]);
  const depositHash = fieldElementToBigIntString(depositHashResult);

  // === Step 5: Calculate note commitment ===
  const noteCommitmentResult = poseidon([
    BigInt(AMOUNT),
    ownerCipherPayPubKeyResult, // Use field element
    BigInt(randomness),
    BigInt(TOKEN_ID),
    BigInt(MEMO)
  ]);
  const noteCommitment = fieldElementToBigIntString(noteCommitmentResult);
  
  // === Step 6: Create a valid Merkle tree state ===
  const { pathElements, pathIndices, merkleRoot } = await calculateValidMerkleTree(poseidon);
  // nextLeafIndex is an INDEX (position) where the new commitment will be placed
  const nextLeafIndex = "0"; // Insert at index 0

  // === Step 6: Create input_deposit.json matching circuit inputs ===
  const input = {
    // Private inputs (note preimage)
    ownerWalletPubKey: OWNER_WALLET_PUB_KEY,
    ownerWalletPrivKey: OWNER_WALLET_PRIV_KEY,
    randomness: randomness,
    tokenId: TOKEN_ID,
    memo: MEMO,
    inPathElements: pathElements,
    inPathIndices: pathIndices,
    
    // Public inputs
    nonce: NONCE,
    amount: AMOUNT,
    depositHash: depositHash,
    nextLeafIndex: nextLeafIndex,
  };

  // === Step 7: Save the file ===
  fs.writeFileSync("proofs/input_deposit.json", JSON.stringify(input, null, 2));
  console.log("✅ Generated proofs/input_deposit.json");
  console.log("📄 Input file contents:");
  console.log(JSON.stringify(input, null, 2));
  console.log("\n🔍 Key values:");
  console.log(`   ownerCipherPayPubKey (calculated): ${ownerCipherPayPubKey}`);
  console.log(`   depositHash (calculated): ${depositHash}`);
  console.log(`   randomness: ${randomness}`);
  console.log(`   merkleRoot (calculated): ${merkleRoot}`);
  console.log("\n📋 Circuit Input Mapping:");
  console.log(`   Private: ownerWalletPubKey, ownerWalletPrivKey, randomness, tokenId, memo, inPathElements[16], inPathIndices[16]`);
  console.log(`   Public: nonce, amount, depositHash, nextLeafIndex`);
  console.log(`   Output: newCommitment, ownerCipherPayPubKey, merkleRoot`);
  console.log("\n🌳 Merkle Tree Info:");
  console.log("   - All leaves start as 0 (empty note commitments)");
  console.log("   - Internal nodes calculated using Poseidon hash");
  console.log("   - Path calculated for inserting at leaf index 0");
  console.log("   - This represents a valid empty tree state");
}

// Run the async function
generateInput().catch(console.error);

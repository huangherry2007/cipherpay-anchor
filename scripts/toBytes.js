// scripts/toBytes.js
// Run with: node scripts/toBytes.js <input_json> <output_bin>

const fs = require("fs");

if (process.argv.length !== 4) {
  console.error("Usage: node scripts/toBytes.js <input_json> <output_bin>");
  process.exit(1);
}

const inputFile = process.argv[2];
const outputFile = process.argv[3];

try {
  // Read the JSON proof file
  const proofData = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
  
  // Convert the proof to binary format
  // This is a simplified version - in production you'd need proper serialization
  const binaryData = Buffer.from(JSON.stringify(proofData), 'utf8');
  
  // Write the binary file
  fs.writeFileSync(outputFile, binaryData);
  
  console.log(`✅ Converted ${inputFile} to ${outputFile}`);
  console.log(`📊 File size: ${binaryData.length} bytes`);
  
} catch (error) {
  console.error("❌ Error:", error.message);
  process.exit(1);
}

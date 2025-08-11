// scripts/extractPublicInputs.js
// Run with: node scripts/extractPublicInputs.js <input_json> <output_json>

const fs = require("fs");

if (process.argv.length !== 4) {
  console.error("Usage: node scripts/extractPublicInputs.js <input_json> <output_json>");
  process.exit(1);
}

const inputFile = process.argv[2];
const outputFile = process.argv[3];

try {
  // Read the proof file
  const proofData = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
  
  // Extract public signals
  const publicInputs = proofData.publicSignals || proofData.public_inputs || [];
  
  // Write the public inputs to a separate file
  fs.writeFileSync(outputFile, JSON.stringify(publicInputs, null, 2));
  
  console.log(`✅ Extracted public inputs from ${inputFile} to ${outputFile}`);
  console.log(`📊 Number of public signals: ${publicInputs.length}`);
  console.log("📄 Public signals:");
  console.log(JSON.stringify(publicInputs, null, 2));
  
} catch (error) {
  console.error("❌ Error:", error.message);
  process.exit(1);
}

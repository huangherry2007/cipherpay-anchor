const fs = require('fs');
const path = require('path');

// Fix the IDL file by adding missing type fields
function fixIdlFile() {
  console.log('🔧 Fixing IDL file by adding missing type fields...');
  
  const idlPath = path.resolve(__dirname, '../target/idl/cipherpay_anchor.json');
  const idlContent = fs.readFileSync(idlPath, 'utf8');
  const idl = JSON.parse(idlContent);
  
  // Fix accounts section (only the program accounts, not instruction accounts)
  if (idl.accounts) {
    idl.accounts = idl.accounts.map(account => {
      if (account.name === "MerkleRootCache") {
        return {
          ...account,
          size: 4 + (1024 * 32), // 4 bytes for vec length + MAX_ROOTS * 32 bytes
          type: {
            kind: "account",
            fields: [
              {
                name: "roots",
                type: {
                  vec: {
                    array: ["u8", 32]
                  }
                }
              }
            ]
          }
        };
      } else if (account.name === "Nullifier") {
        return {
          ...account,
          size: 2, // bool + u8
          type: {
            kind: "account",
            fields: [
              {
                name: "used",
                type: "bool"
              },
              {
                name: "bump",
                type: "u8"
              }
            ]
          }
        };
      } else {
        return {
          ...account,
          size: 0, // Default size for unknown accounts
          type: {
            kind: "account",
            fields: []
          }
        };
      }
    });
  }
  
  // Fix events section
  if (idl.events) {
    idl.events = idl.events.map(event => ({
      ...event,
      type: {
        kind: "event",
        fields: []
      }
    }));
  }
  
  // Write the fixed IDL back to file
  fs.writeFileSync(idlPath, JSON.stringify(idl, null, 2));
  
  console.log('✅ IDL file fixed successfully!');
  console.log(`📄 Fixed IDL saved to: ${idlPath}`);
}

// Run the script
if (require.main === module) {
  fixIdlFile();
}

module.exports = { fixIdlFile };

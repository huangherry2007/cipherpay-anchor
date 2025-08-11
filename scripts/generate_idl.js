const fs = require('fs');
const path = require('path');

// Generate IDL based on the program structure
const idl = {
  "version": "0.1.0",
  "name": "cipherpay_anchor",
  "instructions": [
    {
      "name": "initializeVault",
      "accounts": [
        {
          "name": "vault",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "authority",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "depositTokens",
      "accounts": [
        {
          "name": "user",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "vault",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "tokenMint",
          "isMut": false,
          "isSigner": false
        },
        {
          "name": "userTokenAccount",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "vaultTokenAccount",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "tokenProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "depositHash",
          "type": {
            "vec": "u8"
          }
        }
      ]
    },
    {
      "name": "shieldedDeposit",
      "accounts": [
        {
          "name": "vault",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "rootCache",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "depositHash",
          "type": {
            "vec": "u8"
          }
        },
        {
          "name": "proofBytes",
          "type": {
            "vec": "u8"
          }
        },
        {
          "name": "publicInputsBytes",
          "type": {
            "vec": "u8"
          }
        }
      ]
    },
    {
      "name": "shieldedTransfer",
      "accounts": [
        {
          "name": "vault",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "rootCache",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "nullifierRecord",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "nullifier",
          "type": {
            "vec": "u8"
          }
        },
        {
          "name": "proofBytes",
          "type": {
            "vec": "u8"
          }
        },
        {
          "name": "publicInputsBytes",
          "type": {
            "vec": "u8"
          }
        }
      ]
    },
    {
      "name": "shieldedWithdraw",
      "accounts": [
        {
          "name": "vault",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "rootCache",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "nullifierRecord",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "nullifier",
          "type": {
            "vec": "u8"
          }
        },
        {
          "name": "proofBytes",
          "type": {
            "vec": "u8"
          }
        },
        {
          "name": "publicInputsBytes",
          "type": {
            "vec": "u8"
          }
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "Vault",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "authority",
            "type": "publicKey"
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "MerkleRootCache",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "roots",
            "type": {
              "vec": {
                "array": [
                  "u8",
                  32
                ]
              }
            }
          }
        ]
      }
    },
    {
      "name": "Nullifier",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "nullifier",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    }
  ],
  "events": [
    {
      "name": "DepositCompleted",
      "fields": [
        {
          "name": "depositHash",
          "type": {
            "array": [
              "u8",
              32
            ]
          },
          "index": false
        },
        {
          "name": "commitment",
          "type": {
            "array": [
              "u8",
              32
            ]
          },
          "index": false
        },
        {
          "name": "ownerCipherpayPubkey",
          "type": {
            "array": [
              "u8",
              32
            ]
          },
          "index": false
        }
      ]
    },
    {
      "name": "TransferCompleted",
      "fields": [
        {
          "name": "nullifier",
          "type": {
            "array": [
              "u8",
              32
            ]
          },
          "index": false
        },
        {
          "name": "newCommitment",
          "type": {
            "array": [
              "u8",
              32
            ]
          },
          "index": false
        },
        {
          "name": "ownerCipherpayPubkey",
          "type": {
            "array": [
              "u8",
              32
            ]
          },
          "index": false
        }
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "InvalidZkProof",
      "msg": "Invalid zero-knowledge proof"
    },
    {
      "code": 6001,
      "name": "DepositAlreadyUsed",
      "msg": "Deposit hash already used"
    },
    {
      "code": 6002,
      "name": "UnknownMerkleRoot",
      "msg": "Unknown merkle root"
    },
    {
      "code": 6003,
      "name": "NullifierAlreadyUsed",
      "msg": "Nullifier already used"
    }
  ]
};

// Create target/idl directory if it doesn't exist
const idlDir = path.join(__dirname, '../target/idl');
if (!fs.existsSync(idlDir)) {
  fs.mkdirSync(idlDir, { recursive: true });
}

// Write the IDL file
const idlPath = path.join(idlDir, 'cipherpay_anchor.json');
fs.writeFileSync(idlPath, JSON.stringify(idl, null, 2));

console.log(`✅ Generated IDL file: ${idlPath}`);

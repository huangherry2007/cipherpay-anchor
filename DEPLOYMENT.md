# CipherPay Anchor Program Deployment Guide

This guide explains how to build, test, and deploy the CipherPay Anchor smart contract to Solana devnet, testnet, or mainnet using Anchor.

---

## 1. Prerequisites

- **Rust**: Install via [rustup](https://rustup.rs/)
- **Solana CLI**: [Install instructions](https://docs.solana.com/cli/install-solana-cli-tools)
- **Anchor CLI**: `cargo install --git https://github.com/coral-xyz/anchor avm --locked --force`
- **Node.js**: For Anchor test runner (v16+ recommended)
- **Yarn or npm**: For JS dependencies
- **Solana Wallet**: Funded with SOL for deployment fees

---

## 2. Setup

```sh
# Clone the repository
$ git clone <repo-url>
$ cd cipherpay-anchor

# Install Rust dependencies
$ cargo build

# Install Anchor (if not already installed)
$ avm install latest
$ avm use latest

# Install JS dependencies (if using Anchor tests)
$ yarn install  # or npm install
```

---

## 3. Build & Test

```sh
# Build the program
$ anchor build

# Run Rust unit tests
$ cargo test

# Run Anchor integration tests (if present)
$ anchor test
```

---

## 4. Deploy

```sh
# Set the Solana cluster (devnet, testnet, or mainnet)
$ solana config set --url devnet

# (Optional) Set your keypair
$ solana config set --keypair ~/.config/solana/id.json

# Deploy the program
$ anchor deploy
```

- The program ID will be printed after deployment. Save it for client integration.

---

## 5. Verify Deployment

```sh
# Check program status
$ solana program show <PROGRAM_ID>

# View on Solana Explorer
https://explorer.solana.com/address/<PROGRAM_ID>?cluster=devnet
```

---

## 6. Upgrade the Program

```sh
# Make code changes, then rebuild
$ anchor build

# Upgrade the deployed program
$ anchor upgrade target/deploy/cipherpay_anchor.so --program-id <PROGRAM_ID>
```

---

## 7. Troubleshooting

- **Not enough SOL**: Airdrop on devnet: `solana airdrop 2`
- **Program failed to deploy**: Check build output and logs for errors
- **Account size errors**: Ensure account space matches struct size
- **Anchor.toml errors**: Double-check `[programs]` and `[provider]` sections
- **Cluster mismatch**: Ensure your CLI and Anchor cluster settings match

---

## References
- [Solana Docs](https://docs.solana.com/)
- [Anchor Book](https://book.anchor-lang.com/)
- [Solana Explorer](https://explorer.solana.com/)

---

For further help, open an issue or contact the CipherPay team. 
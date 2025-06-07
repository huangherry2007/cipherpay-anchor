import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import { Cipherpay } from "../target/types/cipherpay";
import { expect } from "chai";
import { PublicKey } from "@solana/web3.js";

describe("cipherpay", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Cipherpay as Program<Cipherpay>;
  const verifierState = anchor.web3.Keypair.generate();
  const authority = provider.wallet;

  it("Initializes the program", async () => {
    const merkleRoot = Buffer.alloc(32, 1); // Example merkle root

    await program.methods
      .initialize(merkleRoot)
      .accounts({
        verifierState: verifierState.publicKey,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([verifierState])
      .rpc();

    const state = await program.account.verifierState.fetch(verifierState.publicKey);
    expect(state.merkleRoot).to.deep.equal(merkleRoot);
    expect(state.authority).to.deep.equal(authority.publicKey);
    expect(state.isInitialized).to.be.true;
  });

  it("Verifies a transfer proof", async () => {
    const proof = {
      proofA: Buffer.alloc(64, 1),
      proofB: Buffer.alloc(128, 1),
      proofC: Buffer.alloc(64, 1),
      publicInputs: Buffer.alloc(32, 1),
    };
    const amount = new anchor.BN(1000000);
    const recipient = new PublicKey("11111111111111111111111111111111");

    await program.methods
      .verifyTransferProof(proof, amount, recipient)
      .accounts({
        verifierState: verifierState.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const state = await program.account.verifierState.fetch(verifierState.publicKey);
    expect(state.totalVerified).to.equal(1);
  });

  it("Verifies a stream proof", async () => {
    const proof = {
      proofA: Buffer.alloc(64, 1),
      proofB: Buffer.alloc(128, 1),
      proofC: Buffer.alloc(64, 1),
      publicInputs: Buffer.alloc(32, 1),
    };
    const streamParams = {
      streamId: Buffer.alloc(32, 1),
      startTime: new anchor.BN(Date.now() / 1000),
      endTime: new anchor.BN(Date.now() / 1000 + 3600),
      totalAmount: new anchor.BN(1000000),
    };

    const streamState = anchor.web3.Keypair.generate();

    await program.methods
      .verifyStreamProof(proof, streamParams)
      .accounts({
        streamState: streamState.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([streamState])
      .rpc();

    const state = await program.account.streamState.fetch(streamState.publicKey);
    expect(state.totalVerified).to.equal(1);
  });

  it("Verifies a split proof", async () => {
    const proof = {
      proofA: Buffer.alloc(64, 1),
      proofB: Buffer.alloc(128, 1),
      proofC: Buffer.alloc(64, 1),
      publicInputs: Buffer.alloc(32, 1),
    };
    const splitParams = {
      splitId: Buffer.alloc(32, 1),
      recipients: [
        new PublicKey("11111111111111111111111111111111"),
        new PublicKey("22222222222222222222222222222222"),
      ],
      amounts: [new anchor.BN(500000), new anchor.BN(500000)],
    };

    const splitState = anchor.web3.Keypair.generate();

    await program.methods
      .verifySplitProof(proof, splitParams)
      .accounts({
        splitState: splitState.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([splitState])
      .rpc();

    const state = await program.account.splitState.fetch(splitState.publicKey);
    expect(state.lastVerifiedTime).to.be.greaterThan(0);
  });

  it("Fails with invalid proof format", async () => {
    const invalidProof = {
      proofA: Buffer.alloc(32, 1), // Invalid length
      proofB: Buffer.alloc(128, 1),
      proofC: Buffer.alloc(64, 1),
      publicInputs: Buffer.alloc(32, 1),
    };
    const amount = new anchor.BN(1000000);
    const recipient = new PublicKey("11111111111111111111111111111111");

    try {
      await program.methods
        .verifyTransferProof(invalidProof, amount, recipient)
        .accounts({
          verifierState: verifierState.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      expect.fail("Expected error was not thrown");
    } catch (error) {
      expect(error.toString()).to.include("InvalidProofFormat");
    }
  });

  it("Fails with expired stream", async () => {
    const proof = {
      proofA: Buffer.alloc(64, 1),
      proofB: Buffer.alloc(128, 1),
      proofC: Buffer.alloc(64, 1),
      publicInputs: Buffer.alloc(32, 1),
    };
    const streamParams = {
      streamId: Buffer.alloc(32, 1),
      startTime: new anchor.BN(Date.now() / 1000 - 7200), // 2 hours ago
      endTime: new anchor.BN(Date.now() / 1000 - 3600), // 1 hour ago
      totalAmount: new anchor.BN(1000000),
    };

    const streamState = anchor.web3.Keypair.generate();

    try {
      await program.methods
        .verifyStreamProof(proof, streamParams)
        .accounts({
          streamState: streamState.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([streamState])
        .rpc();
      expect.fail("Expected error was not thrown");
    } catch (error) {
      expect(error.toString()).to.include("StreamExpired");
    }
  });

  it("Initializes the program with shielded vault", async () => {
    const merkleRoot = Buffer.alloc(32, 1);
    const vaultMerkleRoot = Buffer.alloc(32, 2);

    await program.methods
      .initialize(merkleRoot)
      .accounts({
        verifierState: verifierState.publicKey,
        shieldedVault: vaultState.publicKey,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([verifierState, vaultState])
      .rpc();

    const vault = await program.account.shieldedVault.fetch(vaultState.publicKey);
    expect(vault.merkleRoot).to.deep.equal(vaultMerkleRoot);
    expect(vault.authority).to.deep.equal(authority.publicKey);
    expect(vault.isInitialized).to.be.true;
    expect(vault.totalDeposited).to.equal(0);
    expect(vault.totalWithdrawn).to.equal(0);
  });

  it("Deposits to shielded vault", async () => {
    const amount = new anchor.BN(1000000);
    const merkleProof = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];

    await program.methods
      .depositToVault(amount, merkleProof)
      .accounts({
        shieldedVault: vaultState.publicKey,
        tokenAccount: tokenAccount.publicKey,
        authority: authority.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vault = await program.account.shieldedVault.fetch(vaultState.publicKey);
    expect(vault.totalDeposited).to.equal(amount);
  });

  it("Withdraws from shielded vault", async () => {
    const amount = new anchor.BN(500000);
    const merkleProof = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];

    await program.methods
      .withdrawFromVault(amount, merkleProof)
      .accounts({
        shieldedVault: vaultState.publicKey,
        tokenAccount: tokenAccount.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vault = await program.account.shieldedVault.fetch(vaultState.publicKey);
    expect(vault.totalWithdrawn).to.equal(amount);
  });

  it("Fails to withdraw more than deposited", async () => {
    const amount = new anchor.BN(2000000); // More than deposited
    const merkleProof = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];

    try {
      await program.methods
        .withdrawFromVault(amount, merkleProof)
        .accounts({
          shieldedVault: vaultState.publicKey,
          tokenAccount: tokenAccount.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      expect.fail("Expected error was not thrown");
    } catch (error) {
      expect(error.toString()).to.include("InsufficientFunds");
    }
  });
}); 
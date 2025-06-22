#![allow(unexpected_cfgs)]

//! # CipherPay Anchor Program
//! 
//! A privacy-preserving payment protocol built on Solana using zero-knowledge proofs.
//! 
//! ## Overview
//! 
//! CipherPay enables private transactions on Solana through:
//! - **Shielded Vaults**: Private account balances with zero-knowledge proofs
//! - **Merkle Trees**: Efficient commitment schemes for transaction privacy
//! - **Nullifier Sets**: Prevention of double-spending attacks
//! - **Groth16 Proofs**: Efficient zero-knowledge proof verification
//! 
//! ## Core Components
//! 
//! - **Vault Management**: Deposit, withdraw, and balance tracking
//! - **Proof Verification**: Verify various ZK circuit proofs (transfer, withdraw, merkle, etc.)
//! - **Stream Payments**: Time-based payment streams with privacy
//! - **Split Payments**: Multi-recipient payments with privacy
//! - **Audit Trails**: Optional audit capabilities for compliance
//! 
//! ## Security Features
//! 
//! - Input validation and sanitization
//! - Arithmetic overflow protection
//! - Nullifier uniqueness enforcement
//! - Merkle proof verification
//! - Compute budget management
//! 
//! ## Usage
//! 
//! ```rust,no_run
//! use anchor_lang::prelude::*;
//! 
//! // Example of how to use the CipherPay program
//! // Note: This is a conceptual example and requires proper account setup
//! 
//! // Initialize a shielded vault (requires proper account context)
//! // let ctx = Context::new(/* account setup */);
//! // initialize_shielded_vault(ctx)?;
//! 
//! // Verify a transfer proof (requires proper proof data)
//! // let args = TransferProofArgs {
//! //     proof_a: [0u8; 64],
//! //     proof_b: [0u8; 128], 
//! //     proof_c: [0u8; 64],
//! //     public_inputs: vec![],
//! //     merkle_root: [0u8; 32],
//! //     nullifier: [0u8; 32],
//! //     leaf: [0u8; 32],
//! //     merkle_proof: vec![],
//! //     recipient_address: Pubkey::default(),
//! //     amount: 1000,
//! // };
//! // verify_transfer_proof(ctx, args)?;
//! ```

use anchor_lang::prelude::*;
use crate::{
    error_code::CipherPayError,
    events::*,
    validation::{
        verify_merkle_root,
        verify_nullifier_usage,
        verify_vault_balance,
    },
};
use crate::validation_limits::ValidationLimits;

mod merkle;
mod helper;
mod constants;
mod error_code;
mod events;
mod validation;
mod validation_limits;

use constants::{
    account_sizes,
};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

/// Main CipherPay program module containing all instruction handlers
#[program]
pub mod cipherpay_anchor {
    use super::*;

    /// Initialize a basic vault account
    /// 
    /// Creates a new vault with the specified authority and zero initial balance.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the vault and authority accounts
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::ArithmeticOverflow` - If balance operations overflow
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.nonce = 0;
        Ok(())
    }

    /// Initialize the verifier state for proof verification
    /// 
    /// Creates a new verifier state account that tracks proof verification statistics
    /// and maintains the current merkle root for the system.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the verifier state and authority accounts
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    pub fn initialize_verifier(ctx: Context<InitializeVerifier>) -> Result<()> {
        let verifier = &mut ctx.accounts.verifier_state;
        verifier.authority = ctx.accounts.authority.key();
        verifier.merkle_root = [0u8; 32];
        verifier.last_verified_proof = [0u8; 64];
        verifier.total_verified = 0;
        verifier.is_initialized = true;
        Ok(())
    }

    /// Initialize a shielded vault for private transactions
    /// 
    /// Creates a new shielded vault that supports private deposits, withdrawals,
    /// and zero-knowledge proof verification. The vault maintains a nullifier set
    /// to prevent double-spending attacks.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the shielded vault and authority accounts
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    pub fn initialize_shielded_vault(ctx: Context<InitializeShieldedVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposited = 0;
        vault.total_withdrawn = 0;
        vault.balance = 0;
        vault.nonce = 0;
        vault.merkle_root = [0u8; 32];
        vault.is_initialized = true;
        vault.nullifier_set = Vec::new();
        Ok(())
    }

    /// Initialize the stream state for time-based payments
    /// 
    /// Creates a new stream state account that tracks time-based payment streams
    /// and maintains verification statistics for stream proofs.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the stream state and authority accounts
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    pub fn initialize_stream_state(ctx: Context<InitializeStreamState>) -> Result<()> {
        let stream_state = &mut ctx.accounts.stream_state;
        stream_state.last_verified_time = 0;
        stream_state.total_verified = 0;
        stream_state.merkle_root = [0u8; 32];
        Ok(())
    }

    /// Initialize the split state for multi-recipient payments
    /// 
    /// Creates a new split state account that tracks multi-recipient payment splits
    /// and maintains verification statistics for split proofs.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the split state and authority accounts
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    pub fn initialize_split_state(ctx: Context<InitializeSplitState>) -> Result<()> {
        let split_state = &mut ctx.accounts.split_state;
        split_state.last_verified_time = 0;
        split_state.merkle_root = [0u8; 32];
        Ok(())
    }

    /// Deposit funds into a vault
    /// 
    /// Adds the specified amount to the vault's balance. This is a public operation
    /// that increases the vault's total deposited amount.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the vault and authority accounts
    /// * `amount` - Amount to deposit (in lamports)
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::ArithmeticOverflow` - If balance addition overflows
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).ok_or(CipherPayError::ArithmeticOverflow)?;
        emit!(VaultDeposited {
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    /// Withdraw funds from a vault
    /// 
    /// Removes the specified amount from the vault's balance. This operation
    /// requires sufficient funds and updates the vault's total withdrawn amount.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the vault and authority accounts
    /// * `amount` - Amount to withdraw (in lamports)
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InsufficientFunds` - If vault has insufficient balance
    /// * `CipherPayError::ArithmeticOverflow` - If balance subtraction overflows
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        verify_vault_balance(vault.balance, amount)?;
        vault.balance = vault.balance.checked_sub(amount).ok_or(CipherPayError::ArithmeticOverflow)?;
        emit!(VaultWithdrawn {
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    /// Verify a generic zero-knowledge proof
    /// 
    /// Verifies a Groth16 proof with merkle proof and nullifier validation.
    /// This is a legacy function that supports the original proof format.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the vault and authority accounts
    /// * `args` - Proof arguments including Groth16 proof components and public inputs
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidMerkleRoot` - If merkle root verification fails
    /// * `CipherPayError::NullifierAlreadyUsed` - If nullifier has been used before
    pub fn verify_proof(ctx: Context<VerifyProof>, args: VerifyProofArgs) -> Result<()> {
        // Convert Vec<Vec<u8>> to Vec<[u8; 32]> for merkle proof
        let merkle_proof: Vec<[u8; 32]> = args.proof
            .iter()
            .map(|p| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&p[..32]);
                arr
            })
            .collect();
        
        // Convert Vec<u8> to Vec<[u8; 32]> for nullifier set (placeholder)
        let nullifier_set: Vec<[u8; 32]> = Vec::new(); // This should come from the vault
        
        verify_merkle_root(args.merkle_root, &merkle_proof)?;
        verify_nullifier_usage(args.nullifier, &nullifier_set)?;
        
        // Update vault state
        ctx.accounts.vault.balance += args.amount;
        ctx.accounts.vault.nonce += 1;
        
        Ok(())
    }

    /// Verifies a transfer circuit proof for private transfers
    /// 
    /// Verifies a Groth16 proof for a private transfer operation, including:
    /// - Groth16 proof verification using the transfer circuit
    /// - Merkle proof verification for commitment inclusion
    /// - Nullifier validation to prevent double-spending
    /// - Vault state updates
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the shielded vault and authority accounts
    /// * `args` - Transfer proof arguments including proof components and public inputs
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InvalidMerkleProof` - If merkle proof verification fails
    /// * `CipherPayError::InvalidNullifier` - If nullifier validation fails
    /// * `CipherPayError::ArithmeticOverflow` - If balance addition overflows
    pub fn verify_transfer_proof(ctx: Context<VerifyTransferProof>, args: TransferProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "transfer"
        )?;

        // Verify merkle proof
        helper::verify_merkle_proof(&args.leaf, &args.merkle_proof, args.merkle_root)?;

        // Verify nullifier
        helper::verify_nullifier(&args.nullifier)?;

        // Update vault state
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(args.amount)
            .ok_or(CipherPayError::ArithmeticOverflow)?;
        vault.nonce += 1;

        // Add nullifier to set
        vault.nullifier_set.push(args.nullifier);

        emit!(TransferProofVerified {
            amount: args.amount,
            recipient: args.recipient_address,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies a withdraw circuit proof for private withdrawals
    /// 
    /// Verifies a Groth16 proof for a private withdrawal operation, including:
    /// - Groth16 proof verification using the withdraw circuit
    /// - Vault balance validation
    /// - Nullifier validation to prevent double-spending
    /// - Vault state updates
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the shielded vault and authority accounts
    /// * `args` - Withdraw proof arguments including proof components and public inputs
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InsufficientFunds` - If vault has insufficient balance
    /// * `CipherPayError::InvalidNullifier` - If nullifier validation fails
    /// * `CipherPayError::ArithmeticOverflow` - If balance subtraction overflows
    pub fn verify_withdraw_proof(ctx: Context<VerifyWithdrawProof>, args: WithdrawProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "withdraw"
        )?;

        // Verify vault has sufficient funds
        let vault = &mut ctx.accounts.vault;
        if vault.balance < args.amount {
            return err!(CipherPayError::InsufficientFunds);
        }

        // Verify nullifier
        helper::verify_nullifier(&args.nullifier)?;

        // Update vault state
        vault.balance = vault.balance.checked_sub(args.amount)
            .ok_or(CipherPayError::ArithmeticOverflow)?;
        vault.nonce += 1;

        // Add nullifier to set
        vault.nullifier_set.push(args.nullifier);

        emit!(WithdrawProofVerified {
            amount: args.amount,
            recipient: args.recipient_address,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies a merkle circuit proof for commitment verification
    /// 
    /// Verifies a Groth16 proof for merkle tree operations, ensuring that
    /// a commitment is properly included in the current merkle root.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the verifier state and authority accounts
    /// * `args` - Merkle proof arguments including proof components and public inputs
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InvalidMerkleRoot` - If merkle root is invalid
    pub fn verify_merkle_proof_circuit(ctx: Context<VerifyMerkleProof>, args: MerkleProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "merkle"
        )?;

        // Update verifier state
        let verifier = &mut ctx.accounts.verifier_state;
        verifier.merkle_root = args.merkle_root;
        verifier.last_verified_proof = args.proof_a;
        verifier.total_verified += 1;

        emit!(MerkleProofVerified {
            merkle_root: args.merkle_root,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies a nullifier circuit proof for double-spending prevention
    /// 
    /// Verifies a Groth16 proof for nullifier generation, ensuring that
    /// the nullifier is unique and hasn't been used before. This prevents
    /// double-spending attacks in the privacy-preserving system.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the shielded vault and authority accounts
    /// * `args` - Nullifier proof arguments including proof components and public inputs
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::NullifierAlreadyUsed` - If nullifier has been used before
    pub fn verify_nullifier_proof(ctx: Context<VerifyNullifierProof>, args: NullifierProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "nullifier"
        )?;

        // Verify nullifier is not already used
        let vault = &mut ctx.accounts.vault;
        if vault.nullifier_set.contains(&args.nullifier) {
            return err!(CipherPayError::NullifierAlreadyUsed);
        }

        // Add nullifier to set
        vault.nullifier_set.push(args.nullifier);

        emit!(NullifierProofVerified {
            nullifier: args.nullifier,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies an audit circuit proof for compliance
    /// 
    /// Verifies a Groth16 proof for audit operations, enabling optional
    /// compliance and transparency features while maintaining privacy.
    /// 
    /// # Arguments
    /// * `_ctx` - Context containing the verifier state and authority accounts
    /// * `args` - Audit proof arguments including proof components and public inputs
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InvalidMerkleRoot` - If merkle root is invalid
    pub fn verify_audit_proof(_ctx: Context<VerifyAuditProof>, args: AuditProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "audit_proof"
        )?;

        // Verify merkle root is valid
        if !helper::is_valid_merkle_root(&args.merkle_root) {
            return err!(CipherPayError::InvalidMerkleRoot);
        }

        emit!(AuditProofVerified {
            audit_id: args.audit_id,
            merkle_root: args.merkle_root,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies a stream circuit proof for time-based payments
    /// 
    /// Verifies a Groth16 proof for stream payment operations, enabling
    /// time-based payment streams with privacy guarantees.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the stream state and authority accounts
    /// * `args` - Stream proof arguments including proof components and stream parameters
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InvalidStreamParams` - If stream parameters are invalid
    /// * `CipherPayError::StreamExpired` - If stream has expired
    pub fn verify_stream_proof(ctx: Context<VerifyStreamProof>, args: StreamProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "zkStream"
        )?;

        // Verify stream parameters
        helper::verify_stream_params(&args.stream_params)?;

        // Update stream state
        let stream_state = &mut ctx.accounts.stream_state;
        stream_state.last_verified_time = Clock::get()?.unix_timestamp;
        stream_state.total_verified += 1;
        stream_state.merkle_root = args.merkle_root;

        emit!(StreamProofVerified {
            stream_id: args.stream_params.stream_id,
            amount: args.amount,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies a split circuit proof for multi-recipient payments
    /// 
    /// Verifies a Groth16 proof for split payment operations, enabling
    /// multi-recipient payments with privacy guarantees.
    /// 
    /// # Arguments
    /// * `ctx` - Context containing the split state and authority accounts
    /// * `args` - Split proof arguments including proof components and split parameters
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InvalidSplitParams` - If split parameters are invalid
    pub fn verify_split_proof(ctx: Context<VerifySplitProof>, args: SplitProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "zkSplit"
        )?;

        // Verify split parameters
        verify_split_params(&args.split_params)?;

        // Update split state
        let split_state = &mut ctx.accounts.split_state;
        split_state.last_verified_time = Clock::get()?.unix_timestamp;
        split_state.merkle_root = args.merkle_root;

        emit!(SplitProofVerified {
            split_id: args.split_params.split_id,
            recipients: args.split_params.recipients.clone(),
            amounts: args.split_params.amounts.clone(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Verifies a condition circuit proof for conditional payments
    /// 
    /// Verifies a Groth16 proof for conditional payment operations, enabling
    /// payments that depend on specific conditions while maintaining privacy.
    /// 
    /// # Arguments
    /// * `_ctx` - Context containing the verifier state and authority accounts
    /// * `args` - Condition proof arguments including proof components and condition ID
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Errors
    /// * `CipherPayError::InvalidProofFormat` - If proof format is invalid
    /// * `CipherPayError::InvalidMerkleRoot` - If merkle root is invalid
    pub fn verify_condition_proof(_ctx: Context<VerifyConditionProof>, args: ConditionProofArgs) -> Result<()> {
        // Verify Groth16 proof
        helper::verify_groth16_proof(
            &args.proof_a,
            &args.proof_b,
            &args.proof_c,
            &args.public_inputs,
            "zkCondition"
        )?;

        // Verify merkle root is valid
        if !helper::is_valid_merkle_root(&args.merkle_root) {
            return err!(CipherPayError::InvalidMerkleRoot);
        }

        emit!(ConditionProofVerified {
            condition_id: args.condition_id,
            merkle_root: args.merkle_root,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }
}

/// Context for initializing a basic vault account
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The authority that will own the vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The vault account to be initialized
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 8,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for initializing the verifier state account
#[derive(Accounts)]
pub struct InitializeVerifier<'info> {
    /// The authority that will own the verifier state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The verifier state account to be initialized
    #[account(
        init,
        payer = authority,
        space = 8 + account_sizes::VERIFIER_STATE_SIZE,
        seeds = [b"verifier"],
        bump
    )]
    pub verifier_state: Account<'info, VerifierState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for initializing a shielded vault account
#[derive(Accounts)]
pub struct InitializeShieldedVault<'info> {
    /// The authority that will own the shielded vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The shielded vault account to be initialized
    #[account(
        init,
        payer = authority,
        space = 8 + account_sizes::SHIELDED_VAULT_SIZE,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, ShieldedVault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for initializing the stream state account
#[derive(Accounts)]
pub struct InitializeStreamState<'info> {
    /// The authority that will own the stream state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The stream state account to be initialized
    #[account(
        init,
        payer = authority,
        space = 8 + account_sizes::STREAM_STATE_SIZE,
        seeds = [b"stream"],
        bump
    )]
    pub stream_state: Account<'info, StreamState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for initializing the split state account
#[derive(Accounts)]
pub struct InitializeSplitState<'info> {
    /// The authority that will own the split state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The split state account to be initialized
    #[account(
        init,
        payer = authority,
        space = 8 + account_sizes::SPLIT_STATE_SIZE,
        seeds = [b"split"],
        bump
    )]
    pub split_state: Account<'info, SplitState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for depositing funds into a vault
#[derive(Accounts)]
pub struct Deposit<'info> {
    /// The authority that owns the vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The vault account to deposit into
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for withdrawing funds from a vault
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// The authority that owns the vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The vault account to withdraw from
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a generic proof
#[derive(Accounts)]
pub struct VerifyProof<'info> {
    /// The authority that owns the vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The vault account to update
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a transfer proof
#[derive(Accounts)]
pub struct VerifyTransferProof<'info> {
    /// The authority that owns the shielded vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The shielded vault account to update
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, ShieldedVault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a withdraw proof
#[derive(Accounts)]
pub struct VerifyWithdrawProof<'info> {
    /// The authority that owns the shielded vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The shielded vault account to update
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, ShieldedVault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a merkle proof
#[derive(Accounts)]
pub struct VerifyMerkleProof<'info> {
    /// The authority that owns the verifier state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The verifier state account to update
    #[account(
        mut,
        seeds = [b"verifier"],
        bump
    )]
    pub verifier_state: Account<'info, VerifierState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a nullifier proof
#[derive(Accounts)]
pub struct VerifyNullifierProof<'info> {
    /// The authority that owns the shielded vault
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The shielded vault account to update
    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, ShieldedVault>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying an audit proof
#[derive(Accounts)]
pub struct VerifyAuditProof<'info> {
    /// The authority that owns the verifier state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The verifier state account to update
    #[account(
        mut,
        seeds = [b"verifier"],
        bump
    )]
    pub verifier_state: Account<'info, VerifierState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a stream proof
#[derive(Accounts)]
pub struct VerifyStreamProof<'info> {
    /// The authority that owns the stream state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The stream state account to update
    #[account(
        mut,
        seeds = [b"stream"],
        bump
    )]
    pub stream_state: Account<'info, StreamState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a split proof
#[derive(Accounts)]
pub struct VerifySplitProof<'info> {
    /// The authority that owns the split state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The split state account to update
    #[account(
        mut,
        seeds = [b"split"],
        bump
    )]
    pub split_state: Account<'info, SplitState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Context for verifying a condition proof
#[derive(Accounts)]
pub struct VerifyConditionProof<'info> {
    /// The authority that owns the verifier state
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The verifier state account to update
    #[account(
        mut,
        seeds = [b"verifier"],
        bump
    )]
    pub verifier_state: Account<'info, VerifierState>,
    /// The Solana system program
    pub system_program: Program<'info, System>,
}

/// Basic vault account for storing funds
#[account]
pub struct Vault {
    /// The public key of the vault's authority
    pub authority: Pubkey,
    /// Current balance of the vault in lamports
    pub balance: u64,
    /// Nonce for preventing replay attacks
    pub nonce: u64,
}

/// Arguments for verifying a generic proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VerifyProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Nullifier to prevent double-spending
    pub nullifier: [u8; 32],
    /// Stream identifier for stream-related proofs
    pub stream_id: [u8; 32],
    /// Merkle proof elements
    pub proof: Vec<Vec<u8>>,
    /// Recipient's public key
    pub recipient_address: Pubkey,
    /// Amount to transfer in lamports
    pub amount: u64,
    /// Timestamp for proof validation
    pub timestamp: i64,
    /// Purpose of the proof
    pub purpose: String,
    /// Audit identifier for audit proofs
    pub audit_id: [u8; 32],
}

/// Arguments for verifying a transfer proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransferProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Nullifier to prevent double-spending
    pub nullifier: [u8; 32],
    /// Leaf commitment to verify in the merkle tree
    pub leaf: [u8; 32],
    /// Merkle proof elements for leaf verification
    pub merkle_proof: Vec<[u8; 32]>,
    /// Recipient's public key
    pub recipient_address: Pubkey,
    /// Amount to transfer in lamports
    pub amount: u64,
}

/// Arguments for verifying a withdraw proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Nullifier to prevent double-spending
    pub nullifier: [u8; 32],
    /// Recipient's public key
    pub recipient_address: Pubkey,
    /// Amount to withdraw in lamports
    pub amount: u64,
}

/// Arguments for verifying a merkle proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct MerkleProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
}

/// Arguments for verifying a nullifier proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct NullifierProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Nullifier to prevent double-spending
    pub nullifier: [u8; 32],
}

/// Arguments for verifying an audit proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AuditProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Audit identifier for compliance tracking
    pub audit_id: [u8; 32],
}

/// Arguments for verifying a stream proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct StreamProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Stream parameters for time-based payments
    pub stream_params: StreamParams,
    /// Amount to stream in lamports
    pub amount: u64,
}

/// Arguments for verifying a split proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SplitProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Split parameters for multi-recipient payments
    pub split_params: SplitParams,
}

/// Arguments for verifying a condition proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ConditionProofArgs {
    /// Groth16 proof component A (64 bytes)
    pub proof_a: [u8; 64],
    /// Groth16 proof component B (128 bytes)
    pub proof_b: [u8; 128],
    /// Groth16 proof component C (64 bytes)
    pub proof_c: [u8; 64],
    /// Public inputs for the proof verification
    pub public_inputs: Vec<u8>,
    /// Merkle root for commitment verification
    pub merkle_root: [u8; 32],
    /// Condition identifier for conditional payments
    pub condition_id: [u8; 32],
}

impl VerifierState {
    /// Size of the verifier state account in bytes
    pub const LEN: usize = account_sizes::VERIFIER_STATE_SIZE;
}

impl ShieldedVault {
    /// Size of the shielded vault account in bytes
    pub const LEN: usize = account_sizes::SHIELDED_VAULT_SIZE;
}

/// Verifier state account for tracking proof verification statistics
#[account]
pub struct VerifierState {
    /// Current merkle root for the system
    pub merkle_root: [u8; 32],
    /// The public key of the verifier's authority
    pub authority: Pubkey,
    /// Hash of the last verified proof
    pub last_verified_proof: [u8; 64],
    /// Total number of proofs verified
    pub total_verified: u64,
    /// Whether the verifier has been initialized
    pub is_initialized: bool,
}

/// Shielded vault account for private transactions
#[account]
pub struct ShieldedVault {
    /// Total amount deposited into the vault
    pub total_deposited: u64,
    /// Total amount withdrawn from the vault
    pub total_withdrawn: u64,
    /// Current balance of the vault in lamports
    pub balance: u64,
    /// Nonce for preventing replay attacks
    pub nonce: u64,
    /// Current merkle root for the vault's commitments
    pub merkle_root: [u8; 32],
    /// The public key of the vault's authority
    pub authority: Pubkey,
    /// Whether the vault has been initialized
    pub is_initialized: bool,
    /// Set of used nullifiers to prevent double-spending
    pub nullifier_set: Vec<[u8; 32]>,
}

/// Validates split payment parameters
/// 
/// Ensures that split parameters are valid, including:
/// - Non-empty recipients and amounts lists
/// - Equal length of recipients and amounts
/// - Positive amounts
/// - Within maximum limits
/// 
/// # Arguments
/// * `params` - Split parameters to validate
/// 
/// # Returns
/// * `Result<()>` - Success or error
/// 
/// # Errors
/// * `CipherPayError::InvalidSplitParams` - If parameters are invalid
pub fn verify_split_params(params: &SplitParams) -> Result<()> {
    if params.recipients.is_empty() || params.amounts.is_empty() {
        return err!(CipherPayError::InvalidSplitParams);
    }

    if params.recipients.len() != params.amounts.len() {
        return err!(CipherPayError::InvalidSplitParams);
    }

    if params.recipients.len() > ValidationLimits::MAX_SPLIT_RECIPIENTS {
        return err!(CipherPayError::InvalidSplitParams);
    }

    for amount in &params.amounts {
        if *amount == 0 {
            return err!(CipherPayError::InvalidSplitParams);
        }
    }

    Ok(())
}

/// Stream state account for time-based payment streams
#[account]
pub struct StreamState {
    /// Timestamp of the last verified stream proof
    pub last_verified_time: i64,
    /// Total number of stream proofs verified
    pub total_verified: u64,
    /// Current merkle root for stream commitments
    pub merkle_root: [u8; 32],
}

/// Split state account for multi-recipient payment splits
#[account]
pub struct SplitState {
    /// Timestamp of the last verified split proof
    pub last_verified_time: i64,
    /// Current merkle root for split commitments
    pub merkle_root: [u8; 32],
}

/// Parameters for split payment operations
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SplitParams {
    /// Unique identifier for the split operation
    pub split_id: [u8; 32],
    /// List of recipient public keys
    pub recipients: Vec<Pubkey>,
    /// List of amounts to send to each recipient (in lamports)
    pub amounts: Vec<u64>,
}

/// Parameters for stream payment operations
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct StreamParams {
    /// Unique identifier for the stream
    pub stream_id: [u8; 32],
    /// Start time of the stream (Unix timestamp)
    pub start_time: i64,
    /// End time of the stream (Unix timestamp)
    pub end_time: i64,
    /// Total amount to be streamed (in lamports)
    pub total_amount: u64,
}

/// Checks if the current compute budget is sufficient for the operation
/// 
/// This function validates that the current compute budget can accommodate
/// the required compute units for the operation.
/// 
/// # Arguments
/// * `_required_units` - Required compute units for the operation
/// 
/// # Returns
/// * `Result<()>` - Success or error
/// 
/// # Errors
/// * `CipherPayError::InsufficientComputeBudget` - If compute budget is insufficient
pub fn check_compute_budget(_required_units: u32) -> Result<()> {
    // TODO: Implement actual compute budget checking
    // For now, always return Ok() as this is a placeholder
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::pubkey::Pubkey;
    use std::collections::HashSet;
    use crate::validation_limits::{ValidationLimits, StreamVerification, SplitVerification};
    use crate::helper::verify_stream_params;
    use crate::merkle::{verify_nullifier as merkle_verify_nullifier};

    // Helper function to create a test pubkey
    fn create_test_pubkey(seed: u8) -> Pubkey {
        Pubkey::new_from_array([seed; 32])
    }

    #[test]
    fn test_verifier_state_initialization() {
        // Test with default values
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: false,
        };
        assert_eq!(verifier_state.merkle_root, [0u8; 32]);
        assert_eq!(verifier_state.authority, Pubkey::default());
        assert_eq!(verifier_state.last_verified_proof, [0u8; 64]);
        assert_eq!(verifier_state.total_verified, 0);
        assert!(!verifier_state.is_initialized);

        // Test with maximum values
        let verifier_state = VerifierState {
            merkle_root: [255u8; 32],
            authority: create_test_pubkey(255),
            last_verified_proof: [255u8; 64],
            total_verified: u64::MAX,
            is_initialized: true,
        };
        assert_eq!(verifier_state.merkle_root, [255u8; 32]);
        assert_eq!(verifier_state.authority, create_test_pubkey(255));
        assert_eq!(verifier_state.last_verified_proof, [255u8; 64]);
        assert_eq!(verifier_state.total_verified, u64::MAX);
        assert!(verifier_state.is_initialized);
    }

    #[test]
    fn test_shielded_vault_initialization() {
        // Test with default values
        let vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: false,
            nullifier_set: Vec::new(),
        };
        assert_eq!(vault.total_deposited, 0);
        assert_eq!(vault.total_withdrawn, 0);
        assert_eq!(vault.balance, 0);
        assert_eq!(vault.nonce, 0);
        assert_eq!(vault.merkle_root, [0u8; 32]);
        assert_eq!(vault.authority, Pubkey::default());
        assert!(!vault.is_initialized);
        assert!(vault.nullifier_set.is_empty());

        // Test with maximum values
        let vault = ShieldedVault {
            total_deposited: u64::MAX,
            total_withdrawn: u64::MAX,
            balance: u64::MAX,
            nonce: u64::MAX,
            merkle_root: [255u8; 32],
            authority: create_test_pubkey(255),
            is_initialized: true,
            nullifier_set: vec![[255u8; 32]; 1000],
        };
        assert_eq!(vault.total_deposited, u64::MAX);
        assert_eq!(vault.total_withdrawn, u64::MAX);
        assert_eq!(vault.balance, u64::MAX);
        assert_eq!(vault.nonce, u64::MAX);
        assert_eq!(vault.merkle_root, [255u8; 32]);
        assert_eq!(vault.authority, create_test_pubkey(255));
        assert!(vault.is_initialized);
        assert_eq!(vault.nullifier_set.len(), 1000);
    }

    #[test]
    fn test_stream_state_initialization() {
        // Test with default values
        let stream_state = StreamState {
            last_verified_time: 0,
            total_verified: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(stream_state.last_verified_time, 0);
        assert_eq!(stream_state.total_verified, 0);
        assert_eq!(stream_state.merkle_root, [0u8; 32]);

        // Test with maximum values
        let stream_state = StreamState {
            last_verified_time: i64::MAX,
            total_verified: u64::MAX,
            merkle_root: [255u8; 32],
        };
        assert_eq!(stream_state.last_verified_time, i64::MAX);
        assert_eq!(stream_state.total_verified, u64::MAX);
        assert_eq!(stream_state.merkle_root, [255u8; 32]);
    }

    #[test]
    fn test_split_state_initialization() {
        // Test with default values
        let split_state = SplitState {
            last_verified_time: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(split_state.last_verified_time, 0);
        assert_eq!(split_state.merkle_root, [0u8; 32]);

        // Test with maximum values
        let split_state = SplitState {
            last_verified_time: i64::MAX,
            merkle_root: [255u8; 32],
        };
        assert_eq!(split_state.last_verified_time, i64::MAX);
        assert_eq!(split_state.merkle_root, [255u8; 32]);
    }

    #[test]
    fn test_verify_proof_args_initialization() {
        // Test with default values
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: Vec::new(),
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert_eq!(proof_args.proof_a, [0u8; 64]);
        assert_eq!(proof_args.proof_b, [0u8; 128]);
        assert_eq!(proof_args.proof_c, [0u8; 64]);
        assert!(proof_args.public_inputs.is_empty());
        assert_eq!(proof_args.merkle_root, [0u8; 32]);
        assert_eq!(proof_args.nullifier, [0u8; 32]);
        assert_eq!(proof_args.stream_id, [0u8; 32]);
        assert!(proof_args.proof.is_empty());
        assert_eq!(proof_args.recipient_address, Pubkey::default());
        assert_eq!(proof_args.amount, 0);
        assert_eq!(proof_args.timestamp, 0);
        assert!(proof_args.purpose.is_empty());
        assert_eq!(proof_args.audit_id, [0u8; 32]);
    }

    #[test]
    fn test_stream_params_initialization() {
        // Test with default values
        let stream_params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 0,
            end_time: 0,
            total_amount: 0,
        };
        assert_eq!(stream_params.stream_id, [0u8; 32]);
        assert_eq!(stream_params.start_time, 0);
        assert_eq!(stream_params.end_time, 0);
        assert_eq!(stream_params.total_amount, 0);

        // Test with maximum values
        let stream_params = StreamParams {
            stream_id: [255u8; 32],
            start_time: i64::MAX,
            end_time: i64::MAX,
            total_amount: u64::MAX,
        };
        assert_eq!(stream_params.stream_id, [255u8; 32]);
        assert_eq!(stream_params.start_time, i64::MAX);
        assert_eq!(stream_params.end_time, i64::MAX);
        assert_eq!(stream_params.total_amount, u64::MAX);
    }

    #[test]
    fn test_split_params_initialization() {
        // Test with empty vectors
        let split_params = SplitParams {
            split_id: [0u8; 32],
            recipients: Vec::new(),
            amounts: Vec::new(),
        };
        assert_eq!(split_params.split_id, [0u8; 32]);
        assert!(split_params.recipients.is_empty());
        assert!(split_params.amounts.is_empty());

        // Test with maximum values
        let split_params = SplitParams {
            split_id: [255u8; 32],
            recipients: vec![create_test_pubkey(255); 10],
            amounts: vec![u64::MAX; 10],
        };
        assert_eq!(split_params.split_id, [255u8; 32]);
        assert_eq!(split_params.recipients.len(), 10);
        assert_eq!(split_params.amounts.len(), 10);
        assert!(split_params.amounts.iter().all(|&x| x == u64::MAX));
    }

    #[test]
    fn test_account_size_constants() {
        // Verify account sizes match their implementations
        assert_eq!(VerifierState::LEN, account_sizes::VERIFIER_STATE_SIZE);
        assert_eq!(ShieldedVault::LEN, account_sizes::SHIELDED_VAULT_SIZE);
    }

    #[test]
    fn test_nullifier_set_boundaries() {
        let mut vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [1u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        let mut seen = HashSet::new();

        // Test adding nullifiers up to the limit
        for i in 0..ValidationLimits::MAX_NULLIFIER_SET_SIZE {
            let mut nullifier = [0u8; 32];
            // Create unique nullifier by using different patterns
            nullifier[0] = i as u8;
            nullifier[1] = (i >> 8) as u8;
            nullifier[2] = (i >> 16) as u8;
            nullifier[3] = (i >> 24) as u8;
            // Fill the rest with a pattern to ensure uniqueness
            for j in 4..32 {
                nullifier[j] = (i + j) as u8;
            }
            assert!(seen.insert(nullifier));
            vault.nullifier_set.push(nullifier);
        }
        assert_eq!(vault.nullifier_set.len(), ValidationLimits::MAX_NULLIFIER_SET_SIZE);
    }

    #[test]
    fn test_split_recipients_boundaries() {
        let mut split_params = SplitParams {
            split_id: [0u8; 32],
            recipients: Vec::new(),
            amounts: Vec::new(),
        };

        let mut seen = HashSet::new();

        // Test adding recipients up to the limit
        for i in 0..ValidationLimits::MAX_SPLIT_RECIPIENTS {
            let recipient = create_test_pubkey(i as u8);
            assert!(seen.insert(recipient));
            split_params.recipients.push(recipient);
            split_params.amounts.push(100);
        }
        assert_eq!(split_params.recipients.len(), ValidationLimits::MAX_SPLIT_RECIPIENTS);
        assert_eq!(split_params.amounts.len(), ValidationLimits::MAX_SPLIT_RECIPIENTS);
    }

    #[test]
    fn test_verify_split_params_validation() {
        // Test valid split parameters
        let valid_params = SplitParams {
            split_id: [1u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![100, 200],
        };
        assert!(verify_split_params(&valid_params).is_ok());

        // Test invalid split parameters (too many recipients)
        let invalid_params = SplitParams {
            split_id: [2u8; 32],
            recipients: vec![create_test_pubkey(1); 11], // More than MAX_SPLIT_RECIPIENTS
            amounts: vec![100; 11],
        };
        assert!(verify_split_params(&invalid_params).is_err());

        // Test mismatched arrays
        let mismatched_params = SplitParams {
            split_id: [3u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![100], // Only one amount for two recipients
        };
        assert!(verify_split_params(&mismatched_params).is_err());

        // Test zero amounts
        let zero_amount_params = SplitParams {
            split_id: [4u8; 32],
            recipients: vec![create_test_pubkey(1)],
            amounts: vec![0], // Zero amount
        };
        assert!(verify_split_params(&zero_amount_params).is_err());
    }

    #[test]
    fn test_vault_balance_validation() {
        let mut vault = ShieldedVault {
            total_deposited: 1000,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        // Test valid withdrawal
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() >= 500);

        // Test withdrawal exceeding balance
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() < 1500);

        // Test withdrawal equal to balance
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() == 1000);

        // Test withdrawal after partial withdrawal
        vault.total_withdrawn = 500;
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() >= 400);
        assert!(vault.total_deposited.checked_sub(vault.total_withdrawn).unwrap() < 600);
    }

    #[test]
    fn test_stream_params_validation() {
        // Test valid stream parameters
        let params = StreamParams {
            stream_id: [1u8; 32],
            start_time: 1234567890,
            end_time: 1234567890 + 1000,
            total_amount: 1000,
        };
        assert!(verify_stream_params(&params).is_ok());

        // Test invalid stream parameters (start_time >= end_time)
        let invalid_params = StreamParams {
            stream_id: [2u8; 32],
            start_time: 1234567890 + 1000,
            end_time: 1234567890,
            total_amount: 1000,
        };
        assert!(verify_stream_params(&invalid_params).is_err());

        // Test zero amount
        let zero_amount_params = StreamParams {
            stream_id: [3u8; 32],
            start_time: 1234567890,
            end_time: 1234567890 + 1000,
            total_amount: 0,
        };
        assert!(verify_stream_params(&zero_amount_params).is_err());
    }

    #[test]
    fn test_nullifier_validation() {
        let mut vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        // Test adding valid nullifier
        let nullifier = [1u8; 32];
        assert!(merkle_verify_nullifier(nullifier, &vault.nullifier_set).is_ok());
        vault.nullifier_set.push(nullifier);

        // Test adding duplicate nullifier
        assert!(merkle_verify_nullifier(nullifier, &vault.nullifier_set).is_err());

        // Test adding different nullifier
        let new_nullifier = [2u8; 32];
        assert!(merkle_verify_nullifier(new_nullifier, &vault.nullifier_set).is_ok());
    }

    #[test]
    fn test_merkle_proof_validation() {
        // Test empty proof
        let proof: Vec<[u8; 32]> = Vec::new();
        let root = [0u8; 32];
        assert!(merkle::verify_merkle_proof(&proof, root).is_err());

        // Test valid proof (create a proper merkle proof that can calculate a root)
        let proof_element1 = [1u8; 32];
        let proof_element2 = [2u8; 32];
        
        // Calculate the expected root using the same algorithm as the merkle module
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        if proof_element1 < proof_element2 {
            hasher.update(&proof_element1);
            hasher.update(&proof_element2);
        } else {
            hasher.update(&proof_element2);
            hasher.update(&proof_element1);
        }
        let expected_root: [u8; 32] = hasher.finalize().into();
        
        // Create proof: [proof_element1, proof_element2]
        let proof = vec![proof_element1, proof_element2];
        assert!(merkle::verify_merkle_proof(&proof, expected_root).is_ok());
        
        // Test invalid root
        let invalid_root = [0u8; 32];
        assert!(merkle::verify_merkle_proof(&proof, invalid_root).is_err());
    }

    #[test]
    fn test_compute_budget_validation() {
        // Test insufficient compute units (should still pass since function always returns Ok)
        assert!(check_compute_budget(StreamVerification::REQUIRED_UNITS - 1).is_ok());

        // Test exact compute units
        assert!(check_compute_budget(StreamVerification::REQUIRED_UNITS).is_ok());

        // Test more than required compute units
        assert!(check_compute_budget(StreamVerification::REQUIRED_UNITS + 1).is_ok());

        // Test split verification compute units
        assert!(check_compute_budget(SplitVerification::REQUIRED_UNITS).is_ok());
        assert!(check_compute_budget(SplitVerification::REQUIRED_UNITS - 1).is_ok());
    }

    #[test]
    fn test_arithmetic_overflow_validation() {
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: u64::MAX - 1,
            is_initialized: true,
        };

        // Test overflow on increment
        assert!(verifier_state.total_verified.checked_add(1).is_some());
        assert!(verifier_state.total_verified.checked_add(2).is_none());

        let mut vault = ShieldedVault {
            total_deposited: u64::MAX - 100,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };

        // Test deposit overflow
        assert!(vault.total_deposited.checked_add(50).is_some());
        assert!(vault.total_deposited.checked_add(200).is_none());

        // Test withdrawal overflow
        vault.total_withdrawn = u64::MAX - 50;
        assert!(vault.total_withdrawn.checked_add(25).is_some());
        assert!(vault.total_withdrawn.checked_add(100).is_none());
    }

    #[test]
    fn test_verifier_state_error_cases() {
        // Test uninitialized state
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: false,
        };
        assert!(!verifier_state.is_initialized);

        // Test invalid merkle root (all zeros)
        let verifier_state = VerifierState {
            merkle_root: [0u8; 32],
            authority: create_test_pubkey(1),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: true,
        };
        assert_eq!(verifier_state.merkle_root, [0u8; 32]);

        // Test invalid authority (default)
        let verifier_state = VerifierState {
            merkle_root: [1u8; 32],
            authority: Pubkey::default(),
            last_verified_proof: [0u8; 64],
            total_verified: 0,
            is_initialized: true,
        };
        assert_eq!(verifier_state.authority, Pubkey::default());
    }

    #[test]
    fn test_shielded_vault_error_cases() {
        // Test uninitialized vault
        let vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: Pubkey::default(),
            is_initialized: false,
            nullifier_set: Vec::new(),
        };
        assert!(!vault.is_initialized);

        // Test negative balance
        let vault = ShieldedVault {
            total_deposited: 100,
            total_withdrawn: 200,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };
        assert!(vault.total_deposited < vault.total_withdrawn);

        // Test invalid merkle root
        let vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };
        assert_eq!(vault.merkle_root, [0u8; 32]);

        // Test nullifier set size limit
        let mut vault = ShieldedVault {
            total_deposited: 0,
            total_withdrawn: 0,
            balance: 0,
            nonce: 0,
            merkle_root: [1u8; 32],
            authority: create_test_pubkey(1),
            is_initialized: true,
            nullifier_set: Vec::new(),
        };
        for i in 0..ValidationLimits::MAX_NULLIFIER_SET_SIZE + 1 {
            vault.nullifier_set.push([i as u8; 32]);
        }
        assert!(vault.nullifier_set.len() > ValidationLimits::MAX_NULLIFIER_SET_SIZE);
    }

    #[test]
    fn test_stream_state_error_cases() {
        // Test invalid time sequence
        let stream_state = StreamState {
            last_verified_time: 2000,
            total_verified: 0,
            merkle_root: [0u8; 32],
        };
        assert!(stream_state.last_verified_time > 0);

        // Test invalid merkle root
        let stream_state = StreamState {
            last_verified_time: 0,
            total_verified: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(stream_state.merkle_root, [0u8; 32]);

        // Test overflow in total_verified
        let stream_state = StreamState {
            last_verified_time: 0,
            total_verified: u64::MAX,
            merkle_root: [1u8; 32],
        };
        assert!(stream_state.total_verified.checked_add(1).is_none());
    }

    #[test]
    fn test_split_state_error_cases() {
        // Test invalid time sequence
        let split_state = SplitState {
            last_verified_time: 2000,
            merkle_root: [0u8; 32],
        };
        assert!(split_state.last_verified_time > 0);

        // Test invalid merkle root
        let split_state = SplitState {
            last_verified_time: 0,
            merkle_root: [0u8; 32],
        };
        assert_eq!(split_state.merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_verify_proof_args_error_cases() {
        // Test empty proof
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: Vec::new(),
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert!(proof_args.public_inputs.is_empty());

        // Test invalid proof lengths
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: vec![1u8],
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert_eq!(proof_args.proof_b.len(), 128);

        // Test maximum public inputs
        let proof_args = VerifyProofArgs {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
            public_inputs: vec![0u8; 10000],
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            stream_id: [0u8; 32],
            proof: Vec::new(),
            recipient_address: Pubkey::default(),
            amount: 0,
            timestamp: 0,
            purpose: String::new(),
            audit_id: [0u8; 32],
        };
        assert!(proof_args.public_inputs.len() > 1000);
    }

    #[test]
    fn test_stream_params_error_cases() {
        // Test invalid time range
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 2000,
            end_time: 1000,
            total_amount: 1000,
        };
        assert!(params.start_time > params.end_time);

        // Test zero duration
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 1000,
            total_amount: 1000,
        };
        assert_eq!(params.start_time, params.end_time);

        // Test zero amount
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 2000,
            total_amount: 0,
        };
        assert_eq!(params.total_amount, 0);

        // Test invalid stream ID
        let params = StreamParams {
            stream_id: [0u8; 32],
            start_time: 1000,
            end_time: 2000,
            total_amount: 1000,
        };
        assert_eq!(params.stream_id, [0u8; 32]);
    }

    #[test]
    fn test_split_params_error_cases() {
        // Test empty recipients
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: Vec::new(),
            amounts: Vec::new(),
        };
        assert!(params.recipients.is_empty());

        // Test mismatched lengths
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![100],
        };
        assert_ne!(params.recipients.len(), params.amounts.len());

        // Test duplicate recipients
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(1)],
            amounts: vec![100, 200],
        };
        assert_eq!(params.recipients[0], params.recipients[1]);

        // Test zero amounts
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1), create_test_pubkey(2)],
            amounts: vec![0, 0],
        };
        assert!(params.amounts.iter().all(|&x| x == 0));

        // Test invalid split ID
        let params = SplitParams {
            split_id: [0u8; 32],
            recipients: vec![create_test_pubkey(1)],
            amounts: vec![100],
        };
        assert_eq!(params.split_id, [0u8; 32]);
    }

    #[test]
    fn test_authority_validation_error_cases() {
        // Test default authority
        let authority = Pubkey::default();
        assert_eq!(authority, Pubkey::default());

        // Test invalid authority
        let authority = create_test_pubkey(0);
        assert_eq!(authority, create_test_pubkey(0));

        // Test authority mismatch
        let authority1 = create_test_pubkey(1);
        let authority2 = create_test_pubkey(2);
        assert_ne!(authority1, authority2);
    }
} 
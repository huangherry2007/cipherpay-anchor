use anchor_lang::prelude::*;

#[event]
pub struct DepositCompleted {
    pub deposit_hash: [u8; 32],
    pub owner_cipherpay_pubkey: [u8; 32],
    pub commitment: [u8; 32],
}

#[event]
pub struct TransferCompleted {
    pub nullifier: [u8; 32],
    pub out1_cipherpay_pubkey: [u8; 32],
    pub out1_commitment: [u8; 32],
    pub out2_cipherpay_pubkey: [u8; 32],
    pub out2_commitment: [u8; 32],
}

#[event]
pub struct WithdrawCompleted {
    pub nullifier: [u8; 32],
    pub recipient: Pubkey,
    pub amount: u64,
}

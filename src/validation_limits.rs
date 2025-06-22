// Remove unused import
// use anchor_lang::prelude::*;

#[allow(dead_code)]
#[derive(Default)]
pub struct ValidationLimits {
    pub max_stream_amount: u64,
    pub max_stream_duration: i64,
    pub max_recipients: u8,
    pub max_proof_size: usize,
    pub max_public_inputs: usize,
}

#[allow(dead_code)]
impl ValidationLimits {
    pub const MAX_NULLIFIER_SET_SIZE: usize = 1000;
    pub const MAX_SPLIT_RECIPIENTS: usize = 10;
    
    pub fn new() -> Self {
        Self {
            max_stream_amount: 1_000_000_000, // 1 billion lamports
            max_stream_duration: 365 * 24 * 60 * 60, // 1 year in seconds
            max_recipients: 10,
            max_proof_size: 1024,
            max_public_inputs: 100,
        }
    }

    pub fn verify_stream_amount(&self, amount: u64) -> bool {
        amount <= self.max_stream_amount
    }

    pub fn verify_stream_duration(&self, duration: i64) -> bool {
        duration <= self.max_stream_duration
    }

    pub fn verify_recipients_count(&self, count: u8) -> bool {
        count <= self.max_recipients
    }

    pub fn verify_proof_size(&self, size: usize) -> bool {
        size <= self.max_proof_size
    }

    pub fn verify_public_inputs_count(&self, count: usize) -> bool {
        count <= self.max_public_inputs
    }
}

#[allow(dead_code)]
pub struct StreamVerification;

#[allow(dead_code)]
impl StreamVerification {
    pub const REQUIRED_UNITS: u32 = 200_000;
}

#[allow(dead_code)]
pub struct SplitVerification;

#[allow(dead_code)]
impl SplitVerification {
    pub const REQUIRED_UNITS: u32 = 150_000;
} 
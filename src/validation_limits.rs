use anchor_lang::prelude::*;

#[derive(Default)]
pub struct ValidationLimits {
    pub max_stream_amount: u64,
    pub max_stream_duration: i64,
    pub max_recipients: u8,
    pub max_proof_size: usize,
    pub max_public_inputs: usize,
}

impl ValidationLimits {
    pub fn new() -> Self {
        Self {
            max_stream_amount: 1_000_000_000, // 1 SOL
            max_stream_duration: 31_536_000, // 1 year in seconds
            max_recipients: 10,
            max_proof_size: 1024,
            max_public_inputs: 1000,
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
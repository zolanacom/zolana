//! Experimental local wallet. RPC consensus is trusted; keys never leave this process.
#![forbid(unsafe_code)]

pub mod history;
pub mod keys;
pub mod operation;
pub mod payments;
pub mod rpc;
mod upload;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

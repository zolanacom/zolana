//! Experimental local wallet. RPC consensus is trusted; keys never leave this process.
#![forbid(unsafe_code)]

mod archive;
mod cache;
pub mod fees;
pub mod history;
pub mod keys;
pub mod operation;
pub mod operator;
pub mod payments;
pub mod rpc;
pub mod sponsor;
mod upload;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

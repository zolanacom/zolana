//! Experimental local wallet. RPC consensus is trusted; keys never leave this process.
#![forbid(unsafe_code)]

pub mod access;
mod archive;
mod cache;
pub mod command_session;
pub mod connection;
pub mod faucet;
pub mod fees;
pub mod history;
pub mod keys;
pub mod operation;
pub mod operator;
pub mod payments;
pub mod progress;
pub mod rpc;
pub mod shielded;
pub mod sponsor;
mod upload;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

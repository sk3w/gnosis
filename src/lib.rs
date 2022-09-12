mod client;
pub mod codec;
mod error;
pub mod messages;
pub mod parser;
mod proxy;
mod server;
mod session;

pub use client::Client;
pub use error::Error;
use error::Result;
pub use proxy::{Proxy, ProxyStats};
pub use server::{Handler, BasicServer, Server};

pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos.rs"));
}
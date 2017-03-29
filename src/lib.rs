//! Asynchronous websockets for Rust.
//!
//! Built onto the modern [tokio](https://tokio.rs) stack.

#![deny(bad_style, missing_docs)]

extern crate base64;
extern crate bytes;
#[macro_use] extern crate futures;
#[macro_use] extern crate nom;
extern crate rand;
extern crate sha1;
extern crate tokio_io;
extern crate tokio_proto;

mod codec;
mod message;
mod transport;

pub use self::codec::Codec;
pub use self::message::{CloseCode, Frame, OpCode};
pub use self::transport::Transport;
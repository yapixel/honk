//! Snell v3–v6 TCP outbound; codecs ported from meow-rs (see README acknowledgments).

pub mod aead;
pub mod cipher;
pub mod handler;
pub mod protocol;
pub mod udp;
pub mod v3;
pub mod v4;
pub mod v6;
pub mod v6_shape;

pub use handler::{SnellHandler, SnellStream, SnellVersion};
pub use protocol::{Snell, connect_request, write_header, write_zero_chunk};
pub use udp::SnellUdpTransport;
pub use v6::{SnellV6Mode, V6Codec};

#[cfg(test)]
mod tests;

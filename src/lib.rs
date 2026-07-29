//! An application framework for building Named Data Networking (NDN)
//! applications on top of [tokio], modeled after the producer/consumer
//! split used by the NDN client libraries in other languages (ndn-cxx,
//! python-ndn, etc).
//!
//! The framework owns the connection to a local NFD forwarder, route
//! registration, Interest/Data matching and dispatch, and NDNLPv2
//! link-layer framing, so application code only needs to describe routes
//! and write async handlers for them. See [`app::App`] for the entry
//! point and the crate's README for a worked example.
//!
//! ```rust,no_run
//! use ndn_app::{app::App, verifier::ForbidUnsigned};
//! use ndn_protocol::{Data, DigestSha256, Interest};
//!
//! # async fn run() {
//! App::new(DigestSha256::new(), ())
//!     .route("example", ForbidUnsigned, |_handler, interest: Interest<()>, _ctx| async move {
//!         Some(Data::new(interest.name().clone(), ()))
//!     })
//!     .start()
//!     .await
//!     .unwrap();
//! # }
//! ```

use bytes::{BufMut, Bytes, BytesMut};
use error::Error;
use log::warn;
use ndn_ndnlp::{LpPacket, Packet};
use ndn_protocol::{Data, Interest, Name};
use ndn_tlv::{Tlv, TlvDecode, TlvEncode, VarNum};
use tokio::io::{AsyncRead, AsyncReadExt};

pub mod app;
pub mod error;
mod util;
pub mod verifier;

/// The `Result` type returned by fallible operations across this crate,
/// with the error type fixed to [`Error`] so callers don't need to name
/// it at every call site.
pub type Result<T> = std::result::Result<T, Error>;

/// Lets route names be given as either a [`Name`] or a plain `&str`
/// (parsed with [`Name::from_str`]), so `App::route` doesn't force
/// callers to construct a `Name` just to register a route by URI.
trait ToName {
    fn to_name(self) -> Name;
}

impl ToName for &str {
    fn to_name(self) -> Name {
        Name::from_str(self).unwrap()
    }
}

impl ToName for Name {
    fn to_name(self) -> Name {
        self
    }
}

/// Reads a single NDN [`Packet`] (Interest, Data, or NDNLPv2 frame) off
/// an async byte stream.
///
/// This exists because packets on the wire are self-delimiting TLV, not
/// length-prefixed, so the only way to know how many bytes to read is to
/// decode the TLV header first and use its length field. Framing this way
/// (peek header, then read exactly that many bytes) avoids buffering
/// unbounded amounts of data from a slow or malicious peer before we know
/// how much to expect.
trait DataExt: Sized {
    async fn from_async_reader(reader: impl AsyncRead + Unpin) -> Option<Self>;
}

impl DataExt for Packet {
    async fn from_async_reader(mut reader: impl AsyncRead + Unpin) -> Option<Self> {
        const BUFFER_SIZE: usize = 1024;

        let mut header_buf = [0; 18];
        let bytes_read = reader.read(&mut header_buf).await.ok()?;
        let mut header_bytes = Bytes::copy_from_slice(&header_buf);

        if bytes_read == 0 {
            return None;
        }

        let typ = VarNum::decode(&mut header_bytes).ok()?;
        let len = VarNum::decode(&mut header_bytes).ok()?;
        if typ.value() as usize != Interest::<()>::TYP
            && typ.value() as usize != Data::<()>::TYP
            && typ.value() as usize != LpPacket::TYP
        {
            // Unknown TLV type, skip the rest and return
            warn!("Unknown TLV type {typ} received");
            let remaining_len = len.value() as usize - bytes_read;
            tokio::io::copy(
                &mut reader.take(remaining_len as u64),
                &mut tokio::io::sink(),
            )
            .await
            .expect("Failed to read unknown packet");
            return None;
        }

        let total_len = typ.size() + len.size() + len.value() as usize;

        let mut bytes = BytesMut::with_capacity(total_len);
        bytes.put(&header_buf[0..bytes_read]);

        let mut left_to_read = total_len - bytes_read;
        let mut buf = [0; BUFFER_SIZE];
        while left_to_read > 0 {
            let bytes_read = reader
                .read(&mut buf[0..left_to_read.min(BUFFER_SIZE)])
                .await
                .ok()?;
            bytes.put(&buf[..left_to_read.min(BUFFER_SIZE)]);
            left_to_read -= bytes_read;
        }

        Self::decode(&mut bytes.freeze()).ok()
    }
}

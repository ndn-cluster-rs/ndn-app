use bytes::{BufMut, Bytes, BytesMut};
use error::Error;
use log::warn;
use ndn_ndnlp::{LpPacket, Packet};
use ndn_protocol::{Data, Interest, Name};
use ndn_tlv::{Tlv, TlvDecode, TlvEncode, VarNum};
use tokio::io::{AsyncRead, AsyncReadExt};

pub mod app;
pub mod error;
pub mod verifier;

pub type Result<T> = std::result::Result<T, Error>;

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

trait DataExt: Sized {
    async fn from_async_reader(reader: impl AsyncRead + Unpin) -> Option<Self>;
}

impl DataExt for Packet {
    async fn from_async_reader(mut reader: impl AsyncRead + Unpin) -> Option<Self> {
        let mut header_buf = [0; 18];
        let bytes_read = reader.read(&mut header_buf).await.ok()?;
        let mut header_bytes = Bytes::copy_from_slice(&header_buf);

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
        let mut buf = [0; 1024];
        while left_to_read > 0 {
            let bytes_read = reader.read(&mut buf[0..left_to_read]).await.ok()?;
            bytes.put(&buf[..left_to_read]);
            left_to_read -= bytes_read;
        }

        Self::decode(&mut bytes.freeze()).ok()
    }
}

use bytes::{Buf, BufMut, BytesMut};
use log::{trace, error};
use nom::Offset;
use prost::Message;
use tokio_util::codec::{Decoder, Encoder};

use crate::messages::{DataMessage, DataMessageP, GnsFrame};
use crate::parser;
use crate::protos::*;
use crate::session::Session;

pub struct GnsCodec;

impl Decoder for GnsCodec {
    type Item = GnsFrame;

    type Error = crate::error::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parser::gns_frame(src) {
            Ok((leftover, frame)) => {
                let cnt = src.offset(leftover);
                src.advance(cnt);
                Ok(Some(frame))
            }
            Err(nom::Err::Incomplete(needed)) => {
                trace!("Inside decode() needed is: {needed:?}");
                Ok(None)
            }
            Err(nom::Err::Error(e)) => {
                trace!("Inside decode(), error is: {e:?}");
                Err(crate::error::Error::CodecDecodeError)
            }
            Err(_) => Err(crate::error::Error::CodecDecodeError),
        }
    }
}

impl Encoder<GnsFrame> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(&mut self, item: GnsFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            GnsFrame::ChallengeRequest(item) => self.encode(item, dst),
            GnsFrame::ChallengeReply(item) => self.encode(item, dst),
            GnsFrame::ConnectRequest(item) => self.encode(item, dst),
            GnsFrame::ConnectOk(item) => self.encode(item, dst),
            GnsFrame::ConnectionClosed(item) => self.encode(item, dst),
            GnsFrame::NoConnection(item) => self.encode(item, dst),
            GnsFrame::Data(item) => self.encode(item, dst),
        }
    }
}

impl Encoder<CMsgSteamSocketsUdpChallengeRequest> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(
        &mut self,
        item: CMsgSteamSocketsUdpChallengeRequest,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(512);
        dst.put_u8(0x20);
        let len: u16 = item.encoded_len().try_into().unwrap();
        dst.put_u16_le(len);
        item.encode(dst)?;
        dst.put_bytes(0u8, 509 - len as usize);
        Ok(())
    }
}

impl Encoder<CMsgSteamSocketsUdpChallengeReply> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(
        &mut self,
        item: CMsgSteamSocketsUdpChallengeReply,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(1 + item.encoded_len());
        dst.put_u8(0x21);
        item.encode(dst)?;
        Ok(())
    }
}

impl Encoder<CMsgSteamSocketsUdpConnectRequest> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(
        &mut self,
        item: CMsgSteamSocketsUdpConnectRequest,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(1 + item.encoded_len());
        dst.put_u8(0x22);
        item.encode(dst)?;
        Ok(())
    }
}

impl Encoder<CMsgSteamSocketsUdpConnectOk> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(
        &mut self,
        item: CMsgSteamSocketsUdpConnectOk,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(1 + item.encoded_len());
        dst.put_u8(0x23);
        item.encode(dst)?;
        Ok(())
    }
}

impl Encoder<CMsgSteamSocketsUdpConnectionClosed> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(
        &mut self,
        item: CMsgSteamSocketsUdpConnectionClosed,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(512);
        dst.put_u8(0x24);
        let len: u16 = item.encoded_len().try_into().unwrap();
        dst.put_u16_le(len);
        item.encode(dst)?;
        dst.put_bytes(0u8, 509 - len as usize);
        Ok(())
    }
}

impl Encoder<CMsgSteamSocketsUdpNoConnection> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(
        &mut self,
        item: CMsgSteamSocketsUdpNoConnection,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(1 + item.encoded_len());
        dst.put_u8(0x25);
        item.encode(dst)?;
        Ok(())
    }
}

impl Encoder<DataMessage> for GnsCodec {
    type Error = crate::error::Error;

    fn encode(&mut self, item: DataMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(7 + item.ciphertext.len());
        dst.put_u8(0x80 ^ item.flags);
        dst.put_u32_le(item.to_connection_id);
        dst.put_u16_le(item.sequence_number);
        dst.put(item.ciphertext);
        Ok(())
    }
}
pub struct DataMessageCodec {
    pub session: Session,
}

impl DataMessageCodec {
    pub fn new(session: Session) -> Self {
        Self { session }
    }
}

impl Decoder for DataMessageCodec {
    type Item = DataMessageP;
    //type Item = DataMessage;

    type Error = crate::error::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parser::data_message(src) {
            Ok((leftover_bytes, msg)) => {
                let cnt = src.offset(leftover_bytes);
                src.advance(cnt);
                Ok(Some(msg.decrypt(&mut self.session)))
                //Ok(Some(msg))
            }
            Err(nom::Err::Incomplete(_needed)) => {
                //trace!("Inside decode() needed is: {needed:?}");
                Ok(None)
            }
            Err(nom::Err::Error(e)) => {
                error!("Inside decode(), error is: {e:?}");
                Err(crate::error::Error::CodecDecodeError)
            }
            Err(_) => Err(crate::error::Error::CodecDecodeError),
        }
    }
}

// impl Encoder<DataMessage> for DataMessageCodec {
//     type Error = crate::error::Error;

//     fn encode(&mut self, item: DataMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
//         // TODO: do we need to dst.reserve(7) or check that we have enough capacity to not panic?
//         dst.put_u8(0x80 ^ item.flags);
//         dst.put_u32_le(item.to_connection_id);
//         dst.put_u16_le(item.sequence_number);
//         dst.copy_from_slice(&item.ciphertext);
//         Ok(())
//     }
// }

impl Encoder<DataMessageP> for DataMessageCodec {
    type Error = crate::error::Error;

    fn encode(&mut self, item: DataMessageP, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // TODO: do we need to dst.reserve(7) or check that we have enough capacity to not panic?
        dst.reserve(7 + item.plaintext.len());
        dst.put_u8(0x80 ^ item.flags);
        dst.put_u32_le(item.to_connection_id);
        dst.put_u16_le(item.sequence_number);
        dst.put(self.session.encrypt(item.plaintext, item.sequence_number));
        Ok(())
    }
}

use bytes::Bytes;
use pretty_hex::PrettyHex;

use crate::{protos::*, session::Session};

#[derive(Debug, derive_more::From)]
pub enum GnsFrame {
    ChallengeRequest(CMsgSteamSocketsUdpChallengeRequest),
    ChallengeReply(CMsgSteamSocketsUdpChallengeReply),
    ConnectRequest(CMsgSteamSocketsUdpConnectRequest),
    ConnectOk(CMsgSteamSocketsUdpConnectOk),
    ConnectionClosed(CMsgSteamSocketsUdpConnectionClosed),
    NoConnection(CMsgSteamSocketsUdpNoConnection),
    Data(DataMessage),
}

// UDPDataMsgHdr
// https://github.com/ValveSoftware/GameNetworkingSockets/blob/505c697d0abef5da2ff3be35aa4ea3687597c3e9/src/steamnetworkingsockets/clientlib/steamnetworkingsockets_udp.h#L25
#[derive(Debug, PartialEq)]
pub struct DataMessage {
    pub flags: u8,
    // TODO: DataMessageFlags,
    pub to_connection_id: u32,
    pub sequence_number: u16,
    pub ciphertext: Bytes,
}

impl DataMessage {
    pub fn decrypt(self, session: &mut Session) -> DataMessageP {
        let plaintext = session.decrypt(&self.ciphertext, self.sequence_number);
        DataMessageP {
            flags: self.flags,
            to_connection_id: self.to_connection_id,
            sequence_number: self.sequence_number,
            plaintext,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DataMessageP {
    pub flags: u8,
    // TODO: DataMessageFlags,
    pub to_connection_id: u32,
    pub sequence_number: u16,
    pub plaintext: Bytes,
}

impl DataMessageP {
    pub fn encrypt(self, session: &mut Session) -> DataMessage {
        let ciphertext = session.encrypt(self.plaintext, self.sequence_number);
        DataMessage {
            flags: self.flags,
            to_connection_id: self.to_connection_id,
            sequence_number: self.sequence_number,
            ciphertext,
        }
    }
}

/// SNP data payload
///
/// The SNP data payload is a sequence of frames. Each frame begins with an 8-bit frame type / flags field.

/// https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/src/steamnetworkingsockets/clientlib/SNP_WIRE_FORMAT.md
#[derive(Debug, PartialEq, derive_more::From)]
pub enum SnpFrame {
    UnreliableSegment(SnpUnreliableSegment),
    ReliableSegment(SnpReliableSegment),
    StopWaiting(u64),
    Ack(SnpAck),
    SelectLane(usize),
}

#[derive(Debug, PartialEq)]
pub struct SnpUnreliableSegment {
    pub flags: u8,
    pub message_number: u32,
    pub offset: u32,
    //pub size: u16, // max value is 0x4ff = 1279
    pub data: Bytes,
}

#[derive(Debug, PartialEq)]
pub struct SnpReliableSegment {
    pub flags: u8,
    pub stream_pos: u64,
    pub data: Bytes,
}

impl SnpReliableSegment {
    pub fn pretty_print(&self) {
        println!(
            "SnpReliableSegment\n  flags: {}\n  stream_pos: {}\n==[data]==\n{:#?}\n==========",
            &self.flags,
            &self.stream_pos,
            &self.data.hex_dump()
        );
    }
}

#[derive(Debug, PartialEq)]
pub struct SnpAck {
    pub flags: u8,
    pub latest_received_pkt_num: u32,
    pub latest_received_delay: u16,
    pub blocks: Vec<SnpAckBlock>,
}

#[derive(Debug, PartialEq)]
pub struct SnpAckBlock {
    // pub flags: u8,
    // pub num_ack: u8,
}

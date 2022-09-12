mod snp;

use bytes::Bytes;
use nom::branch::alt;
use nom::bytes::streaming::tag;
use nom::combinator::{into, map, rest, value};
use nom::multi::length_data;
use nom::number::streaming::{le_u16, le_u32, le_u8};
use nom::sequence::{delimited, preceded};
use nom::IResult;
use prost::Message;

use crate::messages::{DataMessage, GnsFrame};
use crate::protos::*;

pub use self::snp::snp_frames;

pub fn gns_frame(input: &[u8]) -> IResult<&[u8], GnsFrame> {
    alt((
        into(challenge_request),
        into(challenge_reply),
        into(connect_request),
        into(connect_ok),
        into(connection_closed),
        into(no_connection),
        into(data_message),
    ))(input)
}

// fn padded_message(input: &[u8]) -> IResult<&[u8], &[u8]> {
//     todo!()
// }

pub fn challenge_request(input: &[u8]) -> IResult<&[u8], CMsgSteamSocketsUdpChallengeRequest> {
    delimited(
        tag([0x20]),
        map(length_data(le_u16), |b| {
            CMsgSteamSocketsUdpChallengeRequest::decode(b).unwrap()
        }),
        rest,
    )(input)
}

pub fn challenge_reply(input: &[u8]) -> IResult<&[u8], CMsgSteamSocketsUdpChallengeReply> {
    map(preceded(tag([0x21]), rest), |b| {
        CMsgSteamSocketsUdpChallengeReply::decode(b).unwrap()
    })(input)
}

pub fn connect_request(input: &[u8]) -> IResult<&[u8], CMsgSteamSocketsUdpConnectRequest> {
    preceded(
        tag([0x22]),
        map(rest, |b| {
            CMsgSteamSocketsUdpConnectRequest::decode(b).unwrap()
        }),
    )(input)
}

pub fn connect_ok(input: &[u8]) -> IResult<&[u8], CMsgSteamSocketsUdpConnectOk> {
    preceded(
        tag([0x23]),
        map(rest, |b| CMsgSteamSocketsUdpConnectOk::decode(b).unwrap()),
    )(input)
}

pub fn connection_closed(input: &[u8]) -> IResult<&[u8], CMsgSteamSocketsUdpConnectionClosed> {
    delimited(
        tag([0x24]),
        map(length_data(le_u16), |b| {
            CMsgSteamSocketsUdpConnectionClosed::decode(b).unwrap()
        }),
        rest,
    )(input)
}

pub fn no_connection(input: &[u8]) -> IResult<&[u8], CMsgSteamSocketsUdpNoConnection> {
    preceded(
        tag([0x25]),
        map(rest, |b| {
            CMsgSteamSocketsUdpNoConnection::decode(b).unwrap()
        }),
    )(input)
}

pub fn data_message(input: &[u8]) -> IResult<&[u8], DataMessage> {
    let (input, flags) = alt((value(0x0, tag(&[0x80])), value(0x1, tag(&[0x81]))))(input)?;

    let (input, to_connection_id) = le_u32(input)?;
    let (input, sequence_number) = le_u16(input)?;
    let input = if flags == 1 {
        // skip protobuf-encoded inline CMsgSteamSockets_UDP_Stats
        let (input, _proto_udp_stats) = length_data(le_u8)(input)?;
        input
    } else {
        input
    };
    let (input, ciphertext) = rest(input)?;
    let ciphertext = Bytes::copy_from_slice(ciphertext);
    Ok((
        input,
        DataMessage {
            flags,
            to_connection_id,
            sequence_number,
            ciphertext,
        },
    ))
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use pretty_hex::*;

    use crate::messages::{SnpAck, SnpFrame};

    use super::*;

    #[test]
    fn parse_data_message() {
        let msg_bytes = &hex!(
            "80 29 c2 c1  77 02 00 ab  ea 83 88 b0  53 23 36 ca"
            "4a be 98 13  06 e2 5b e4  65 58 85 bd  5d 1e b8 97"
            "87 42 89 67  18 d5 b0 c9  26 03 8c"
        );
        let ciphertext = Bytes::copy_from_slice(&hex!(
            "ab ea 83 88  b0 53 23 36  ca"
            "4a be 98 13  06 e2 5b e4  65 58 85 bd  5d 1e b8 97"
            "87 42 89 67  18 d5 b0 c9  26 03 8c"
        ));
        let (_, msg) = data_message(msg_bytes).unwrap();
        let expected = DataMessage {
            flags: 0,
            to_connection_id: 2009186857,
            sequence_number: 2,
            ciphertext,
        };
        assert_eq!(msg, expected);
    }

    #[test]
    fn parse_sample_plaintext() {
        let input = b"\x80\0\x98$\0\xe8\x0cWx\0\0\0\0\00\t\x1e\x9b\xc0\xd4(\x01\0\0\xae\xec\xf19\0\0\0\0\x070.210.6\0\0\0\0\0\0\0\0\0\0\0\0\x06Johnny\x10*?c????C??M\x0c?\x0b\x17g\xf0\0\0\0\x14\0\0\0\xf7\xce\xe4\x19\x81\"\x8a\xe2'5\xc2L\x01\0\x10\x01D\xca#c\x18\0\0\0\x01\0\0\0\x02\0\0\0\xf6\xbe=\xebs&\xdb\x8e\xb00C\0\x04\0\0\0\xb8\0\0\08\0\0\0\x04\0\0\0'5\xc2L\x01\0\x10\x01*\xa0\r\0\xb1\xb31K\x077\xd3\n\x02\0\0\0X\xa0\x1ac\xd8O6c\x01\0hY\x04\0\x01\0\x94\xae\r\0\0\0\0\02JL\xdc}\xcb\xd5D\xef`\xa0\x99w\x92\xbaH\xf8g\x13\xab\xcd\xcf\xbdQL([\xacI\x8f\\\x06\xfdru\x13\x04a\xd2\xc0H0*\x16\xd9\x04a\xb3\xbe\xd6\xb0V4\xe5\xa4v\xf5+)%\x8b\xed\xde\xc2\x81#\xd0\x14\xa8*\xc7?8{\x1e\xbf\x97\xb8q\x90j+\"&b\xcc\xd3\x94\xa8\xdd\r\x8a\xaf{f\xaea\x13C\xb2\x7fc5Z[\x1b\n\xb7Tz'Z\x89y\xb8\xd8\xaa\x10\xe7=\xdd\xa3\xb1\x97\xca\xd6q\x91";
        let (_, output) = snp_frames(input).unwrap();
        let expected = vec![SnpFrame::Ack(SnpAck {
            flags: 0,
            latest_received_pkt_num: 0,
            latest_received_delay: 0,
            blocks: vec![],
        })];
        dbg!(&output);
        match &output[2] {
            SnpFrame::ReliableSegment(s) => println!("{:#?}", s.data.hex_dump()),
            _ => (),
        }
        assert_eq!(output, expected)
    }
}

//! Parsers for SNP wire format
//!
//! Described at <https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/src/steamnetworkingsockets/clientlib/SNP_WIRE_FORMAT.md>

use bytes::Bytes;
use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::combinator::{eof, into, map, rest, verify};
use nom::multi::{count, length_data, many_till};
use nom::number::complete::{le_u16, le_u24, le_u32, le_u64, le_u8};
use nom::sequence::preceded;
use nom::{bits, IResult};
use nom_varint::take_varint;

use crate::messages::{SnpAck, SnpAckBlock, SnpFrame, SnpReliableSegment, SnpUnreliableSegment};

/// Parse a sequence of SNP frames until EOF
pub fn snp_frames(input: &[u8]) -> IResult<&[u8], Vec<SnpFrame>> {
    let (input, (frames, _eof)) = many_till(snp_frame, eof)(input)?;
    Ok((input, frames))
}

/// Parse a single SNP frame
pub fn snp_frame(input: &[u8]) -> IResult<&[u8], SnpFrame> {
    alt((
        into(snp_unreliable_segment),
        into(snp_reliable_segment),
        into(snp_stop_waiting),
        into(snp_ack),
        snp_select_lane,
    ))(input)
}

/// Parse an SNP unreliable message segment frame
///
/// 00emosss [message_num] [offset] [size] data
pub fn snp_unreliable_segment(input: &[u8]) -> IResult<&[u8], SnpUnreliableSegment> {
    let (input, (_e, m, o, sss)) = bits::bits(snp_unreliable_segment_header)(input)?;
    let (input, message_number) = match m {
        0 => le_u16_into_u32(input)?,
        _ => le_u32(input)?,
    };
    let (input, offset) = match o {
        0 => (input, 0usize),
        _ => take_varint(input)?,
    };
    let (input, size) = le_u8(input)?;
    let (input, data) = match sss {
        0b000..=0b100 => take(size as u16 + (sss << 8))(input)?,
        0b111 => rest(input)?,
        _ => unreachable!(), // validated in snp_unreliable_segment_header()
    };
    Ok((
        input,
        SnpUnreliableSegment {
            flags: 0,
            message_number,
            offset: offset as u32,
            data: Bytes::copy_from_slice(data),
        },
    ))
}

fn snp_unreliable_segment_header(
    input: (&[u8], usize),
) -> IResult<(&[u8], usize), (u8, u8, u8, u16)> {
    let (input, _) = bits::streaming::tag(0u8, 2usize)(input)?;
    let (input, e) = bits::streaming::take(1usize)(input)?;
    let (input, m) = bits::streaming::take(1usize)(input)?;
    let (input, o) = bits::streaming::take(1usize)(input)?;
    let (input, sss) = verify(bits::streaming::take(3usize), |sss| match sss {
        0b000..=0b100 => true, // upper three bits of `size` value
        0b111 => true,         // last frame, read data to end of packet
        _ => false,            // reserved or invalid values
    })(input)?;
    Ok((input, (e, m, o, sss)))
}

/// Parse an SNP reliable message segment frame
///
/// 010mmsss [stream_pos] [size] data
pub fn snp_reliable_segment(input: &[u8]) -> IResult<&[u8], SnpReliableSegment> {
    let (input, flags) = verify(le_u8, |f| match f {
        0b01000000..=0b01011111 => true,
        _ => false,
    })(input)?;
    let mm = (flags & 0b00011000) >> 3;
    // TODO: Subsequent reliable segments in the same lane
    let (input, stream_pos) = match mm {
        0b00 => map(le_u24, |u| u64::from(u))(input)?,
        0b01 => map(le_u32, |u| u64::from(u))(input)?,
        0b10 => le_u48_into_u64(input)?,
        0b11 => unimplemented!(), // Reserved value for size of stream_pos
        _ => unreachable!(),
    };
    let sss = flags & 0b00000111;
    let (input, data) = match sss {
        upper @ 0b000..=0b100 => length_data(map(le_u8, |lower| {
            u16::from(lower) + (u16::from(upper) << 8)
        }))(input)?,
        0b111 => rest(input)?,
        0b101 | 0b110 => unimplemented!(), // Reserved
        _ => unreachable!(),
    };
    Ok((
        input,
        SnpReliableSegment {
            flags,
            stream_pos,
            data: Bytes::copy_from_slice(data),
        },
    ))
}

/// Parse an SNP stop waiting frame
///
/// 100000ww pkt_num_offset
pub fn snp_stop_waiting(input: &[u8]) -> IResult<&[u8], SnpFrame> {
    map(
        alt((
            preceded(tag([0b10000000]), map(le_u8, |u| u as u64)),
            preceded(tag([0b10000001]), map(le_u16, |u| u as u64)),
            preceded(tag([0b10000010]), map(le_u32, |u| u as u64)),
            preceded(tag([0b10000011]), le_u64),
        )),
        |pkt_num_offset| SnpFrame::StopWaiting(pkt_num_offset),
    )(input)
}

/// Parse an SNP ack frame
///
/// 1001wnnn latest_received_pkt_num latest_received_delay [N] [ack_block_0 ... ack_block_N]
pub fn snp_ack(input: &[u8]) -> IResult<&[u8], SnpAck> {
    let (input, flags) = verify(le_u8, |f| match f {
        0b10010000..=0b10011111 => true,
        _ => false,
    })(input)?;
    let (input, latest_received_pkt_num) = match flags & 0b00001000 > 0 {
        true => le_u16_into_u32(input)?,
        false => le_u32(input)?,
    };
    let (input, latest_received_delay) = le_u16(input)?;
    let (input, block_count) = match flags & 0b00000111 {
        c @ 0..=6 => (input, c),
        _ => le_u8(input)?,
    };
    let (input, blocks) = count(snp_ack_block, block_count.into())(input)?;
    Ok((
        input,
        SnpAck {
            flags,
            latest_received_pkt_num,
            latest_received_delay,
            blocks,
        },
    ))
}

/// Parse an SNP ack block
///
/// aaaannnn [num_ack] [num_nack]
fn snp_ack_block(input: &[u8]) -> IResult<&[u8], SnpAckBlock> {
    Ok((input, SnpAckBlock {}))
}

fn le_u16_into_u32(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, message_number) = le_u16(input)?;
    Ok((input, message_number.into()))
}

fn le_u48_into_u64(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, u48_bytes) = take(6usize)(input)?;
    let mut buf = [0u8; 8];
    let buf_lower_48 = &mut buf[..6];
    buf_lower_48.copy_from_slice(u48_bytes);
    Ok((input, u64::from_le_bytes(buf)))
}

/// Parse an SNP select lane frame
///
/// 10001nnn
pub fn snp_select_lane(input: &[u8]) -> IResult<&[u8], SnpFrame> {
    let (input, nnn) = bits(snp_select_lane_header)(input)?;
    let (input, lane_num) = match nnn {
        0b000..=0b110 => (input, usize::from(nnn)),
        0b111 => nom_varint::take_varint(input)?,
        _ => unreachable!(),
    };
    Ok((input, SnpFrame::SelectLane(lane_num)))
}

fn snp_select_lane_header(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let (input, _) = bits::complete::tag(0b10001, 5usize)(input)?;
    bits::complete::take(3usize)(input)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn parse_snp_frames() {
        let input = b"\x80\x01\x98\x04\0$sW\x01\0\0\0\0\0\x05\0\0\0\0\x01";
        let (_, frames) = snp_frames(input).unwrap();
        assert_eq!(
            frames,
            &[
                SnpFrame::StopWaiting(1),
                SnpFrame::Ack(SnpAck {
                    flags: 0b10011000,
                    latest_received_pkt_num: 4,
                    latest_received_delay: 29476,
                    blocks: [].into(),
                }),
                SnpFrame::ReliableSegment(SnpReliableSegment {
                    flags: 0b01010111,
                    stream_pos: 1,
                    data: Bytes::from_static(b"\x05\0\0\0\0\x01"),
                })
            ]
        )
    }

    #[test]
    fn parse_snp_reliable_segment() {
        let input = &hex!("57010000000000050000000001");
        let (_, msg) = snp_reliable_segment(input).unwrap();
        assert_eq!(
            msg,
            SnpReliableSegment {
                flags: 0b01010111,
                stream_pos: 1,
                data: Bytes::from_static(b"\x05\0\0\0\0\x01")
            }
        )
    }
    #[test]
    fn parse_snp_ack() {
        let input = &hex!("98 0400 ffff");
        //let input = b"\x98\x04\x00\x24\x73";
        let (_, msg) = snp_ack(input).unwrap();
        dbg!(&msg);
        assert_eq!(
            msg,
            SnpAck {
                flags: 0b10011000,
                latest_received_pkt_num: 4,
                latest_received_delay: 65535,
                blocks: Vec::new(),
            }
        )
    }
}

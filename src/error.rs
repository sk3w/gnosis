#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    #[error("codec decode error")]
    CodecDecodeError,
    #[error("ip address parse error")]
    AddrParseError {
        #[from]
        source: std::net::AddrParseError,
    },
    // #[error("parser error")]
    // ParserError {
    //     #[from]
    //     source: Box<dyn nom::error::ParseError<&[u8]>>,
    // },
    #[error("protobuf decode error")]
    ProtobufDecodeError {
        #[from]
        source: prost::DecodeError,
    },
    #[error("protobuf encode error")]
    ProtobufEncodeError {
        #[from]
        source: prost::EncodeError,
    },
    #[error("unknown error")]
    UnknownError,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
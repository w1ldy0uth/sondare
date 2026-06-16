use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum CodecError {
    BufTooSmall,
    TruncatedPacket,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufTooSmall => write!(f, "buffer too small to encode packet"),
            Self::TruncatedPacket => write!(f, "packet truncated"),
        }
    }
}

impl std::error::Error for CodecError {}

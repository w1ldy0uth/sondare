use std::fmt;

#[derive(Debug)]
pub enum EngineError {
    Channel(String),
    Codec(sondare_codec::CodecError),
    Io(std::io::Error),
    Tls(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(s) => write!(f, "channel error: {s}"),
            Self::Codec(e) => write!(f, "codec error: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Tls(s) => write!(f, "tls error: {s}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<sondare_codec::CodecError> for EngineError {
    fn from(e: sondare_codec::CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

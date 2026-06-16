use std::fmt;

#[derive(Debug)]
pub enum EngineError {
    Channel(String),
    Codec(sondare_codec::CodecError),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(s) => write!(f, "channel error: {s}"),
            Self::Codec(e) => write!(f, "codec error: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<sondare_codec::CodecError> for EngineError {
    fn from(e: sondare_codec::CodecError) -> Self {
        Self::Codec(e)
    }
}

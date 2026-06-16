use std::fmt;

#[derive(Debug)]
pub enum DataLinkError {
    InterfaceNotFound(String),
    ChannelOpen(String),
    Send(String),
    Recv(String),
    Timeout,
}

impl fmt::Display for DataLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceNotFound(s) => write!(f, "interface not found: {s}"),
            Self::ChannelOpen(s) => write!(f, "failed to open channel: {s}"),
            Self::Send(s) => write!(f, "send error: {s}"),
            Self::Recv(s) => write!(f, "recv error: {s}"),
            Self::Timeout => write!(f, "receive timed out"),
        }
    }
}

impl std::error::Error for DataLinkError {}

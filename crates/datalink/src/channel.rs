use std::time::{Duration, Instant};
use pnet_datalink::{self, Channel as PnetChannel, Config};
use crate::{error::DataLinkError, iface::Iface};

/// Raw L2 send/receive channel over a network interface.
pub struct RawChannel {
    tx: Box<dyn pnet_datalink::DataLinkSender>,
    rx: Box<dyn pnet_datalink::DataLinkReceiver>,
}

impl RawChannel {
    pub fn open(iface: &Iface) -> Result<Self, DataLinkError> {
        let cfg = Config {
            read_timeout: Some(Duration::from_millis(10)),
            ..Config::default()
        };
        match pnet_datalink::channel(&iface.inner, cfg) {
            Ok(PnetChannel::Ethernet(tx, rx)) => Ok(Self { tx, rx }),
            Ok(_) => Err(DataLinkError::ChannelOpen("unexpected channel type".into())),
            Err(e) => Err(DataLinkError::ChannelOpen(e.to_string())),
        }
    }

    /// Send a pre-built Ethernet frame (the full frame including Ethernet header).
    pub fn send(&mut self, frame: &[u8]) -> Result<(), DataLinkError> {
        match self.tx.send_to(frame, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(DataLinkError::Send(e.to_string())),
            None => Err(DataLinkError::Send("send_to returned None".into())),
        }
    }

    /// Receive the next frame, blocking for up to `timeout`.
    /// Returns the raw frame bytes on success.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Vec<u8>, DataLinkError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.rx.next() {
                Ok(frame) => return Ok(frame.to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    if Instant::now() >= deadline {
                        return Err(DataLinkError::Timeout);
                    }
                }
                Err(e) => return Err(DataLinkError::Recv(e.to_string())),
            }
        }
    }

    /// Receive frames until `predicate` returns `Some(T)`, or `timeout` elapses.
    pub fn recv_filter<T, F>(&mut self, timeout: Duration, mut predicate: F) -> Result<T, DataLinkError>
    where
        F: FnMut(&[u8]) -> Option<T>,
    {
        let deadline = Instant::now() + timeout;
        loop {
            match self.rx.next() {
                Ok(frame) => {
                    if let Some(result) = predicate(frame) {
                        return Ok(result);
                    }
                    if Instant::now() >= deadline {
                        return Err(DataLinkError::Timeout);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    if Instant::now() >= deadline {
                        return Err(DataLinkError::Timeout);
                    }
                }
                Err(e) => return Err(DataLinkError::Recv(e.to_string())),
            }
        }
    }
}

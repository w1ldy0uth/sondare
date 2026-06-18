use pcap::{Capture, Device};

use crate::EngineError;

pub struct PacketCapture {
    cap: Capture<pcap::Active>,
}

pub enum CaptureResult {
    Packet(Vec<u8>),
    Timeout,
}

impl PacketCapture {
    pub fn open(
        iface_name: &str,
        bpf_filter: &str,
        timeout_ms: i32,
    ) -> Result<Self, EngineError> {
        let device = Device::list()
            .map_err(|e| EngineError::Channel(e.to_string()))?
            .into_iter()
            .find(|d| d.name == iface_name)
            .ok_or_else(|| EngineError::Channel(format!("interface not found: {iface_name}")))?;

        let mut cap = Capture::from_device(device)
            .map_err(|e| EngineError::Channel(e.to_string()))?
            .promisc(false)
            .timeout(timeout_ms)
            .open()
            .map_err(|e| EngineError::Channel(e.to_string()))?;

        if !bpf_filter.is_empty() {
            cap.filter(bpf_filter, true)
                .map_err(|e| EngineError::Channel(format!("BPF filter error: {e}")))?;
        }

        Ok(Self { cap })
    }

    pub fn next_packet(&mut self) -> Result<CaptureResult, EngineError> {
        match self.cap.next_packet() {
            Ok(packet) => Ok(CaptureResult::Packet(packet.data.to_vec())),
            Err(pcap::Error::TimeoutExpired) => Ok(CaptureResult::Timeout),
            Err(e) => Err(EngineError::Channel(e.to_string())),
        }
    }
}

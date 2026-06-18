use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{CodecError, checksum, ipv4, ipv6};

pub const LEN: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct UdpHdr {
    pub sport: u16,
    pub dport: u16,
    pub length: u16,
}

impl UdpHdr {
    pub fn encode(&self, buf: &mut [u8], payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Result<usize, CodecError> {
        let total = LEN + payload.len();
        if buf.len() < total {
            return Err(CodecError::BufTooSmall);
        }
        buf[0..2].copy_from_slice(&self.sport.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dport.to_be_bytes());
        let length = self.length;
        buf[4..6].copy_from_slice(&length.to_be_bytes());
        buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        buf[8..8 + payload.len()].copy_from_slice(payload);
        let pseudo = ipv4::Ipv4Hdr::new(ipv4::PROTO_UDP, src, dst, 0).pseudo_checksum(length);
        let mut sum = pseudo;
        checksum::add_slice(&mut sum, &buf[..total]);
        let csum = checksum::fold(sum);
        buf[6..8].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }

    pub fn encode_v6(&self, buf: &mut [u8], payload: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<usize, CodecError> {
        let total = LEN + payload.len();
        if buf.len() < total {
            return Err(CodecError::BufTooSmall);
        }
        buf[0..2].copy_from_slice(&self.sport.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dport.to_be_bytes());
        buf[4..6].copy_from_slice(&self.length.to_be_bytes());
        buf[6..8].copy_from_slice(&0u16.to_be_bytes());
        buf[8..8 + payload.len()].copy_from_slice(payload);
        let pseudo = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_UDP, src, dst, 0)
            .pseudo_checksum(ipv6::NEXT_HDR_UDP, total as u32);
        let mut sum = pseudo;
        checksum::add_slice(&mut sum, &buf[..total]);
        let csum = checksum::fold(sum);
        buf[6..8].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::TruncatedPacket);
        }
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let payload_end = length as usize;
        let payload_end = payload_end.min(buf.len());
        Ok((
            Self {
                sport: u16::from_be_bytes([buf[0], buf[1]]),
                dport: u16::from_be_bytes([buf[2], buf[3]]),
                length,
            },
            &buf[LEN..payload_end],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello";
        let hdr = UdpHdr {
            sport: 12345,
            dport: 53,
            length: (LEN + payload.len()) as u16,
        };
        let mut buf = [0u8; 13];
        hdr.encode(&mut buf, payload, "10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap())
            .unwrap();
        let (dec, data) = UdpHdr::decode(&buf).unwrap();
        assert_eq!(dec.sport, 12345);
        assert_eq!(dec.dport, 53);
        assert_eq!(data, b"hello");
    }
}

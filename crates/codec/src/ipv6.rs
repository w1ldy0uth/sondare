use std::net::Ipv6Addr;
use crate::{CodecError, checksum};

pub const LEN: usize = 40;
pub const NEXT_HDR_TCP: u8 = 6;
pub const NEXT_HDR_UDP: u8 = 17;
pub const NEXT_HDR_ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv6Hdr {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl Ipv6Hdr {
    pub fn new(next_header: u8, src: Ipv6Addr, dst: Ipv6Addr, payload_len: u16) -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_len,
            next_header,
            hop_limit: 64,
            src,
            dst,
        }
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::BufTooSmall);
        }
        let vtf: u32 = (6u32 << 28)
            | ((self.traffic_class as u32) << 20)
            | (self.flow_label & 0xfffff);
        buf[0..4].copy_from_slice(&vtf.to_be_bytes());
        buf[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src.octets());
        buf[24..40].copy_from_slice(&self.dst.octets());
        Ok(LEN)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::TruncatedPacket);
        }
        let vtf = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok((
            Self {
                traffic_class: ((vtf >> 20) & 0xff) as u8,
                flow_label: vtf & 0xfffff,
                payload_len: u16::from_be_bytes([buf[4], buf[5]]),
                next_header: buf[6],
                hop_limit: buf[7],
                src: Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap()),
                dst: Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap()),
            },
            &buf[LEN..],
        ))
    }

    pub fn pseudo_checksum(&self, next_header: u8, payload_len: u32) -> u32 {
        let mut sum = 0u32;
        checksum::add_slice(&mut sum, &self.src.octets());
        checksum::add_slice(&mut sum, &self.dst.octets());
        // upper-layer packet length as u32 BE
        let len_bytes = payload_len.to_be_bytes();
        checksum::add_slice(&mut sum, &len_bytes);
        // next header (zero-padded to 32 bits)
        sum += next_header as u32;
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let hdr = Ipv6Hdr::new(
            NEXT_HDR_ICMPV6,
            "fe80::1".parse().unwrap(),
            "ff02::1".parse().unwrap(),
            16,
        );
        let mut buf = [0u8; 40];
        hdr.encode(&mut buf).unwrap();
        assert_eq!(buf[0] >> 4, 6); // version = 6
        let (dec, rest) = Ipv6Hdr::decode(&buf).unwrap();
        assert_eq!(dec.src, hdr.src);
        assert_eq!(dec.dst, hdr.dst);
        assert_eq!(dec.next_header, NEXT_HDR_ICMPV6);
        assert_eq!(dec.hop_limit, 64);
        assert!(rest.is_empty());
    }
}

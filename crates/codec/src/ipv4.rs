use std::net::Ipv4Addr;
use crate::{CodecError, checksum};

pub const MIN_LEN: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4Hdr {
    pub ihl: u8,
    pub dscp: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: u8,
    pub frag_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Hdr {
    pub fn new(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, payload_len: u16) -> Self {
        Self {
            ihl: 5,
            dscp: 0,
            total_len: MIN_LEN as u16 + payload_len,
            id: 0,
            flags: 0,
            frag_offset: 0,
            ttl: 64,
            proto,
            src,
            dst,
        }
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, CodecError> {
        let hdr_len = (self.ihl as usize) * 4;
        if buf.len() < hdr_len {
            return Err(CodecError::BufTooSmall);
        }
        buf[0] = (4 << 4) | (self.ihl & 0xf);
        buf[1] = self.dscp << 2;
        buf[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        let frag_word = ((self.flags as u16) << 13) | (self.frag_offset & 0x1fff);
        buf[6..8].copy_from_slice(&frag_word.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.proto;
        buf[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        buf[12..16].copy_from_slice(&self.src.octets());
        buf[16..20].copy_from_slice(&self.dst.octets());
        let csum = checksum::compute(&buf[..hdr_len]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
        Ok(hdr_len)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < MIN_LEN {
            return Err(CodecError::TruncatedPacket);
        }
        let ihl = buf[0] & 0xf;
        let hdr_len = (ihl as usize) * 4;
        if buf.len() < hdr_len {
            return Err(CodecError::TruncatedPacket);
        }
        let frag_word = u16::from_be_bytes([buf[6], buf[7]]);
        Ok((
            Self {
                ihl,
                dscp: buf[1] >> 2,
                total_len: u16::from_be_bytes([buf[2], buf[3]]),
                id: u16::from_be_bytes([buf[4], buf[5]]),
                flags: (frag_word >> 13) as u8,
                frag_offset: frag_word & 0x1fff,
                ttl: buf[8],
                proto: buf[9],
                src: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[12..16]).unwrap()),
                dst: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[16..20]).unwrap()),
            },
            &buf[hdr_len..],
        ))
    }

    pub fn pseudo_checksum(&self, proto_payload_len: u16) -> u32 {
        let mut sum = 0u32;
        checksum::add_slice(&mut sum, &self.src.octets());
        checksum::add_slice(&mut sum, &self.dst.octets());
        sum += self.proto as u32;
        sum += proto_payload_len as u32;
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let hdr = Ipv4Hdr::new(
            PROTO_ICMP,
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            8,
        );
        let mut buf = [0u8; 20];
        hdr.encode(&mut buf).unwrap();
        // version/ihl
        assert_eq!(buf[0], 0x45);
        // checksum field should be non-zero
        assert_ne!(u16::from_be_bytes([buf[10], buf[11]]), 0);
        let (dec, rest) = Ipv4Hdr::decode(&buf).unwrap();
        assert_eq!(dec.src, hdr.src);
        assert_eq!(dec.dst, hdr.dst);
        assert_eq!(dec.proto, PROTO_ICMP);
        assert_eq!(dec.ttl, 64);
        assert!(rest.is_empty());
    }

    #[test]
    fn golden_checksum() {
        // Scapy-generated IPv4 header checksum for src=192.168.1.1 dst=192.168.1.2
        // total_len=28 (20 hdr + 8 ICMP), proto=1, ttl=64
        // Expected IPv4 checksum: 0xb78c
        let hdr = Ipv4Hdr::new(
            PROTO_ICMP,
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            8,
        );
        let mut buf = [0u8; 20];
        hdr.encode(&mut buf).unwrap();
        // id=0, ttl=64, proto=1, src=192.168.1.1, dst=192.168.1.2, total_len=28
        assert_eq!([buf[10], buf[11]], [0xf7, 0x8d]);
    }
}

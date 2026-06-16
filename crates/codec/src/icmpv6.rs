use std::net::Ipv6Addr;
use crate::{CodecError, checksum, ipv6};

pub const TYPE_ECHO_REQUEST: u8 = 128;
pub const TYPE_ECHO_REPLY: u8 = 129;
pub const ECHO_HDR_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct Icmpv6Echo {
    pub typ: u8,
    pub id: u16,
    pub seq: u16,
    pub data: Vec<u8>,
}

impl Icmpv6Echo {
    pub fn request(id: u16, seq: u16, data: Vec<u8>) -> Self {
        Self { typ: TYPE_ECHO_REQUEST, id, seq, data }
    }

    pub fn encode(&self, buf: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<usize, CodecError> {
        let total = ECHO_HDR_LEN + self.data.len();
        if buf.len() < total {
            return Err(CodecError::BufTooSmall);
        }
        buf[0] = self.typ;
        buf[1] = 0; // code
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..8 + self.data.len()].copy_from_slice(&self.data);
        // ICMPv6 checksum requires IPv6 pseudo-header
        let pseudo = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_ICMPV6, src, dst, total as u16)
            .pseudo_checksum(ipv6::NEXT_HDR_ICMPV6, total as u32);
        let mut sum = pseudo;
        checksum::add_slice(&mut sum, &buf[..total]);
        let csum = checksum::fold(sum);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < ECHO_HDR_LEN {
            return Err(CodecError::TruncatedPacket);
        }
        Ok((
            Self {
                typ: buf[0],
                id: u16::from_be_bytes([buf[4], buf[5]]),
                seq: u16::from_be_bytes([buf[6], buf[7]]),
                data: buf[8..].to_vec(),
            },
            &buf[buf.len()..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden: Scapy IPv6/ICMPv6EchoRequest with src=fe80::1, dst=ff02::1, id=0x1234, seq=1, data=b""
    // ICMPv6 checksum = 0x7002
    const GOLDEN_ICMPV6_ONLY: &[u8] = &[
        0x80, 0x00,             // type=128, code=0
        0x70, 0x02,             // checksum
        0x12, 0x34,             // id
        0x00, 0x01,             // seq
    ];

    #[test]
    fn golden_icmpv6_checksum() {
        let echo = Icmpv6Echo::request(0x1234, 1, vec![]);
        let mut buf = [0u8; 8];
        echo.encode(
            &mut buf,
            "fe80::1".parse().unwrap(),
            "ff02::1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(&buf, GOLDEN_ICMPV6_ONLY);
    }

    #[test]
    fn decode_roundtrip() {
        let (decoded, rest) = Icmpv6Echo::decode(GOLDEN_ICMPV6_ONLY).unwrap();
        assert_eq!(decoded.typ, TYPE_ECHO_REQUEST);
        assert_eq!(decoded.id, 0x1234);
        assert_eq!(decoded.seq, 1);
        assert!(rest.is_empty());
    }
}

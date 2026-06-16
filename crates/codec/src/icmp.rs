use crate::{CodecError, checksum, ipv4};
use std::net::Ipv4Addr;

pub const TYPE_ECHO_REQUEST: u8 = 8;
pub const TYPE_ECHO_REPLY: u8 = 0;
pub const ECHO_HDR_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct IcmpEcho {
    pub typ: u8,
    pub id: u16,
    pub seq: u16,
    pub data: Vec<u8>,
}

impl IcmpEcho {
    pub fn request(id: u16, seq: u16, data: Vec<u8>) -> Self {
        Self { typ: TYPE_ECHO_REQUEST, id, seq, data }
    }

    pub fn encode_with_pseudo(
        &self,
        buf: &mut [u8],
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Result<usize, CodecError> {
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
        // ICMP checksum: no pseudo-header for IPv4, just the ICMP segment
        let _ = (src, dst); // not used for IPv4 ICMP
        let csum = checksum::compute(&buf[..total]);
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

/// Build Ether + IPv4 + ICMP echo request into `buf`. Returns bytes written.
pub fn icmp_echo_request(
    buf: &mut [u8],
    src_mac: crate::Mac,
    dst_mac: crate::Mac,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    id: u16,
    seq: u16,
    data: Vec<u8>,
) -> Result<usize, CodecError> {
    let icmp_len = ECHO_HDR_LEN + data.len();
    let needed = crate::ether::LEN + ipv4::MIN_LEN + icmp_len;
    if buf.len() < needed {
        return Err(CodecError::BufTooSmall);
    }
    let eth = crate::ether::EtherHdr {
        dst: dst_mac,
        src: src_mac,
        ethertype: crate::ether::ETYPE_IPV4,
    };
    let mut off = eth.encode(buf)?;
    let ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_ICMP, src_ip, dst_ip, icmp_len as u16);
    off += ip.encode(&mut buf[off..])?;
    let echo = IcmpEcho::request(id, seq, data);
    off += echo.encode_with_pseudo(&mut buf[off..], src_ip, dst_ip)?;
    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden: Scapy Ether/IP/ICMP with src=192.168.1.1, dst=192.168.1.2, id=0x04d2, seq=1, data=b""
    // IPv4 checksum = 0xb78c, ICMP checksum = 0xf32c
    const GOLDEN_ICMP_ONLY: &[u8] = &[
        0x08, 0x00,             // type=8, code=0
        0xf3, 0x2c,             // checksum
        0x04, 0xd2,             // id
        0x00, 0x01,             // seq
    ];

    #[test]
    fn golden_icmp_checksum() {
        let echo = IcmpEcho::request(0x04d2, 1, vec![]);
        let mut buf = [0u8; 8];
        echo.encode_with_pseudo(
            &mut buf,
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(&buf, GOLDEN_ICMP_ONLY);
    }

    #[test]
    fn decode_roundtrip() {
        let (decoded, rest) = IcmpEcho::decode(GOLDEN_ICMP_ONLY).unwrap();
        assert_eq!(decoded.typ, TYPE_ECHO_REQUEST);
        assert_eq!(decoded.id, 0x04d2);
        assert_eq!(decoded.seq, 1);
        assert!(rest.is_empty());
    }
}

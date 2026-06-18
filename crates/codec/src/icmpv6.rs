use std::net::Ipv6Addr;
use crate::{CodecError, checksum, ipv6, Mac};

pub const TYPE_ECHO_REQUEST: u8 = 128;
pub const TYPE_ECHO_REPLY: u8 = 129;
pub const TYPE_NEIGHBOR_SOLICIT: u8 = 135;
pub const TYPE_NEIGHBOR_ADVERT: u8 = 136;
pub const TYPE_TIME_EXCEEDED: u8 = 3;
pub const TYPE_DEST_UNREACH: u8 = 1;
pub const ECHO_HDR_LEN: usize = 8;
pub const NS_LEN: usize = 24; // type(1)+code(1)+csum(2)+reserved(4)+target(16)
pub const NS_WITH_SLLA_LEN: usize = 32; // NS_LEN + option type(1)+len(1)+mac(6)

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

/// ICMPv6 Neighbor Solicitation (type 135).
#[derive(Debug, Clone)]
pub struct NeighborSolicit {
    pub target: Ipv6Addr,
    pub src_mac: Mac,
}

impl NeighborSolicit {
    pub fn encode(&self, buf: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<usize, CodecError> {
        if buf.len() < NS_WITH_SLLA_LEN {
            return Err(CodecError::BufTooSmall);
        }
        buf[0] = TYPE_NEIGHBOR_SOLICIT;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        buf[4..8].copy_from_slice(&0u32.to_be_bytes()); // reserved
        buf[8..24].copy_from_slice(&self.target.octets());
        // Source Link-Layer Address option (type=1, len=1 unit of 8 bytes)
        buf[24] = 1;
        buf[25] = 1;
        buf[26..32].copy_from_slice(&self.src_mac);

        let pseudo = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_ICMPV6, src, dst, NS_WITH_SLLA_LEN as u16)
            .pseudo_checksum(ipv6::NEXT_HDR_ICMPV6, NS_WITH_SLLA_LEN as u32);
        let mut sum = pseudo;
        checksum::add_slice(&mut sum, &buf[..NS_WITH_SLLA_LEN]);
        let csum = checksum::fold(sum);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        Ok(NS_WITH_SLLA_LEN)
    }
}

/// ICMPv6 Neighbor Advertisement (type 136) - decode only.
#[derive(Debug, Clone)]
pub struct NeighborAdvert {
    pub target: Ipv6Addr,
    pub target_mac: Option<Mac>,
}

impl NeighborAdvert {
    pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
        if buf.len() < NS_LEN || buf[0] != TYPE_NEIGHBOR_ADVERT {
            return Err(CodecError::TruncatedPacket);
        }
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap());
        // Parse options for Target Link-Layer Address (type=2)
        let mut target_mac = None;
        let mut off = 24;
        while off + 2 <= buf.len() {
            let opt_type = buf[off];
            let opt_len = buf[off + 1] as usize * 8;
            if opt_len == 0 { break; }
            if opt_type == 2 && opt_len >= 8 && off + 8 <= buf.len() {
                target_mac = Some(<[u8; 6]>::try_from(&buf[off + 2..off + 8]).unwrap());
            }
            off += opt_len;
        }
        Ok(Self { target, target_mac })
    }
}

/// Compute the solicited-node multicast address for a given IPv6 address.
/// ff02::1:ffXX:XXXX where XX:XXXX are the last 3 bytes of the address.
pub fn solicited_node_addr(addr: Ipv6Addr) -> Ipv6Addr {
    let oct = addr.octets();
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00 | oct[13] as u16, (oct[14] as u16) << 8 | oct[15] as u16)
}

/// Compute the multicast MAC for a solicited-node multicast address.
pub fn solicited_node_mac(addr: Ipv6Addr) -> Mac {
    let oct = addr.octets();
    [0x33, 0x33, oct[12], oct[13], oct[14], oct[15]]
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

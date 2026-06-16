use std::net::Ipv4Addr;
use crate::{CodecError, Mac, MAC_BROADCAST, MAC_ZERO, ether};

pub const LEN: usize = 28;
pub const OPER_REQUEST: u16 = 1;
pub const OPER_REPLY: u16 = 2;

#[derive(Debug, Clone, PartialEq)]
pub struct ArpHdr {
    pub oper: u16,
    pub sha: Mac,
    pub spa: Ipv4Addr,
    pub tha: Mac,
    pub tpa: Ipv4Addr,
}

impl ArpHdr {
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::BufTooSmall);
        }
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());      // htype = Ethernet
        buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
        buf[4] = 6;                                           // hlen
        buf[5] = 4;                                           // plen
        buf[6..8].copy_from_slice(&self.oper.to_be_bytes());
        buf[8..14].copy_from_slice(&self.sha);
        buf[14..18].copy_from_slice(&self.spa.octets());
        buf[18..24].copy_from_slice(&self.tha);
        buf[24..28].copy_from_slice(&self.tpa.octets());
        Ok(LEN)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::TruncatedPacket);
        }
        Ok((
            Self {
                oper: u16::from_be_bytes([buf[6], buf[7]]),
                sha: buf[8..14].try_into().unwrap(),
                spa: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[14..18]).unwrap()),
                tha: buf[18..24].try_into().unwrap(),
                tpa: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[24..28]).unwrap()),
            },
            &buf[LEN..],
        ))
    }
}

/// Build a complete Ethernet + ARP request frame into `buf`.
pub fn arp_request(
    buf: &mut [u8],
    src_mac: Mac,
    src_ip: Ipv4Addr,
    tgt_ip: Ipv4Addr,
) -> Result<usize, CodecError> {
    if buf.len() < ether::LEN + LEN {
        return Err(CodecError::BufTooSmall);
    }
    let eth = crate::ether::EtherHdr {
        dst: MAC_BROADCAST,
        src: src_mac,
        ethertype: ether::ETYPE_ARP,
    };
    let n = eth.encode(buf)?;
    let m = ArpHdr {
        oper: OPER_REQUEST,
        sha: src_mac,
        spa: src_ip,
        tha: MAC_ZERO,
        tpa: tgt_ip,
    }
    .encode(&mut buf[n..])?;
    Ok(n + m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_ARP_REQUEST: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac (broadcast)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src mac
        0x08, 0x06,                         // ethertype ARP
        0x00, 0x01,                         // htype Ethernet
        0x08, 0x00,                         // ptype IPv4
        0x06,                               // hlen
        0x04,                               // plen
        0x00, 0x01,                         // oper request
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // sha
        0xc0, 0xa8, 0x01, 0x01,             // spa 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tha zero
        0xc0, 0xa8, 0x01, 0x02,             // tpa 192.168.1.2
    ];

    #[test]
    fn golden_encode() {
        let mut buf = [0u8; 42];
        let n = arp_request(
            &mut buf,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(&buf[..n], GOLDEN_ARP_REQUEST);
    }

    #[test]
    fn decode_roundtrip() {
        let (_, arp_bytes) = GOLDEN_ARP_REQUEST.split_at(ether::LEN);
        let (hdr, rest) = ArpHdr::decode(arp_bytes).unwrap();
        assert_eq!(hdr.oper, OPER_REQUEST);
        assert_eq!(hdr.sha, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(hdr.spa, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hdr.tpa, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        assert!(rest.is_empty());
    }
}

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{CodecError, checksum, ipv4, ipv6};

pub const FLAG_FIN: u16 = 0x001;
pub const FLAG_SYN: u16 = 0x002;
pub const FLAG_RST: u16 = 0x004;
pub const FLAG_PSH: u16 = 0x008;
pub const FLAG_ACK: u16 = 0x010;
pub const FLAG_URG: u16 = 0x020;

#[derive(Debug, Clone, PartialEq)]
pub enum TcpOption {
    Mss(u16),
    Nop,
    WScale(u8),
    SackPermitted,
    Timestamp { tsval: u32, tsecr: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpHdr {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
    pub urgent: u16,
    pub options: Vec<TcpOption>,
}

impl TcpHdr {
    pub fn syn(sport: u16, dport: u16, seq: u32) -> Self {
        Self {
            sport,
            dport,
            seq,
            ack: 0,
            flags: FLAG_SYN,
            window: 65535,
            urgent: 0,
            options: vec![],
        }
    }

    fn options_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for opt in &self.options {
            match opt {
                TcpOption::Nop => out.push(1),
                TcpOption::Mss(v) => {
                    out.push(2);
                    out.push(4);
                    out.extend_from_slice(&v.to_be_bytes());
                }
                TcpOption::WScale(s) => {
                    out.push(3);
                    out.push(3);
                    out.push(*s);
                }
                TcpOption::SackPermitted => {
                    out.push(4);
                    out.push(2);
                }
                TcpOption::Timestamp { tsval, tsecr } => {
                    out.push(8);
                    out.push(10);
                    out.extend_from_slice(&tsval.to_be_bytes());
                    out.extend_from_slice(&tsecr.to_be_bytes());
                }
            }
        }
        // pad to 4-byte boundary
        while out.len() % 4 != 0 {
            out.push(0); // EOL
        }
        out
    }

    pub fn encode(&self, buf: &mut [u8], payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Result<usize, CodecError> {
        let opts = self.options_bytes();
        let data_offset = (20 + opts.len()) / 4;
        let hdr_len = data_offset * 4;
        let total = hdr_len + payload.len();
        if buf.len() < total {
            return Err(CodecError::BufTooSmall);
        }
        buf[0..2].copy_from_slice(&self.sport.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dport.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.to_be_bytes());
        buf[12] = (data_offset as u8) << 4;
        buf[13] = (self.flags & 0xff) as u8;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        buf[18..20].copy_from_slice(&self.urgent.to_be_bytes());
        buf[20..20 + opts.len()].copy_from_slice(&opts);
        if !payload.is_empty() {
            buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);
        }
        let pseudo = ipv4::Ipv4Hdr::new(ipv4::PROTO_TCP, src, dst, 0)
            .pseudo_checksum(total as u16);
        let mut sum = pseudo;
        checksum::add_slice(&mut sum, &buf[..total]);
        let csum = checksum::fold(sum);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }

    pub fn encode_v6(&self, buf: &mut [u8], payload: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<usize, CodecError> {
        let opts = self.options_bytes();
        let data_offset = (20 + opts.len()) / 4;
        let hdr_len = data_offset * 4;
        let total = hdr_len + payload.len();
        if buf.len() < total {
            return Err(CodecError::BufTooSmall);
        }
        buf[0..2].copy_from_slice(&self.sport.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dport.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.to_be_bytes());
        buf[12] = (data_offset as u8) << 4;
        buf[13] = (self.flags & 0xff) as u8;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&0u16.to_be_bytes());
        buf[18..20].copy_from_slice(&self.urgent.to_be_bytes());
        buf[20..20 + opts.len()].copy_from_slice(&opts);
        if !payload.is_empty() {
            buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);
        }
        let pseudo = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_TCP, src, dst, 0)
            .pseudo_checksum(ipv6::NEXT_HDR_TCP, total as u32);
        let mut sum = pseudo;
        checksum::add_slice(&mut sum, &buf[..total]);
        let csum = checksum::fold(sum);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < 20 {
            return Err(CodecError::TruncatedPacket);
        }
        let data_offset = (buf[12] >> 4) as usize;
        let hdr_len = data_offset * 4;
        if buf.len() < hdr_len {
            return Err(CodecError::TruncatedPacket);
        }
        let flags = (((buf[12] & 0x0f) as u16) << 8) | (buf[13] as u16);
        let options = decode_options(&buf[20..hdr_len]);
        Ok((
            Self {
                sport: u16::from_be_bytes([buf[0], buf[1]]),
                dport: u16::from_be_bytes([buf[2], buf[3]]),
                seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
                ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
                flags,
                window: u16::from_be_bytes([buf[14], buf[15]]),
                urgent: u16::from_be_bytes([buf[18], buf[19]]),
                options,
            },
            &buf[hdr_len..],
        ))
    }
}

fn decode_options(buf: &[u8]) -> Vec<TcpOption> {
    let mut opts = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        match buf[i] {
            0 => break,  // EOL
            1 => { opts.push(TcpOption::Nop); i += 1; }
            2 if i + 4 <= buf.len() => {
                let v = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
                opts.push(TcpOption::Mss(v));
                i += 4;
            }
            3 if i + 3 <= buf.len() => {
                opts.push(TcpOption::WScale(buf[i + 2]));
                i += 3;
            }
            4 if i + 2 <= buf.len() => {
                opts.push(TcpOption::SackPermitted);
                i += 2;
            }
            8 if i + 10 <= buf.len() => {
                let tsval = u32::from_be_bytes([buf[i+2], buf[i+3], buf[i+4], buf[i+5]]);
                let tsecr = u32::from_be_bytes([buf[i+6], buf[i+7], buf[i+8], buf[i+9]]);
                opts.push(TcpOption::Timestamp { tsval, tsecr });
                i += 10;
            }
            kind => {
                if i + 1 >= buf.len() { break; }
                let len = buf[i + 1] as usize;
                if len < 2 { break; }
                i += len;
                let _ = kind;
            }
        }
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden: Scapy TCP SYN sport=12345, dport=80, seq=0x12345678, window=65535, no options
    // TCP checksum = 0x9359
    const GOLDEN_TCP_SYN_NO_OPTS: &[u8] = &[
        0x30, 0x39, // sport 12345
        0x00, 0x50, // dport 80
        0x12, 0x34, 0x56, 0x78, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50,       // data_offset=5, reserved=0
        0x02,       // flags: SYN
        0xff, 0xff, // window
        0x93, 0x59, // checksum
        0x00, 0x00, // urgent
    ];

    #[test]
    fn golden_syn_no_opts() {
        let mut hdr = TcpHdr::syn(12345, 80, 0x12345678);
        hdr.window = 65535;
        let mut buf = [0u8; 20];
        hdr.encode(&mut buf, &[], "192.168.1.1".parse().unwrap(), "192.168.1.2".parse().unwrap())
            .unwrap();
        assert_eq!(&buf, GOLDEN_TCP_SYN_NO_OPTS);
    }

    #[test]
    fn decode_syn_no_opts() {
        let (hdr, rest) = TcpHdr::decode(GOLDEN_TCP_SYN_NO_OPTS).unwrap();
        assert_eq!(hdr.sport, 12345);
        assert_eq!(hdr.dport, 80);
        assert_eq!(hdr.seq, 0x12345678);
        assert_eq!(hdr.flags, FLAG_SYN);
        assert_eq!(hdr.window, 65535);
        assert!(rest.is_empty());
    }

    #[test]
    fn syn_with_options_roundtrip() {
        let mut hdr = TcpHdr::syn(12345, 80, 0x12345678);
        hdr.options = vec![
            TcpOption::Mss(1460),
            TcpOption::Nop,
            TcpOption::WScale(7),
            TcpOption::Nop,
            TcpOption::Nop,
            TcpOption::SackPermitted,
        ];
        let mut buf = [0u8; 40];
        let n = hdr.encode(&mut buf, &[], "192.168.1.1".parse().unwrap(), "192.168.1.2".parse().unwrap())
            .unwrap();
        let (dec, rest) = TcpHdr::decode(&buf[..n]).unwrap();
        assert_eq!(dec.sport, hdr.sport);
        assert_eq!(dec.dport, hdr.dport);
        assert_eq!(dec.seq, hdr.seq);
        assert_eq!(dec.flags, FLAG_SYN);
        assert!(rest.is_empty());
        // MSS should decode correctly
        assert!(dec.options.iter().any(|o| matches!(o, TcpOption::Mss(1460))));
        assert!(dec.options.iter().any(|o| matches!(o, TcpOption::WScale(7))));
        assert!(dec.options.iter().any(|o| matches!(o, TcpOption::SackPermitted)));
    }
}

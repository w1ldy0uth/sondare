use crate::{CodecError, Mac};

pub const LEN: usize = 14;

pub const ETYPE_IPV4: u16 = 0x0800;
pub const ETYPE_ARP: u16 = 0x0806;
pub const ETYPE_IPV6: u16 = 0x86DD;

#[derive(Debug, Clone, PartialEq)]
pub struct EtherHdr {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
}

impl EtherHdr {
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::BufTooSmall);
        }
        buf[0..6].copy_from_slice(&self.dst);
        buf[6..12].copy_from_slice(&self.src);
        buf[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        Ok(LEN)
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        if buf.len() < LEN {
            return Err(CodecError::TruncatedPacket);
        }
        Ok((
            Self {
                dst: buf[0..6].try_into().unwrap(),
                src: buf[6..12].try_into().unwrap(),
                ethertype: u16::from_be_bytes([buf[12], buf[13]]),
            },
            &buf[LEN..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let hdr = EtherHdr {
            dst: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            src: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ethertype: ETYPE_IPV4,
        };
        let mut buf = [0u8; 14];
        hdr.encode(&mut buf).unwrap();
        let (decoded, rest) = EtherHdr::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
        assert!(rest.is_empty());
    }
}

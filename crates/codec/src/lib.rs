mod error;
pub mod checksum;
pub mod ether;
pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod udp;

pub use error::CodecError;

pub type Mac = [u8; 6];

pub const MAC_BROADCAST: Mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
pub const MAC_ZERO: Mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

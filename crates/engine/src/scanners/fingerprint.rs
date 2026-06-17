use std::net::Ipv4Addr;
use std::time::Duration;
use sondare_codec::{ether, ipv4, tcp as tcp_codec, tcp::TcpOption, Mac};
use sondare_datalink::{by_name, Iface};

use crate::{sweep, EngineError, SweepConfig};
use crate::scanners::arp::resolve_mac;

const PROBE_SPORT: u16 = 0xDEAD;

pub struct FingerprintResult {
    pub ttl: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub has_timestamps: bool,
    pub has_sack: bool,
}

fn build_syn(src_mac: Mac, dst_mac: Mac, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let tcp_len = 20usize;
    let mut buf = vec![0u8; ether::LEN + ipv4::MIN_LEN + tcp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV4 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_TCP, src_ip, dst_ip, tcp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let mut hdr = tcp_codec::TcpHdr::syn(PROBE_SPORT, port, 0xF1_0000u32.wrapping_add(port as u32));
    hdr.window = 65535;
    hdr.encode(&mut buf[off..], &[], src_ip, dst_ip).unwrap();

    buf
}

fn parse_synack(raw: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Option<FingerprintResult> {
    if raw.len() < ether::LEN + ipv4::MIN_LEN + 20 { return None; }
    let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
    let (ip, rest) = ipv4::Ipv4Hdr::decode(rest).ok()?;
    if ip.proto != ipv4::PROTO_TCP || ip.src != dst_ip || ip.dst != src_ip { return None; }
    let (hdr, _) = tcp_codec::TcpHdr::decode(rest).ok()?;
    if hdr.dport != PROBE_SPORT { return None; }

    let sa = tcp_codec::FLAG_SYN | tcp_codec::FLAG_ACK;
    if hdr.flags & sa != sa { return None; }

    let mut mss = None;
    let mut wscale = None;
    let mut has_timestamps = false;
    let mut has_sack = false;
    for opt in &hdr.options {
        match opt {
            TcpOption::Mss(v) => mss = Some(*v),
            TcpOption::WScale(v) => wscale = Some(*v),
            TcpOption::Timestamp { .. } => has_timestamps = true,
            TcpOption::SackPermitted => has_sack = true,
            TcpOption::Nop => {}
        }
    }

    Some(FingerprintResult {
        ttl: ip.ttl,
        window: hdr.window,
        mss,
        wscale,
        has_timestamps,
        has_sack,
    })
}

/// Probe ports via TCP SYN looking for a SYN-ACK to fingerprint the target OS.
///
/// Returns the first SYN-ACK's TTL, window size, and TCP options,
/// or None if no port responded with SYN-ACK.
pub fn fingerprint_v4(
    iface_name: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
) -> Result<Option<FingerprintResult>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv4
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv4 address")))?;
    let src_mac = iface.mac;
    let dst_ip: Ipv4Addr = target_ip
        .parse()
        .map_err(|_| EngineError::Channel(format!("invalid target IP: {target_ip}")))?;
    let dst_mac = resolve_mac(iface_name, dst_ip, Duration::from_secs(2))?;

    let cfg = SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) };

    let results = sweep(
        &iface,
        ports.into_iter(),
        move |port| Some(build_syn(src_mac, dst_mac, src_ip, dst_ip, port)),
        move |raw| parse_synack(raw, src_ip, dst_ip),
        cfg,
    )?;

    Ok(results.into_iter().next())
}

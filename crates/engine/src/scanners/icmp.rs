use std::net::Ipv4Addr;
use std::time::Duration;

use sondare_codec::{ether, icmp, ipv4, Mac};
use sondare_datalink::{by_name, Iface};

use crate::{sweep, EngineError, SweepConfig};

const PROBE_ID: u16 = 0x5a1e; // "sale" - avoids clashing with other ICMP tools

fn build_frame(src_mac: Mac, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, seq: u16) -> Vec<u8> {
    let icmp_len = icmp::ECHO_HDR_LEN;
    let mut buf = vec![0u8; ether::LEN + ipv4::MIN_LEN + icmp_len];
    let dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // broadcast; routed back by local switch

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV4 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_ICMP, src_ip, dst_ip, icmp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let echo = icmp::IcmpEcho::request(PROBE_ID, seq, vec![]);
    echo.encode_with_pseudo(&mut buf[off..], src_ip, dst_ip).unwrap();

    buf
}

fn parse_reply(raw: &[u8], src_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    if raw.len() < ether::LEN + ipv4::MIN_LEN + icmp::ECHO_HDR_LEN {
        return None;
    }
    let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
    let (ip, rest) = ipv4::Ipv4Hdr::decode(rest).ok()?;
    // Only accept packets destined for us
    if ip.proto != ipv4::PROTO_ICMP || ip.dst != src_ip {
        return None;
    }
    let (echo, _) = icmp::IcmpEcho::decode(rest).ok()?;
    if echo.typ == icmp::TYPE_ECHO_REPLY && echo.id == PROBE_ID {
        Some(ip.src)
    } else {
        None
    }
}

/// Sweep a list of IPv4 targets via ICMP echo. Returns responding IP strings.
pub fn icmp_sweep_v4(
    iface_name: &str,
    targets: Vec<String>,
    pps: u32,
    grace_ms: u64,
) -> Result<Vec<String>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv4
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv4 address")))?;
    let src_mac = iface.mac;

    let parsed: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let results = sweep(
        &iface,
        parsed.into_iter().enumerate(),
        move |(seq, dst_ip)| Some(build_frame(src_mac, src_ip, dst_ip, seq as u16)),
        move |raw| parse_reply(raw, src_ip).map(|ip| ip.to_string()),
        SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) },
    )?;

    Ok(results)
}

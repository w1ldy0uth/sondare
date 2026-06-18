use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use sondare_codec::{ether, icmp, icmpv6, ipv4, ipv6, Mac};
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

const PROBE_ID_V6: u16 = 0x5afe;

fn build_frame_v6(src_mac: Mac, dst_mac: Mac, src_ip: Ipv6Addr, dst_ip: Ipv6Addr, seq: u16) -> Vec<u8> {
    let icmp_len = icmpv6::ECHO_HDR_LEN;
    let mut buf = vec![0u8; ether::LEN + ipv6::LEN + icmp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV6 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_ICMPV6, src_ip, dst_ip, icmp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let echo = icmpv6::Icmpv6Echo::request(PROBE_ID_V6, seq, vec![]);
    echo.encode(&mut buf[off..], src_ip, dst_ip).unwrap();

    buf
}

fn parse_reply_v6(raw: &[u8], src_ip: Ipv6Addr) -> Option<Ipv6Addr> {
    if raw.len() < ether::LEN + ipv6::LEN + icmpv6::ECHO_HDR_LEN {
        return None;
    }
    let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
    if eth.ethertype != ether::ETYPE_IPV6 { return None; }
    let (ip, rest) = ipv6::Ipv6Hdr::decode(rest).ok()?;
    if ip.next_header != ipv6::NEXT_HDR_ICMPV6 || ip.dst != src_ip { return None; }
    let (echo, _) = icmpv6::Icmpv6Echo::decode(rest).ok()?;
    if echo.typ == icmpv6::TYPE_ECHO_REPLY && echo.id == PROBE_ID_V6 {
        Some(ip.src)
    } else {
        None
    }
}

/// Sweep a list of IPv6 targets via ICMPv6 echo. Returns responding IP strings.
///
/// Each target's MAC is resolved via NDP Neighbor Solicitation before probing.
/// Targets whose MAC cannot be resolved are silently skipped.
pub fn icmp_sweep_v6(
    iface_name: &str,
    targets: Vec<String>,
    pps: u32,
    grace_ms: u64,
) -> Result<Vec<String>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv6_ll
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv6 link-local address")))?;
    let src_mac = iface.mac;

    // Resolve MACs for each target
    let mut resolved: Vec<(Ipv6Addr, Mac)> = Vec::new();
    for t in &targets {
        if let Ok(dst_ip) = t.parse::<Ipv6Addr>() {
            if let Ok(mac) = super::ndp::resolve_mac_v6(iface_name, dst_ip, Duration::from_secs(2)) {
                resolved.push((dst_ip, mac));
            }
        }
    }

    let results = sweep(
        &iface,
        resolved.into_iter().enumerate(),
        move |(seq, (dst_ip, dst_mac))| Some(build_frame_v6(src_mac, dst_mac, src_ip, dst_ip, seq as u16)),
        move |raw| parse_reply_v6(raw, src_ip).map(|ip| ip.to_string()),
        SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) },
    )?;

    Ok(results)
}

/// ICMPv6 multicast sweep of ff02::1 (all-nodes). Returns responding IP strings.
///
/// Unlike icmp_sweep_v6, this sends a single probe to the multicast address
/// and collects all replies. The scanner's own link-local address is excluded.
pub fn icmp_multicast_v6(
    iface_name: &str,
    pps: u32,
    grace_ms: u64,
) -> Result<Vec<String>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv6_ll
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv6 link-local address")))?;
    let src_mac = iface.mac;
    let dst_mac: Mac = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];
    let dst_ip: Ipv6Addr = "ff02::1".parse().unwrap();

    let results = sweep(
        &iface,
        std::iter::once(()),
        move |()| Some(build_frame_v6(src_mac, dst_mac, src_ip, dst_ip, 1)),
        move |raw| {
            let ip = parse_reply_v6(raw, src_ip)?;
            if ip == src_ip || ip.segments()[0] == 0xff02 { return None; }
            Some(ip.to_string())
        },
        SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) },
    )?;

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    Ok(results.into_iter().filter(|ip| seen.insert(ip.clone())).collect())
}

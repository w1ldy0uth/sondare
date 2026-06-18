use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use sondare_codec::{ether, ipv4, ipv6, udp as udp_codec, icmp, icmpv6, Mac};
use sondare_datalink::{by_name, Iface};

use crate::{sweep, EngineError, SweepConfig};
use crate::scanners::arp::resolve_mac;
use crate::scanners::ndp::resolve_mac_v6;

const PROBE_SPORT: u16 = 0xBEEF;

fn build_udp_probe(src_mac: Mac, dst_mac: Mac, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let udp_len = udp_codec::LEN;
    let mut buf = vec![0u8; ether::LEN + ipv4::MIN_LEN + udp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV4 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_UDP, src_ip, dst_ip, udp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let hdr = udp_codec::UdpHdr { sport: PROBE_SPORT, dport: port, length: udp_len as u16 };
    hdr.encode(&mut buf[off..], &[], src_ip, dst_ip).unwrap();

    buf
}

fn parse_icmp_unreach(raw: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Option<u16> {
    if raw.len() < ether::LEN + ipv4::MIN_LEN + icmp::ECHO_HDR_LEN + ipv4::MIN_LEN + udp_codec::LEN {
        return None;
    }
    let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
    let (ip, rest) = ipv4::Ipv4Hdr::decode(rest).ok()?;
    if ip.proto != ipv4::PROTO_ICMP || ip.src != dst_ip || ip.dst != src_ip { return None; }

    // ICMP header: type(1) code(1) checksum(2) unused(4) = 8 bytes
    if rest.len() < 8 { return None; }
    let icmp_type = rest[0];
    let icmp_code = rest[1];
    if icmp_type != 3 || icmp_code != 3 { return None; }

    // After the 8-byte ICMP header: the original IP header + at least 8 bytes of original UDP
    let inner = &rest[8..];
    let (inner_ip, inner_rest) = ipv4::Ipv4Hdr::decode(inner).ok()?;
    if inner_ip.src != src_ip || inner_ip.dst != dst_ip { return None; }
    if inner_rest.len() < 4 { return None; }

    let inner_sport = u16::from_be_bytes([inner_rest[0], inner_rest[1]]);
    let inner_dport = u16::from_be_bytes([inner_rest[2], inner_rest[3]]);
    if inner_sport != PROBE_SPORT { return None; }

    Some(inner_dport)
}

/// UDP scan a list of ports on a single IPv4 target. Returns open|filtered port numbers.
///
/// Sends empty UDP datagrams. Ports that reply with ICMP port-unreachable (type 3, code 3)
/// are confirmed closed. Ports with no response after two passes are reported as open|filtered.
pub fn udp_scan_v4(
    iface_name: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
    retries: u32,
) -> Result<Vec<u16>, EngineError> {
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

    let first = sweep(
        &iface,
        ports.iter().copied(),
        move |port| Some(build_udp_probe(src_mac, dst_mac, src_ip, dst_ip, port)),
        move |raw| parse_icmp_unreach(raw, src_ip, dst_ip),
        cfg,
    )?;

    let mut closed: HashSet<u16> = first.into_iter().collect();

    for _ in 0..retries {
        let silent: Vec<u16> = ports.iter()
            .filter(|&&p| !closed.contains(&p))
            .copied()
            .collect();
        if silent.is_empty() { break; }

        let retry = sweep(
            &iface,
            silent.into_iter(),
            move |port| Some(build_udp_probe(src_mac, dst_mac, src_ip, dst_ip, port)),
            move |raw| parse_icmp_unreach(raw, src_ip, dst_ip),
            cfg,
        )?;
        for p in retry {
            closed.insert(p);
        }
    }

    let mut open: Vec<u16> = ports.into_iter()
        .filter(|p| !closed.contains(p))
        .collect();
    open.sort_unstable();
    Ok(open)
}

fn build_udp_probe_v6(src_mac: Mac, dst_mac: Mac, src_ip: Ipv6Addr, dst_ip: Ipv6Addr, port: u16) -> Vec<u8> {
    let udp_len = udp_codec::LEN;
    let mut buf = vec![0u8; ether::LEN + ipv6::LEN + udp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV6 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_UDP, src_ip, dst_ip, udp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let hdr = udp_codec::UdpHdr { sport: PROBE_SPORT, dport: port, length: udp_len as u16 };
    hdr.encode_v6(&mut buf[off..], &[], src_ip, dst_ip).unwrap();

    buf
}

fn parse_icmpv6_unreach(raw: &[u8], src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Option<u16> {
    // ICMPv6 Destination Unreachable (type 1) with code 4 = port unreachable
    if raw.len() < ether::LEN + ipv6::LEN + 8 + ipv6::LEN + udp_codec::LEN { return None; }
    let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
    if eth.ethertype != ether::ETYPE_IPV6 { return None; }
    let (ip, rest) = ipv6::Ipv6Hdr::decode(rest).ok()?;
    if ip.next_header != ipv6::NEXT_HDR_ICMPV6 || ip.src != dst_ip || ip.dst != src_ip { return None; }

    // ICMPv6: type(1) code(1) checksum(2) unused(4) = 8 bytes
    if rest.len() < 8 { return None; }
    if rest[0] != icmpv6::TYPE_DEST_UNREACH || rest[1] != 4 { return None; }

    // Embedded original IPv6 header + UDP
    let inner = &rest[8..];
    let (inner_ip, inner_rest) = ipv6::Ipv6Hdr::decode(inner).ok()?;
    if inner_ip.src != src_ip || inner_ip.dst != dst_ip { return None; }
    if inner_rest.len() < 4 { return None; }

    let inner_sport = u16::from_be_bytes([inner_rest[0], inner_rest[1]]);
    let inner_dport = u16::from_be_bytes([inner_rest[2], inner_rest[3]]);
    if inner_sport != PROBE_SPORT { return None; }

    Some(inner_dport)
}

/// UDP scan a list of ports on a single IPv6 target. Returns open|filtered port numbers.
pub fn udp_scan_v6(
    iface_name: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
    retries: u32,
) -> Result<Vec<u16>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv6_ll
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv6 link-local address")))?;
    let src_mac = iface.mac;
    let dst_ip: Ipv6Addr = target_ip
        .parse()
        .map_err(|_| EngineError::Channel(format!("invalid target IPv6: {target_ip}")))?;
    let dst_mac = resolve_mac_v6(iface_name, dst_ip, Duration::from_secs(2))?;

    let cfg = SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) };

    let first = sweep(
        &iface,
        ports.iter().copied(),
        move |port| Some(build_udp_probe_v6(src_mac, dst_mac, src_ip, dst_ip, port)),
        move |raw| parse_icmpv6_unreach(raw, src_ip, dst_ip),
        cfg,
    )?;

    let mut closed: HashSet<u16> = first.into_iter().collect();

    for _ in 0..retries {
        let silent: Vec<u16> = ports.iter()
            .filter(|&&p| !closed.contains(&p))
            .copied()
            .collect();
        if silent.is_empty() { break; }

        let retry = sweep(
            &iface,
            silent.into_iter(),
            move |port| Some(build_udp_probe_v6(src_mac, dst_mac, src_ip, dst_ip, port)),
            move |raw| parse_icmpv6_unreach(raw, src_ip, dst_ip),
            cfg,
        )?;
        for p in retry {
            closed.insert(p);
        }
    }

    let mut open: Vec<u16> = ports.into_iter()
        .filter(|p| !closed.contains(p))
        .collect();
    open.sort_unstable();
    Ok(open)
}

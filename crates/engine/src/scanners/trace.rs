use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use sondare_codec::{ether, ipv4, ipv6, icmp, icmpv6, Mac};
use sondare_datalink::{by_name, RawChannel};

use crate::EngineError;
use crate::scanners::arp::resolve_mac;
use crate::scanners::ndp::resolve_mac_v6;

const ICMP_TIME_EXCEEDED: u8 = 11;
const PROBE_ID: u16 = 0xDA7E;

pub struct HopResult {
    pub ttl: u8,
    pub ip: Option<String>,
    pub rtt_ms: Option<f64>,
}

fn build_echo(src_mac: Mac, dst_mac: Mac, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, ttl: u8, seq: u16) -> Vec<u8> {
    let icmp_len = icmp::ECHO_HDR_LEN;
    let mut buf = vec![0u8; ether::LEN + ipv4::MIN_LEN + icmp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV4 };
    let mut off = eth.encode(&mut buf).unwrap();

    let mut ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_ICMP, src_ip, dst_ip, icmp_len as u16);
    ip.ttl = ttl;
    off += ip.encode(&mut buf[off..]).unwrap();

    let echo = icmp::IcmpEcho::request(PROBE_ID, seq, vec![]);
    echo.encode_with_pseudo(&mut buf[off..], src_ip, dst_ip).unwrap();

    buf
}

fn parse_response(raw: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, seq: u16) -> Option<String> {
    if raw.len() < ether::LEN + ipv4::MIN_LEN + 8 { return None; }
    let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
    if eth.ethertype != ether::ETYPE_IPV4 { return None; }
    let (ip, rest) = ipv4::Ipv4Hdr::decode(rest).ok()?;
    if ip.proto != ipv4::PROTO_ICMP { return None; }
    if rest.len() < 8 { return None; }

    let icmp_type = rest[0];

    if icmp_type == icmp::TYPE_ECHO_REPLY && ip.src == dst_ip && ip.dst == src_ip {
        let (echo, _) = icmp::IcmpEcho::decode(rest).ok()?;
        if echo.id == PROBE_ID && echo.seq == seq {
            return Some(ip.src.to_string());
        }
    }

    if icmp_type == ICMP_TIME_EXCEEDED && ip.dst == src_ip {
        // After 8-byte ICMP header: original IP header + at least 8 bytes of original ICMP
        let inner = &rest[8..];
        if inner.len() < ipv4::MIN_LEN + 8 { return None; }
        let (inner_ip, inner_rest) = ipv4::Ipv4Hdr::decode(inner).ok()?;
        if inner_ip.src != src_ip || inner_ip.dst != dst_ip { return None; }
        if inner_rest.len() < 8 { return None; }
        let (inner_echo, _) = icmp::IcmpEcho::decode(inner_rest).ok()?;
        if inner_echo.id == PROBE_ID && inner_echo.seq == seq {
            return Some(ip.src.to_string());
        }
    }

    None
}

/// Traceroute to an IPv4 target. Returns a list of hops.
///
/// Uses the gateway MAC for forwarding (resolved via ARP to the target or default route).
/// Each hop sends one ICMP echo probe and waits up to `timeout` for a response.
pub fn traceroute_v4(
    iface_name: &str,
    target_ip: &str,
    max_hops: u8,
    timeout_ms: u64,
) -> Result<Vec<HopResult>, EngineError> {
    let iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv4
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv4 address")))?;
    let src_mac = iface.mac;
    let dst_ip: Ipv4Addr = target_ip
        .parse()
        .map_err(|_| EngineError::Channel(format!("invalid target IP: {target_ip}")))?;

    // Resolve gateway MAC. For LAN targets this resolves directly;
    // for remote targets ARP goes to the default gateway which answers.
    let dst_mac = resolve_mac(iface_name, dst_ip, Duration::from_secs(2))
        .or_else(|_| {
            // Target may not be on LAN; try resolving gateway via a common default
            let gateway = default_gateway(src_ip);
            resolve_mac(iface_name, gateway, Duration::from_secs(2))
        })?;

    let mut chan = RawChannel::open(&iface)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let timeout = Duration::from_millis(timeout_ms);

    let mut hops = Vec::new();

    for ttl in 1..=max_hops {
        let frame = build_echo(src_mac, dst_mac, src_ip, dst_ip, ttl, ttl as u16);
        chan.send(&frame).map_err(|e| EngineError::Channel(e.to_string()))?;

        let t0 = Instant::now();
        let result = chan.recv_filter(timeout, |raw| {
            parse_response(raw, src_ip, dst_ip, ttl as u16)
        });

        match result {
            Ok(hop_ip) => {
                let rtt = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
                let reached_target = hop_ip == target_ip;
                hops.push(HopResult { ttl, ip: Some(hop_ip), rtt_ms: Some(rtt) });
                if reached_target {
                    break;
                }
            }
            Err(_) => {
                hops.push(HopResult { ttl, ip: None, rtt_ms: None });
            }
        }
    }

    Ok(hops)
}

fn default_gateway(src_ip: Ipv4Addr) -> Ipv4Addr {
    let octets = src_ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
}

const ICMPV6_TIME_EXCEEDED: u8 = 3;
const PROBE_ID_V6: u16 = 0xDA7E;

fn build_echo_v6(src_mac: Mac, dst_mac: Mac, src_ip: Ipv6Addr, dst_ip: Ipv6Addr, hlim: u8, seq: u16) -> Vec<u8> {
    let icmp_len = icmpv6::ECHO_HDR_LEN;
    let mut buf = vec![0u8; ether::LEN + ipv6::LEN + icmp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV6 };
    let mut off = eth.encode(&mut buf).unwrap();

    let mut ip = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_ICMPV6, src_ip, dst_ip, icmp_len as u16);
    ip.hop_limit = hlim;
    off += ip.encode(&mut buf[off..]).unwrap();

    let echo = icmpv6::Icmpv6Echo::request(PROBE_ID_V6, seq, vec![]);
    echo.encode(&mut buf[off..], src_ip, dst_ip).unwrap();

    buf
}

fn parse_response_v6(raw: &[u8], src_ip: Ipv6Addr, dst_ip: Ipv6Addr, seq: u16) -> Option<String> {
    if raw.len() < ether::LEN + ipv6::LEN + 8 { return None; }
    let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
    if eth.ethertype != ether::ETYPE_IPV6 { return None; }
    let (ip, rest) = ipv6::Ipv6Hdr::decode(rest).ok()?;
    if ip.next_header != ipv6::NEXT_HDR_ICMPV6 { return None; }
    if rest.len() < 8 { return None; }

    let icmp_type = rest[0];

    // Echo Reply from destination
    if icmp_type == icmpv6::TYPE_ECHO_REPLY && ip.src == dst_ip && ip.dst == src_ip {
        let (echo, _) = icmpv6::Icmpv6Echo::decode(rest).ok()?;
        if echo.id == PROBE_ID_V6 && echo.seq == seq {
            return Some(ip.src.to_string());
        }
    }

    // Time Exceeded from intermediate router
    if icmp_type == ICMPV6_TIME_EXCEEDED && ip.dst == src_ip {
        // After 8-byte ICMPv6 header: original IPv6 header + at least 8 bytes of original ICMPv6
        let inner = &rest[8..];
        if inner.len() < ipv6::LEN + icmpv6::ECHO_HDR_LEN { return None; }
        let (inner_ip, inner_rest) = ipv6::Ipv6Hdr::decode(inner).ok()?;
        if inner_ip.src != src_ip || inner_ip.dst != dst_ip { return None; }
        if inner_rest.len() < icmpv6::ECHO_HDR_LEN { return None; }
        let (inner_echo, _) = icmpv6::Icmpv6Echo::decode(inner_rest).ok()?;
        if inner_echo.id == PROBE_ID_V6 && inner_echo.seq == seq {
            return Some(ip.src.to_string());
        }
    }

    None
}

/// Traceroute to an IPv6 target. Returns a list of hops.
pub fn traceroute_v6(
    iface_name: &str,
    target_ip: &str,
    max_hops: u8,
    timeout_ms: u64,
) -> Result<Vec<HopResult>, EngineError> {
    let iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv6_ll
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv6 link-local address")))?;
    let src_mac = iface.mac;
    let dst_ip: Ipv6Addr = target_ip
        .parse()
        .map_err(|_| EngineError::Channel(format!("invalid target IPv6: {target_ip}")))?;

    // Resolve MAC via NDP; for remote targets, try the link-local all-routers multicast
    let dst_mac = resolve_mac_v6(iface_name, dst_ip, Duration::from_secs(2))
        .unwrap_or([0x33, 0x33, 0x00, 0x00, 0x00, 0x02]); // ff02::2 all-routers multicast MAC

    let mut chan = RawChannel::open(&iface)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let timeout = Duration::from_millis(timeout_ms);

    let mut hops = Vec::new();

    for ttl in 1..=max_hops {
        let frame = build_echo_v6(src_mac, dst_mac, src_ip, dst_ip, ttl, ttl as u16);
        chan.send(&frame).map_err(|e| EngineError::Channel(e.to_string()))?;

        let t0 = Instant::now();
        let result = chan.recv_filter(timeout, |raw| {
            parse_response_v6(raw, src_ip, dst_ip, ttl as u16)
        });

        match result {
            Ok(hop_ip) => {
                let rtt = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
                let reached_target = hop_ip == target_ip;
                hops.push(HopResult { ttl, ip: Some(hop_ip), rtt_ms: Some(rtt) });
                if reached_target {
                    break;
                }
            }
            Err(_) => {
                hops.push(HopResult { ttl, ip: None, rtt_ms: None });
            }
        }
    }

    Ok(hops)
}

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use sondare_codec::{ether, ipv4, ipv6, tcp as tcp_codec, Mac};
use sondare_datalink::{by_name, Iface};

use crate::{sweep, EngineError, SweepConfig};
use crate::scanners::arp::resolve_mac;
use crate::scanners::ndp::resolve_mac_v6;

/// Fixed high source port for all SYN probes.
/// SYN-ACKs return sport = probed port, dport = PROBE_SPORT.
const PROBE_SPORT: u16 = 0xDEAD;

enum Response {
    Open(u16),
    Closed(u16),
}

fn build_syn(src_mac: Mac, dst_mac: Mac, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let tcp_len = 20usize;
    let mut buf = vec![0u8; ether::LEN + ipv4::MIN_LEN + tcp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV4 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_TCP, src_ip, dst_ip, tcp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let mut hdr = tcp_codec::TcpHdr::syn(PROBE_SPORT, port, 0x5a1e_0000u32.wrapping_add(port as u32));
    hdr.window = 65535;
    hdr.encode(&mut buf[off..], &[], src_ip, dst_ip).unwrap();

    buf
}

fn parse_response(raw: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Option<Response> {
    if raw.len() < ether::LEN + ipv4::MIN_LEN + 20 { return None; }
    let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
    let (ip, rest) = ipv4::Ipv4Hdr::decode(rest).ok()?;
    if ip.proto != ipv4::PROTO_TCP || ip.src != dst_ip || ip.dst != src_ip { return None; }
    let (hdr, _) = tcp_codec::TcpHdr::decode(rest).ok()?;
    if hdr.dport != PROBE_SPORT { return None; }

    let sa = tcp_codec::FLAG_SYN | tcp_codec::FLAG_ACK;
    let rst = tcp_codec::FLAG_RST;

    if hdr.flags & sa == sa {
        Some(Response::Open(hdr.sport))
    } else if hdr.flags & rst != 0 {
        Some(Response::Closed(hdr.sport))
    } else {
        None
    }
}

/// SYN scan a list of ports on a single IPv4 target. Returns open port numbers.
///
/// Resolves the target's MAC via ARP before scanning (timeout 2s).
/// After the first pass, silently retries any ports that sent no response
/// (neither SYN-ACK nor RST-ACK) — these are either filtered or had a probe/response
/// lost in transit. Ports that replied RST-ACK are confirmed closed and not retried.
pub fn tcp_syn_scan_v4(
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
        move |port| Some(build_syn(src_mac, dst_mac, src_ip, dst_ip, port)),
        move |raw| parse_response(raw, src_ip, dst_ip),
        cfg,
    )?;

    let mut open: Vec<u16> = Vec::new();
    let mut responded: HashSet<u16> = HashSet::new();
    for r in first {
        match r {
            Response::Open(p)   => { open.push(p); responded.insert(p); }
            Response::Closed(p) => { responded.insert(p); }
        }
    }

    for _ in 0..retries {
        let silent: Vec<u16> = ports.iter()
            .filter(|&&p| !responded.contains(&p))
            .copied()
            .collect();
        if silent.is_empty() { break; }

        let retry = sweep(
            &iface,
            silent.into_iter(),
            move |port| Some(build_syn(src_mac, dst_mac, src_ip, dst_ip, port)),
            move |raw| parse_response(raw, src_ip, dst_ip),
            cfg,
        )?;
        for r in retry {
            match r {
                Response::Open(p)   => { open.push(p); responded.insert(p); }
                Response::Closed(p) => { responded.insert(p); }
            }
        }
    }

    open.sort_unstable();
    open.dedup();
    Ok(open)
}

fn build_syn_v6(src_mac: Mac, dst_mac: Mac, src_ip: Ipv6Addr, dst_ip: Ipv6Addr, port: u16) -> Vec<u8> {
    let tcp_len = 20usize;
    let mut buf = vec![0u8; ether::LEN + ipv6::LEN + tcp_len];

    let eth = ether::EtherHdr { dst: dst_mac, src: src_mac, ethertype: ether::ETYPE_IPV6 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_TCP, src_ip, dst_ip, tcp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let mut hdr = tcp_codec::TcpHdr::syn(PROBE_SPORT, port, 0x5a1e_0000u32.wrapping_add(port as u32));
    hdr.window = 65535;
    hdr.encode_v6(&mut buf[off..], &[], src_ip, dst_ip).unwrap();

    buf
}

fn parse_response_v6(raw: &[u8], src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Option<Response> {
    if raw.len() < ether::LEN + ipv6::LEN + 20 { return None; }
    let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
    if eth.ethertype != ether::ETYPE_IPV6 { return None; }
    let (ip, rest) = ipv6::Ipv6Hdr::decode(rest).ok()?;
    if ip.next_header != ipv6::NEXT_HDR_TCP || ip.src != dst_ip || ip.dst != src_ip { return None; }
    let (hdr, _) = tcp_codec::TcpHdr::decode(rest).ok()?;
    if hdr.dport != PROBE_SPORT { return None; }

    let sa = tcp_codec::FLAG_SYN | tcp_codec::FLAG_ACK;
    let rst = tcp_codec::FLAG_RST;

    if hdr.flags & sa == sa {
        Some(Response::Open(hdr.sport))
    } else if hdr.flags & rst != 0 {
        Some(Response::Closed(hdr.sport))
    } else {
        None
    }
}

/// SYN scan a list of ports on a single IPv6 target. Returns open port numbers.
pub fn tcp_syn_scan_v6(
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
        move |port| Some(build_syn_v6(src_mac, dst_mac, src_ip, dst_ip, port)),
        move |raw| parse_response_v6(raw, src_ip, dst_ip),
        cfg,
    )?;

    let mut open: Vec<u16> = Vec::new();
    let mut responded: HashSet<u16> = HashSet::new();
    for r in first {
        match r {
            Response::Open(p)   => { open.push(p); responded.insert(p); }
            Response::Closed(p) => { responded.insert(p); }
        }
    }

    for _ in 0..retries {
        let silent: Vec<u16> = ports.iter()
            .filter(|&&p| !responded.contains(&p))
            .copied()
            .collect();
        if silent.is_empty() { break; }

        let retry = sweep(
            &iface,
            silent.into_iter(),
            move |port| Some(build_syn_v6(src_mac, dst_mac, src_ip, dst_ip, port)),
            move |raw| parse_response_v6(raw, src_ip, dst_ip),
            cfg,
        )?;
        for r in retry {
            match r {
                Response::Open(p)   => { open.push(p); responded.insert(p); }
                Response::Closed(p) => { responded.insert(p); }
            }
        }
    }

    open.sort_unstable();
    open.dedup();
    Ok(open)
}

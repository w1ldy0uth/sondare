use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use sondare_codec::{ether, ipv4, tcp as tcp_codec, Mac};
use sondare_datalink::{by_name, Iface};

use crate::{sweep, EngineError, SweepConfig};
use crate::scanners::arp::resolve_mac;

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

    // First pass: collect SYN-ACK (open) and RST-ACK (closed).
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

    // Retry only ports that sent no response at all (lost probe/response or filtered).
    let silent: Vec<u16> = ports.iter()
        .filter(|&&p| !responded.contains(&p))
        .copied()
        .collect();

    if !silent.is_empty() {
        let retry = sweep(
            &iface,
            silent.into_iter(),
            move |port| Some(build_syn(src_mac, dst_mac, src_ip, dst_ip, port)),
            move |raw| parse_response(raw, src_ip, dst_ip),
            cfg,
        )?;
        for r in retry {
            if let Response::Open(p) = r {
                open.push(p);
            }
        }
    }

    open.sort_unstable();
    open.dedup();
    Ok(open)
}

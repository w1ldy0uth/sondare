use std::net::Ipv6Addr;
use std::time::Duration;
use sondare_codec::{ether, ipv6, icmpv6, Mac};
use sondare_datalink::{by_name, Iface};

use crate::{sweep, EngineError, SweepConfig};

const ALL_NODES_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ALL_NODES_MAC: Mac = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];

fn mac_to_string(mac: Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn build_echo_request(src_mac: Mac, src_ip: Ipv6Addr) -> Vec<u8> {
    let icmp_len = icmpv6::ECHO_HDR_LEN;
    let mut buf = vec![0u8; ether::LEN + ipv6::LEN + icmp_len];

    let eth = ether::EtherHdr { dst: ALL_NODES_MAC, src: src_mac, ethertype: ether::ETYPE_IPV6 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv6::Ipv6Hdr::new(ipv6::NEXT_HDR_ICMPV6, src_ip, ALL_NODES_ADDR, icmp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let echo = icmpv6::Icmpv6Echo::request(0x5afe, 1, vec![]);
    echo.encode(&mut buf[off..], src_ip, ALL_NODES_ADDR).unwrap();

    buf
}

fn parse_echo_reply(raw: &[u8], src_ip: Ipv6Addr) -> Option<(String, String)> {
    if raw.len() < ether::LEN + ipv6::LEN + icmpv6::ECHO_HDR_LEN { return None; }
    let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
    if eth.ethertype != ether::ETYPE_IPV6 { return None; }
    let (ip, rest) = ipv6::Ipv6Hdr::decode(rest).ok()?;
    if ip.next_header != ipv6::NEXT_HDR_ICMPV6 { return None; }
    let (echo, _) = icmpv6::Icmpv6Echo::decode(rest).ok()?;
    if echo.typ != icmpv6::TYPE_ECHO_REPLY { return None; }

    let reply_ip = ip.src;
    if reply_ip == src_ip { return None; }
    if reply_ip.segments()[0] == 0xff00 >> 8 { return None; }

    let ip_str = reply_ip.to_string();
    let mac_str = mac_to_string(eth.src);
    Some((ip_str, mac_str))
}

/// ICMPv6 multicast ping sweep of ff02::1. Returns (ipv6, mac) pairs.
///
/// Sends a single ICMPv6 echo request to the all-nodes multicast address
/// and collects echo replies. The scanner's own link-local address is excluded.
pub fn ndp_sweep(
    iface_name: &str,
    pps: u32,
    grace_ms: u64,
) -> Result<Vec<(String, String)>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv6_ll
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv6 link-local address")))?;
    let src_mac = iface.mac;

    let cfg = SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) };

    // Single probe to ff02::1; sweep expects an iterator of targets
    let results = sweep(
        &iface,
        std::iter::once(()),
        move |()| Some(build_echo_request(src_mac, src_ip)),
        move |raw| parse_echo_reply(raw, src_ip),
        cfg,
    )?;

    // Deduplicate by IP (multiple replies possible from same host)
    let mut seen = std::collections::HashMap::new();
    for (ip, mac) in results {
        seen.entry(ip).or_insert(mac);
    }

    Ok(seen.into_iter().collect())
}

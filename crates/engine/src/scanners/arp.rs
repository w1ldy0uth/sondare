use std::net::Ipv4Addr;
use std::time::Duration;

use sondare_codec::{arp, ether, Mac};
use sondare_datalink::{by_name, Iface, RawChannel};

use crate::{sweep, EngineError, SweepConfig};

fn mac_to_string(mac: Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn subnet_hosts(cidr: &str) -> Result<Vec<Ipv4Addr>, EngineError> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| EngineError::Channel(format!("invalid CIDR: {cidr}")))?;
    let base: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| EngineError::Channel(format!("invalid IP: {ip_str}")))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| EngineError::Channel(format!("invalid prefix: {prefix_str}")))?;
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let network = u32::from(base) & mask;
    let broadcast = network | !mask;
    Ok((network + 1..broadcast).map(Ipv4Addr::from).collect())
}

/// Send a single ARP who-has and return the target's MAC within `timeout`.
pub fn resolve_mac(iface_name: &str, target_ip: Ipv4Addr, timeout: Duration) -> Result<Mac, EngineError> {
    let iface = by_name(iface_name).map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface.ipv4.ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv4")))?;
    let src_mac = iface.mac;

    let mut chan = RawChannel::open(&iface).map_err(|e| EngineError::Channel(e.to_string()))?;

    let mut buf = [0u8; ether::LEN + arp::LEN];
    arp::arp_request(&mut buf, src_mac, src_ip, target_ip)
        .map_err(|e| EngineError::Codec(e))?;
    chan.send(&buf).map_err(|e| EngineError::Channel(e.to_string()))?;

    chan.recv_filter(timeout, move |raw| {
        if raw.len() < ether::LEN + arp::LEN { return None; }
        let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
        let (hdr, _) = arp::ArpHdr::decode(rest).ok()?;
        if hdr.oper == arp::OPER_REPLY && hdr.spa == target_ip && hdr.tpa == src_ip {
            Some(hdr.sha)
        } else {
            None
        }
    })
    .map_err(|_| EngineError::Channel(format!("no ARP reply from {target_ip}")))
}

/// Active ARP sweep of a subnet. Returns (ip, mac) pairs for responding hosts.
pub fn arp_sweep_v4(
    iface_name: &str,
    cidr: &str,
    pps: u32,
    grace_ms: u64,
) -> Result<Vec<(String, String)>, EngineError> {
    let iface: Iface = by_name(iface_name)
        .map_err(|e| EngineError::Channel(e.to_string()))?;
    let src_ip = iface
        .ipv4
        .ok_or_else(|| EngineError::Channel(format!("{iface_name} has no IPv4 address")))?;
    let src_mac = iface.mac;

    let targets = subnet_hosts(cidr)?;

    let results = sweep(
        &iface,
        targets.into_iter(),
        move |dst_ip| {
            let mut buf = [0u8; ether::LEN + arp::LEN];
            arp::arp_request(&mut buf, src_mac, src_ip, dst_ip).ok()?;
            Some(buf.to_vec())
        },
        move |raw| {
            if raw.len() < ether::LEN + arp::LEN {
                return None;
            }
            let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
            let (hdr, _) = arp::ArpHdr::decode(rest).ok()?;
            // Accept only ARP replies addressed to us
            if hdr.oper == arp::OPER_REPLY && hdr.tpa == src_ip {
                Some((hdr.spa.to_string(), mac_to_string(hdr.sha)))
            } else {
                None
            }
        },
        SweepConfig { pps, recv_grace: Duration::from_millis(grace_ms) },
    )?;

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_hosts_slash24() {
        let hosts = subnet_hosts("192.168.1.0/24").unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hosts[253], "192.168.1.254".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn subnet_hosts_slash30() {
        let hosts = subnet_hosts("192.168.1.0/30").unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn mac_format() {
        assert_eq!(mac_to_string([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), "aa:bb:cc:dd:ee:ff");
    }
}

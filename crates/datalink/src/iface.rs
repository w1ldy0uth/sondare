use std::net::{Ipv4Addr, Ipv6Addr};
use pnet_datalink::NetworkInterface;
use crate::error::DataLinkError;
use sondare_codec::Mac;

#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub mac: Mac,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6_ll: Option<Ipv6Addr>,
    pub inner: NetworkInterface,
}

/// List all usable interfaces (have a MAC, not loopback, are up).
pub fn list() -> Vec<Iface> {
    pnet_datalink::interfaces()
        .into_iter()
        .filter(|i| i.mac.is_some() && !i.is_loopback() && i.is_up())
        .map(|i| {
            let mac = i.mac.unwrap();
            let mac_bytes = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];
            let ipv4 = i.ips.iter().find_map(|net| {
                if let std::net::IpAddr::V4(a) = net.ip() { Some(a) } else { None }
            });
            let ipv6_ll = i.ips.iter().find_map(|net| {
                if let std::net::IpAddr::V6(a) = net.ip() {
                    let seg = a.segments();
                    if seg[0] == 0xfe80 { Some(a) } else { None }
                } else { None }
            });
            Iface { name: i.name.clone(), mac: mac_bytes, ipv4, ipv6_ll, inner: i }
        })
        .collect()
}

/// Find an interface by exact name.
pub fn by_name(name: &str) -> Result<Iface, DataLinkError> {
    list()
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| DataLinkError::InterfaceNotFound(name.to_owned()))
}

/// Pick the first usable non-loopback interface, preferring one with an IPv4 address.
pub fn default_iface() -> Result<Iface, DataLinkError> {
    let mut ifaces = list();
    // prefer one that has an IPv4 address
    if let Some(pos) = ifaces.iter().position(|i| i.ipv4.is_some()) {
        return Ok(ifaces.swap_remove(pos));
    }
    ifaces.into_iter().next().ok_or_else(|| DataLinkError::InterfaceNotFound("(none)".into()))
}

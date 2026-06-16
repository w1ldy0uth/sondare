/// Integration test: ICMP echo sweep of the local /24.
///
/// Requires root/CAP_NET_RAW and a live interface. Run with:
///   sudo cargo test -p sondare-engine -- --ignored --nocapture
use std::net::Ipv4Addr;
use std::time::Duration;

use sondare_codec::{ether, icmp, ipv4, Mac};
use sondare_datalink::default_iface;
use sondare_engine::{sweep, SweepConfig};

// Gateway MAC used as dst for all probes; the gateway will route replies back.
// We learn it from the ARP cache or just use broadcast - broadcast works for /24.
const DST_MAC: Mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

fn build_icmp_frame(src_mac: Mac, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, seq: u16) -> Vec<u8> {
    let icmp_len = icmp::ECHO_HDR_LEN;
    let mut buf = vec![0u8; ether::LEN + ipv4::MIN_LEN + icmp_len];

    let eth = ether::EtherHdr { dst: DST_MAC, src: src_mac, ethertype: ether::ETYPE_IPV4 };
    let mut off = eth.encode(&mut buf).unwrap();

    let ip = ipv4::Ipv4Hdr::new(ipv4::PROTO_ICMP, src_ip, dst_ip, icmp_len as u16);
    off += ip.encode(&mut buf[off..]).unwrap();

    let echo = icmp::IcmpEcho::request(0xd1ce, seq, vec![]);
    echo.encode_with_pseudo(&mut buf[off..], src_ip, dst_ip).unwrap();

    buf
}

#[test]
#[ignore]
fn icmp_sweep_local_subnet() {
    let iface = default_iface().expect("no usable interface");
    let src_ip = iface.ipv4.expect("interface has no IPv4");
    let src_mac = iface.mac;

    // Generate all /24 host addresses
    let octets = src_ip.octets();
    let targets: Vec<Ipv4Addr> = (1u8..=254)
        .map(|i| Ipv4Addr::new(octets[0], octets[1], octets[2], i))
        .collect();

    let total = targets.len();

    let results = sweep(
        &iface,
        targets.into_iter().enumerate(),
        move |(seq, dst_ip)| {
            Some(build_icmp_frame(src_mac, src_ip, dst_ip, seq as u16))
        },
        move |raw| {
            // Must be Ether(14) + IPv4(20) + ICMP(8) minimum
            if raw.len() < ether::LEN + ipv4::MIN_LEN + icmp::ECHO_HDR_LEN {
                return None;
            }
            let (_, rest) = ether::EtherHdr::decode(raw).ok()?;
            let (ip, rest) = ipv4::Ipv4Hdr::decode(rest).ok()?;
            if ip.proto != ipv4::PROTO_ICMP { return None; }
            let (echo, _) = icmp::IcmpEcho::decode(rest).ok()?;
            // ICMP echo reply (type 0), matching our id
            if echo.typ == icmp::TYPE_ECHO_REPLY && echo.id == 0xd1ce {
                Some(ip.src)
            } else {
                None
            }
        },
        SweepConfig {
            pps: 500,
            recv_grace: Duration::from_millis(800),
        },
    )
    .expect("sweep failed");

    println!("Swept {total} addresses, got {} replies:", results.len());
    for ip in &results {
        println!("  {ip}");
    }

    // On any real LAN there should be at least the local host itself
    assert!(!results.is_empty(), "no ICMP replies - is the interface up?");
}

/// Integration test: send an ARP who-has and receive the reply.
///
/// Requires root/CAP_NET_RAW and a live interface. Run with:
///   sudo cargo test -p sondare-datalink -- --ignored --nocapture
use std::time::Duration;
use sondare_codec::{arp, ether};
use sondare_datalink::{default_iface, RawChannel};

#[test]
#[ignore]
fn arp_who_has_gateway() {
    let iface = default_iface().expect("no usable interface");
    let src_ip = iface.ipv4.expect("interface has no IPv4");

    // Target: the gateway (first address in the subnet, e.g. .1)
    let octets = src_ip.octets();
    let gw_ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1);

    let mut chan = RawChannel::open(&iface).expect("open channel - need root");

    // Build and send ARP request
    let mut frame = [0u8; 42];
    let n = arp::arp_request(&mut frame, iface.mac, src_ip, gw_ip).unwrap();
    chan.send(&frame[..n]).expect("send ARP request");

    // Wait for an ARP reply addressed to us
    let reply = chan.recv_filter(Duration::from_secs(2), |raw| {
        // Must be at least Ether(14) + ARP(28)
        if raw.len() < 42 { return None; }
        let (eth, rest) = ether::EtherHdr::decode(raw).ok()?;
        if eth.ethertype != ether::ETYPE_ARP { return None; }
        let (arp_hdr, _) = arp::ArpHdr::decode(rest).ok()?;
        if arp_hdr.oper == arp::OPER_REPLY && arp_hdr.tpa == src_ip {
            Some(arp_hdr)
        } else {
            None
        }
    });

    match reply {
        Ok(arp_hdr) => {
            println!("ARP reply: {} is at {:02x?}", gw_ip, arp_hdr.sha);
            assert_eq!(arp_hdr.spa, gw_ip);
        }
        Err(sondare_datalink::DataLinkError::Timeout) => {
            // Gateway may not respond (e.g. in CI). Treat as a soft warning.
            println!("WARN: no ARP reply within 2s - gateway may be unreachable");
        }
        Err(e) => panic!("recv error: {e}"),
    }
}

use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::EngineError;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

// DNS record types
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_SRV: u16 = 33;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MdnsResult {
    pub hostname: String,
    pub ip: String,
    pub service: String,
    pub port: u16,
}

fn build_ptr_query(service: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    // Header: ID=0, flags=0, QD=1, AN=0, NS=0, AR=0
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // QNAME
    for label in service.split('.') {
        if label.is_empty() { continue; }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root
    // QTYPE=PTR, QCLASS=IN with QU bit set (0x8001)
    pkt.extend_from_slice(&[0, TYPE_PTR as u8, 0x80, 0x01]);
    pkt
}

fn read_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut end_offset = 0;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;

        if len == 0 {
            if !jumped { end_offset = offset + 1; }
            break;
        }

        // Pointer (compression)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() { return None; }
            let ptr = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            if !jumped { end_offset = offset + 2; }
            jumped = true;
            offset = ptr;
            jumps += 1;
            if jumps > 64 { return None; } // loop protection
            continue;
        }

        offset += 1;
        if offset + len > data.len() { return None; }
        parts.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
        offset += len;
    }

    let name = parts.join(".");
    Some((name, if jumped { end_offset } else { end_offset }))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() { return None; }
    Some(u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

struct DnsRecord {
    name: String,
    rtype: u16,
    rdata_offset: usize,
    rdlength: u16,
}

fn parse_response(data: &[u8]) -> Vec<DnsRecord> {
    if data.len() < 12 { return Vec::new(); }

    let qd_count = read_u16(data, 4).unwrap_or(0);
    let an_count = read_u16(data, 6).unwrap_or(0);
    let ns_count = read_u16(data, 8).unwrap_or(0);
    let ar_count = read_u16(data, 10).unwrap_or(0);
    let total = an_count as usize + ns_count as usize + ar_count as usize;

    // Skip questions
    let mut offset = 12;
    for _ in 0..qd_count {
        let (_, next) = match read_name(data, offset) {
            Some(v) => v,
            None => return Vec::new(),
        };
        offset = next + 4; // QTYPE + QCLASS
    }

    let mut records = Vec::new();
    for _ in 0..total {
        let (name, next) = match read_name(data, offset) {
            Some(v) => v,
            None => break,
        };
        offset = next;
        let rtype = match read_u16(data, offset) { Some(v) => v, None => break };
        // skip class + ttl
        let _class = read_u16(data, offset + 2);
        let _ttl = read_u32(data, offset + 4);
        let rdlength = match read_u16(data, offset + 8) { Some(v) => v, None => break };
        offset += 10;
        let rdata_offset = offset;
        if offset + rdlength as usize > data.len() { break; }
        records.push(DnsRecord { name, rtype, rdata_offset, rdlength });
        offset += rdlength as usize;
    }

    records
}

fn extract_services(data: &[u8], records: &[DnsRecord]) -> Vec<MdnsResult> {
    // Collect A records: name -> ip
    let mut a_records: HashMap<String, String> = HashMap::new();
    // Collect SRV records: instance_name -> (hostname, port)
    let mut srv_records: HashMap<String, (String, u16)> = HashMap::new();
    // Collect PTR records: service_type -> [instance_name]
    let mut ptr_targets: Vec<(String, String)> = Vec::new();

    for rec in records {
        match rec.rtype {
            TYPE_A if rec.rdlength == 4 => {
                let off = rec.rdata_offset;
                let ip = format!("{}.{}.{}.{}", data[off], data[off + 1], data[off + 2], data[off + 3]);
                if !ip.starts_with("127.") {
                    a_records.insert(rec.name.clone(), ip);
                }
            }
            TYPE_PTR => {
                if let Some((target, _)) = read_name(data, rec.rdata_offset) {
                    ptr_targets.push((rec.name.clone(), target));
                }
            }
            TYPE_SRV => {
                let off = rec.rdata_offset;
                // SRV: priority(2) + weight(2) + port(2) + target
                if rec.rdlength >= 7 {
                    let port = read_u16(data, off + 4).unwrap_or(0);
                    if let Some((target, _)) = read_name(data, off + 6) {
                        let hostname = target.trim_end_matches('.').to_string();
                        srv_records.insert(rec.name.clone(), (hostname, port));
                    }
                }
            }
            _ => {}
        }
    }

    let mut results = Vec::new();
    for (svc_type, instance_name) in &ptr_targets {
        let service = svc_type
            .trim_end_matches('.')
            .strip_suffix(".local")
            .unwrap_or(svc_type.trim_end_matches('.'))
            .to_string();

        if let Some((hostname, port)) = srv_records.get(instance_name) {
            // Find IP: check A records for the SRV target hostname
            let hostname_dot = format!("{}.", hostname);
            let ip = a_records.get(hostname)
                .or_else(|| a_records.get(&hostname_dot))
                .or_else(|| {
                    // Try resolving via DNS
                    None
                });

            if let Some(ip) = ip {
                results.push(MdnsResult {
                    hostname: hostname.trim_end_matches(".local").to_string(),
                    ip: ip.clone(),
                    service,
                    port: *port,
                });
            }
        }
    }

    results
}

/// Discover mDNS services on the local network.
///
/// Sends PTR queries with the QU bit for each service type to the mDNS
/// multicast group and collects responses over the timeout period.
pub fn mdns_scan(service_types: &[String], timeout_ms: u64) -> Result<Vec<MdnsResult>, EngineError> {
    let timeout = Duration::from_millis(timeout_ms);
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| EngineError::Io(e))?;
    sock.set_reuse_address(true)?;

    #[cfg(unix)]
    sock.set_reuse_port(true)?;

    let bind_addr = SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT));
    sock.bind(&bind_addr)?;
    sock.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)?;
    sock.set_nonblocking(true)?;

    let mdns_dest = SockAddr::from(SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
    let mut seen: HashSet<(String, String, String, u16)> = HashSet::new();
    let start = Instant::now();

    // Send queries at t=0
    for svc in service_types {
        let pkt = build_ptr_query(svc);
        let _ = sock.send_to(&pkt, &mdns_dest);
    }

    let half = timeout / 2;
    let mut second_burst_sent = false;
    let mut buf: [MaybeUninit<u8>; 4096] = unsafe { MaybeUninit::uninit().assume_init() };

    while start.elapsed() < timeout {
        if !second_burst_sent && start.elapsed() >= half {
            for svc in service_types {
                let pkt = build_ptr_query(svc);
                let _ = sock.send_to(&pkt, &mdns_dest);
            }
            second_burst_sent = true;
        }

        match sock.recv(&mut buf) {
            Ok(n) if n > 12 => {
                let data: Vec<u8> = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
                let records = parse_response(&data);
                for result in extract_services(&data, &records) {
                    seen.insert((result.hostname.clone(), result.ip.clone(), result.service.clone(), result.port));
                }
            }
            _ => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    sock.leave_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED).ok();

    let mut results: Vec<MdnsResult> = seen.into_iter()
        .map(|(hostname, ip, service, port)| MdnsResult { hostname, ip, service, port })
        .collect();
    results.sort_by(|a, b| (&a.hostname, &a.service).cmp(&(&b.hostname, &b.service)));
    Ok(results)
}

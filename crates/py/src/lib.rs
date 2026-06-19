use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::PyBytes;
use sondare_engine::scanners::arp::arp_sweep_v4 as _arp_sweep_v4;
use sondare_engine::scanners::icmp::icmp_sweep_v4 as _icmp_sweep_v4;
use sondare_engine::scanners::tcp::tcp_syn_scan_v4 as _tcp_syn_scan_v4;
use sondare_engine::scanners::udp::udp_scan_v4 as _udp_scan_v4;
use sondare_engine::scanners::fingerprint::fingerprint_v4 as _fingerprint_v4;
use sondare_engine::scanners::ndp::ndp_sweep as _ndp_sweep;
use sondare_engine::scanners::trace::traceroute_v4 as _traceroute_v4;
use sondare_engine::scanners::trace::traceroute_v6 as _traceroute_v6;
use sondare_engine::scanners::tls::tls_probe as _tls_probe;
use sondare_engine::scanners::mdns::mdns_scan as _mdns_scan;
use sondare_engine::scanners::icmp::icmp_sweep_v6 as _icmp_sweep_v6;
use sondare_engine::scanners::icmp::icmp_multicast_v6 as _icmp_multicast_v6;
use sondare_engine::scanners::tcp::tcp_syn_scan_v6 as _tcp_syn_scan_v6;
use sondare_engine::scanners::udp::udp_scan_v6 as _udp_scan_v6;
use sondare_engine::scanners::fingerprint::fingerprint_v6 as _fingerprint_v6;
use sondare_engine::sniffer::{PacketCapture, CaptureResult};

/// Sweep a list of IPv4 targets via ICMP echo.
///
/// Args:
///     iface:    network interface name (e.g. "en0", "eth0")
///     targets:  list of IPv4 address strings to probe
///     pps:      max packets per second
///     grace_ms: milliseconds to keep the receive window open after the last probe
///
/// Returns a list of IP strings that replied.
#[pyfunction]
#[pyo3(signature = (iface, targets, pps=500, grace_ms=500))]
fn icmp_sweep_v4(
    iface: &str,
    targets: Vec<String>,
    pps: u32,
    grace_ms: u64,
) -> PyResult<Vec<String>> {
    _icmp_sweep_v4(iface, targets, pps, grace_ms)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Active ARP sweep of a subnet.
///
/// Returns a list of (ip, mac) tuples for hosts that responded.
/// MAC is formatted as lowercase colon-separated hex (e.g. "aa:bb:cc:dd:ee:ff").
#[pyfunction]
#[pyo3(signature = (iface, cidr, pps=500, grace_ms=500))]
fn arp_sweep_v4(
    iface: &str,
    cidr: &str,
    pps: u32,
    grace_ms: u64,
) -> PyResult<Vec<(String, String)>> {
    _arp_sweep_v4(iface, cidr, pps, grace_ms)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// SYN scan a list of ports on a single IPv4 target.
///
/// Resolves the target MAC via ARP automatically before scanning.
///
/// Args:
///     iface:    network interface name
///     target_ip: IPv4 address string of the target
///     ports:    list of port numbers to probe
///     pps:      max packets per second
///     grace_ms: ms to keep receive window open after last probe
///
/// Returns list of open port numbers.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500, retries=2))]
fn tcp_syn_scan_v4(
    iface: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
    retries: u32,
) -> PyResult<Vec<u16>> {
    _tcp_syn_scan_v4(iface, target_ip, ports, pps, grace_ms, retries)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// UDP scan a list of ports on a single IPv4 target.
///
/// Sends empty UDP datagrams and listens for ICMP port-unreachable.
/// Ports with no ICMP unreachable after two passes are reported as open|filtered.
///
/// Returns list of open|filtered port numbers.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500, retries=2))]
fn udp_scan_v4(
    iface: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
    retries: u32,
) -> PyResult<Vec<u16>> {
    _udp_scan_v4(iface, target_ip, ports, pps, grace_ms, retries)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Probe ports via TCP SYN to fingerprint a target's OS from the SYN-ACK response.
///
/// Returns (ttl, window, mss_or_none, wscale_or_none, has_timestamps, has_sack)
/// or None if no port responded with SYN-ACK.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500))]
fn fingerprint_v4(
    iface: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
) -> PyResult<Option<(u8, u16, Option<u16>, Option<u8>, bool, bool)>> {
    _fingerprint_v4(iface, target_ip, ports, pps, grace_ms)
        .map(|r| r.map(|f| (f.ttl, f.window, f.mss, f.wscale, f.has_timestamps, f.has_sack)))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// ICMPv6 multicast ping sweep of ff02::1 for IPv6 host discovery.
///
/// Returns a list of (ipv6, mac) tuples for hosts that responded.
#[pyfunction]
#[pyo3(signature = (iface, pps=500, grace_ms=2000))]
fn ndp_sweep(
    iface: &str,
    pps: u32,
    grace_ms: u64,
) -> PyResult<Vec<(String, String)>> {
    _ndp_sweep(iface, pps, grace_ms)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// ICMP traceroute to an IPv4 target.
///
/// Returns a list of (ttl, ip_or_none, rtt_ms_or_none) tuples.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, max_hops=30, timeout_ms=3000))]
fn traceroute_v4(
    iface: &str,
    target_ip: &str,
    max_hops: u8,
    timeout_ms: u64,
) -> PyResult<Vec<(u8, Option<String>, Option<f64>)>> {
    _traceroute_v4(iface, target_ip, max_hops, timeout_ms)
        .map(|hops| hops.into_iter().map(|h| (h.ttl, h.ip, h.rtt_ms)).collect())
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Sweep a list of IPv6 targets via ICMPv6 echo.
#[pyfunction]
#[pyo3(signature = (iface, targets, pps=500, grace_ms=500))]
fn icmp_sweep_v6(iface: &str, targets: Vec<String>, pps: u32, grace_ms: u64) -> PyResult<Vec<String>> {
    _icmp_sweep_v6(iface, targets, pps, grace_ms)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// ICMPv6 multicast sweep of ff02::1 (all-nodes).
#[pyfunction]
#[pyo3(signature = (iface, pps=500, grace_ms=2000))]
fn icmp_multicast_v6(iface: &str, pps: u32, grace_ms: u64) -> PyResult<Vec<String>> {
    _icmp_multicast_v6(iface, pps, grace_ms)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// SYN scan ports on a single IPv6 target.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500, retries=2))]
fn tcp_syn_scan_v6(iface: &str, target_ip: &str, ports: Vec<u16>, pps: u32, grace_ms: u64, retries: u32) -> PyResult<Vec<u16>> {
    _tcp_syn_scan_v6(iface, target_ip, ports, pps, grace_ms, retries)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// UDP scan ports on a single IPv6 target.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500, retries=2))]
fn udp_scan_v6(iface: &str, target_ip: &str, ports: Vec<u16>, pps: u32, grace_ms: u64, retries: u32) -> PyResult<Vec<u16>> {
    _udp_scan_v6(iface, target_ip, ports, pps, grace_ms, retries)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// OS fingerprint an IPv6 target via TCP SYN probe.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500))]
fn fingerprint_v6(iface: &str, target_ip: &str, ports: Vec<u16>, pps: u32, grace_ms: u64)
    -> PyResult<Option<(u8, u16, Option<u16>, Option<u8>, bool, bool)>>
{
    _fingerprint_v6(iface, target_ip, ports, pps, grace_ms)
        .map(|r| r.map(|f| (f.ttl, f.window, f.mss, f.wscale, f.has_timestamps, f.has_sack)))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// ICMPv6 traceroute to an IPv6 target.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, max_hops=30, timeout_ms=3000))]
fn traceroute_v6(iface: &str, target_ip: &str, max_hops: u8, timeout_ms: u64)
    -> PyResult<Vec<(u8, Option<String>, Option<f64>)>>
{
    _traceroute_v6(iface, target_ip, max_hops, timeout_ms)
        .map(|hops| hops.into_iter().map(|h| (h.ttl, h.ip, h.rtt_ms)).collect())
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Probe TLS certificates on the given ports.
///
/// Returns a list of dicts with keys: ip, port, cn, issuer, not_before,
/// not_after, san, expired, self_signed.  Only ports that responded are included.
#[pyfunction]
#[pyo3(signature = (ip, ports, timeout_ms=5000))]
fn tls_probe(
    ip: &str,
    ports: Vec<u16>,
    timeout_ms: u64,
) -> PyResult<Vec<(String, u16, Option<String>, Option<String>, String, String, Vec<String>, bool, bool)>> {
    _tls_probe(ip, &ports, timeout_ms)
        .map(|certs| certs.into_iter().map(|c| (
            c.ip, c.port, c.cn, c.issuer, c.not_before, c.not_after,
            c.san, c.expired, c.self_signed,
        )).collect())
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Discover mDNS services on the local network.
///
/// Returns a list of (hostname, ip, service, port) tuples.
#[pyfunction]
#[pyo3(signature = (service_types, timeout_ms=5000))]
fn mdns_scan(
    service_types: Vec<String>,
    timeout_ms: u64,
) -> PyResult<Vec<(String, String, String, u16)>> {
    _mdns_scan(&service_types, timeout_ms)
        .map(|results| results.into_iter().map(|r| (
            r.hostname, r.ip, r.service, r.port,
        )).collect())
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Sniff packets on an interface with a BPF filter.
///
/// Calls `callback(raw_bytes)` for each captured packet. Blocks until
/// KeyboardInterrupt (Ctrl+C). The GIL is released during the pcap wait
/// and re-acquired for each callback invocation.
#[pyfunction]
#[pyo3(signature = (iface, bpf_filter, callback))]
fn sniff(py: Python<'_>, iface: &str, bpf_filter: &str, callback: PyObject) -> PyResult<()> {
    let mut cap = PacketCapture::open(iface, bpf_filter, 100)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    loop {
        py.check_signals()?;

        let result = py.allow_threads(|| cap.next_packet());

        match result {
            Ok(CaptureResult::Packet(data)) => {
                let py_bytes = PyBytes::new(py, &data);
                callback.call1(py, (py_bytes,))?;
            }
            Ok(CaptureResult::Timeout) => continue,
            Err(e) => return Err(PyRuntimeError::new_err(e.to_string())),
        }
    }
}

#[pymodule]
fn _sondare(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(arp_sweep_v4, m)?)?;
    m.add_function(wrap_pyfunction!(icmp_sweep_v4, m)?)?;
    m.add_function(wrap_pyfunction!(tcp_syn_scan_v4, m)?)?;
    m.add_function(wrap_pyfunction!(udp_scan_v4, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_v4, m)?)?;
    m.add_function(wrap_pyfunction!(ndp_sweep, m)?)?;
    m.add_function(wrap_pyfunction!(traceroute_v4, m)?)?;
    m.add_function(wrap_pyfunction!(tls_probe, m)?)?;
    m.add_function(wrap_pyfunction!(mdns_scan, m)?)?;
    m.add_function(wrap_pyfunction!(icmp_sweep_v6, m)?)?;
    m.add_function(wrap_pyfunction!(icmp_multicast_v6, m)?)?;
    m.add_function(wrap_pyfunction!(tcp_syn_scan_v6, m)?)?;
    m.add_function(wrap_pyfunction!(udp_scan_v6, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_v6, m)?)?;
    m.add_function(wrap_pyfunction!(traceroute_v6, m)?)?;
    m.add_function(wrap_pyfunction!(sniff, m)?)?;
    Ok(())
}

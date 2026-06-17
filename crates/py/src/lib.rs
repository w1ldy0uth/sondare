use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use sondare_engine::scanners::arp::arp_sweep_v4 as _arp_sweep_v4;
use sondare_engine::scanners::icmp::icmp_sweep_v4 as _icmp_sweep_v4;
use sondare_engine::scanners::tcp::tcp_syn_scan_v4 as _tcp_syn_scan_v4;
use sondare_engine::scanners::udp::udp_scan_v4 as _udp_scan_v4;
use sondare_engine::scanners::fingerprint::fingerprint_v4 as _fingerprint_v4;

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
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500))]
fn tcp_syn_scan_v4(
    iface: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
) -> PyResult<Vec<u16>> {
    _tcp_syn_scan_v4(iface, target_ip, ports, pps, grace_ms)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// UDP scan a list of ports on a single IPv4 target.
///
/// Sends empty UDP datagrams and listens for ICMP port-unreachable.
/// Ports with no ICMP unreachable after two passes are reported as open|filtered.
///
/// Returns list of open|filtered port numbers.
#[pyfunction]
#[pyo3(signature = (iface, target_ip, ports, pps=500, grace_ms=500))]
fn udp_scan_v4(
    iface: &str,
    target_ip: &str,
    ports: Vec<u16>,
    pps: u32,
    grace_ms: u64,
) -> PyResult<Vec<u16>> {
    _udp_scan_v4(iface, target_ip, ports, pps, grace_ms)
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

#[pymodule]
fn _sondare(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(arp_sweep_v4, m)?)?;
    m.add_function(wrap_pyfunction!(icmp_sweep_v4, m)?)?;
    m.add_function(wrap_pyfunction!(tcp_syn_scan_v4, m)?)?;
    m.add_function(wrap_pyfunction!(udp_scan_v4, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_v4, m)?)?;
    Ok(())
}

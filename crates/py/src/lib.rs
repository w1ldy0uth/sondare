use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use sondare_engine::scanners::arp::arp_sweep_v4 as _arp_sweep_v4;
use sondare_engine::scanners::icmp::icmp_sweep_v4 as _icmp_sweep_v4;

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

#[pymodule]
fn _sondare(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(arp_sweep_v4, m)?)?;
    m.add_function(wrap_pyfunction!(icmp_sweep_v4, m)?)?;
    Ok(())
}

import argparse
import pytest
from sondare.main import parse_target, Target


def test_ip_only_defaults_ports():
    assert parse_target("192.168.1.1") == Target("192.168.1.1", 1, 1000)


def test_single_port():
    assert parse_target("10.0.0.1:80") == Target("10.0.0.1", 80, 80)


def test_port_range():
    assert parse_target("10.0.0.1:1-1024") == Target("10.0.0.1", 1, 1024)


def test_invalid_format_raises():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_target("")


def test_start_greater_than_end_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="must be <="):
        parse_target("10.0.0.1:100-50")


def test_port_out_of_range_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="out of range"):
        parse_target("10.0.0.1:1-99999")


def test_port_at_max_boundary():
    assert parse_target("10.0.0.1:65535") == Target("10.0.0.1", 65535, 65535)


def test_port_zero_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="out of range"):
        parse_target("10.0.0.1:0")


def test_port_exactly_65536_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="out of range"):
        parse_target("10.0.0.1:65536")


def test_reversed_range_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="must be <="):
        parse_target("10.0.0.1:443-80")


def test_ip_only_uses_default_range():
    t = parse_target("10.0.0.1")
    assert t.port_begin == 1
    assert t.port_end == 1000


# IPv6 tests
def test_bare_ipv6_defaults_ports():
    assert parse_target("fe80::1") == Target("fe80::1", 1, 1000)


def test_bracket_ipv6_single_port():
    assert parse_target("[fe80::1]:80") == Target("fe80::1", 80, 80)


def test_bracket_ipv6_port_range():
    assert parse_target("[fe80::dead:beef]:1-1024") == Target("fe80::dead:beef", 1, 1024)


def test_bracket_ipv6_no_port_defaults():
    assert parse_target("[2001:db8::1]") == Target("2001:db8::1", 1, 1000)


def test_bracket_ipv6_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_target("[not closed")


def test_bracket_ipv6_reversed_range_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="must be <="):
        parse_target("[fe80::1]:443-80")


def test_bare_ipv6_with_port_suggests_bracket_notation():
    with pytest.raises(argparse.ArgumentTypeError, match="bracket notation"):
        parse_target("fe80::c331:6970:6df:6e96:1-10")


def test_bare_ipv6_that_is_also_valid_address_uses_default_ports():
    # fe80::1:80 is itself a valid IPv6 address, so it's accepted as-is with default port range.
    assert parse_target("fe80::1:80") == Target("fe80::1:80", 1, 1000)

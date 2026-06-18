from unittest.mock import patch, MagicMock
from sondare.services.tcp import Tcp
from sondare.utils.banners import grab_banner
from sondare.models import Port


def _make_scanner(**kwargs):
    defaults = dict(verbose=False, ip="10.0.0.1", port_begin=80, port_end=80, timeout=1, threads=1, retries=2)
    defaults.update(kwargs)
    return Tcp(**defaults)


def _ipv4_patches(open_ports):
    return [
        patch("sondare.services.tcp._sondare.tcp_syn_scan_v4", return_value=open_ports),
        patch("sondare.services.tcp.get_network_interface", return_value="eth0"),
    ]


class TestScanIpv4:
    def test_scan_calls_rust_backend(self):
        scanner = _make_scanner()
        patches = _ipv4_patches([80])
        with patches[0] as mock_rust, patches[1]:
            scanner.scan()
        mock_rust.assert_called_once()

    def test_open_port_recorded(self):
        scanner = _make_scanner()
        patches = _ipv4_patches([80])
        with patches[0], patches[1]:
            scanner.scan()
        assert 80 in [p.port for p in scanner.get_results()]

    def test_no_open_ports(self):
        scanner = _make_scanner()
        patches = _ipv4_patches([])
        with patches[0], patches[1]:
            scanner.scan()
        assert scanner.get_results() == []


class TestGetResults:
    def test_returns_empty_before_scan(self):
        scanner = _make_scanner()
        assert scanner.get_results() == []

    def test_get_results_after_scan_includes_service_name(self):
        scanner = _make_scanner(port_begin=80, port_end=80)
        patches = _ipv4_patches([80])
        with patches[0], patches[1]:
            scanner.scan()
        assert scanner.get_results() == [Port("10.0.0.1", 80, service="http")]

    def test_results_sorted_by_port(self):
        scanner = _make_scanner(port_begin=22, port_end=80)
        patches = _ipv4_patches(list(range(80, 21, -1)))
        with patches[0], patches[1]:
            scanner.scan()
        ports = [p.port for p in scanner.get_results()]
        assert ports == sorted(ports)


class TestGrabBanner:
    def test_raw_banner_on_non_http_port(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 22, 2.0)
        assert result == "SSH-2.0-OpenSSH_8.9"

    def _mock_http_sock(self, response: bytes):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [response, b""]
        return mock_sock

    def test_http_port_sends_probe_and_returns_server_header(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = self._mock_http_sock(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 80, 2.0)
        mock_sock.sendall.assert_called_once()
        assert result == "nginx/1.25.3"

    def test_http_port_returns_x_powered_by_when_no_server_header(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = self._mock_http_sock(b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2\r\n\r\n")
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 80, 2.0)
        assert result == "PHP/8.2"

    def test_http_port_returns_realm_from_www_authenticate(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = self._mock_http_sock(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="RT-AX88U"\r\n\r\n')
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 80, 2.0)
        assert result == "RT-AX88U"

    def test_http_port_falls_back_to_title_tag(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = self._mock_http_sock(b"HTTP/1.1 200 OK\r\n\r\n<html><head><title>Router Admin</title></head></html>")
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 80, 2.0)
        assert result == "Router Admin"

    def test_http_port_falls_back_to_status_line_as_last_resort(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = self._mock_http_sock(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 80, 2.0)
        assert result == "HTTP/1.1 200 OK"

    def test_returns_none_on_empty_raw_response(self):
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b""
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 22, 2.0)
        assert result is None

    def test_returns_none_on_connection_error(self):
        with patch("sondare.utils.banners.socket.create_connection", side_effect=OSError):
            result = grab_banner("10.0.0.1", 9999, 2.0)
        assert result is None

    def test_follows_meta_refresh_redirect_to_extract_title(self):
        first = "HTTP/1.0 200 OK\r\n\r\n<meta http-equiv='refresh' content='0; URL=cgi-bin/luci/'>"
        second = "HTTP/1.1 403 Forbidden\r\n\r\n<html><head><title>WR1500</title></head></html>"
        with patch("sondare.utils.banners._fetch_http", side_effect=[first, second]) as mock_fetch:
            result = grab_banner("192.168.10.1", 80, 2.0)
        assert mock_fetch.call_count == 2
        assert mock_fetch.call_args_list[1][0][2] == "/cgi-bin/luci/"
        assert result == "WR1500"

    def _make_smb2_response(self, dialect: int) -> bytes:
        header = bytearray(74)
        header[4:8] = b"\xfe\x53\x4d\x42"
        header[72:74] = dialect.to_bytes(2, "little")
        return bytes(header)

    def test_smb_port_returns_dialect_string(self):
        response = self._make_smb2_response(0x0302)
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = response
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 445, 2.0)
        assert result == "SMB 3.0.2 (Windows 8.1 / Server 2012 R2+)"

    def test_smb_port_returns_none_for_unknown_dialect(self):
        response = self._make_smb2_response(0xFFFF)
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = response
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 445, 2.0)
        assert result is None

    def test_smb_port_returns_none_on_non_smb2_response(self):
        response = b"\x00" * 74
        with patch("sondare.utils.banners.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = response
            mock_conn.return_value.__enter__.return_value = mock_sock
            result = grab_banner("10.0.0.1", 445, 2.0)
        assert result is None


class TestBannersIntegration:
    def test_banners_flag_populates_port_banner(self):
        scanner = _make_scanner(banners=True)
        patches = _ipv4_patches([80])
        with patches[0], patches[1], \
             patch("sondare.services.tcp.grab_banner", return_value="SSH-2.0-OpenSSH_8.9") as mock_grab:
            scanner.scan()

        mock_grab.assert_called_once_with("10.0.0.1", 80, scanner._timeout)

    def test_no_banners_flag_leaves_banner_none(self):
        scanner = _make_scanner(banners=False)
        patches = _ipv4_patches([80])
        with patches[0], patches[1], \
             patch("sondare.services.tcp.grab_banner") as mock_grab:
            scanner.scan()

        mock_grab.assert_not_called()


class TestIpv6Tcp:
    def test_ipv6_scan_calls_rust_v6_backend(self):
        scanner = Tcp(verbose=False, ip="fe80::1", port_begin=80, port_end=80,
                      timeout=1, threads=1, retries=0)
        with patch("sondare.services.tcp._sondare.tcp_syn_scan_v6", return_value=[80]) as mock_v6, \
             patch("sondare.services.tcp.get_network_interface", return_value="eth0"):
            scanner.scan()
        mock_v6.assert_called_once()
        assert 80 in [p.port for p in scanner.get_results()]


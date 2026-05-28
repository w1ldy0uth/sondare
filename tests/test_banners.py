from unittest.mock import patch, MagicMock, call
from sondare.utils.banners import (
    grab_banner,
    _parse_http,
    _meta_refresh_path,
    _smb_banner,
    _SMB_DIALECTS,
)


def _mock_socket(recv_data: bytes = b""):
    sock = MagicMock()
    sock.recv.return_value = recv_data
    sock.__enter__ = lambda s: s
    sock.__exit__ = MagicMock(return_value=False)
    return sock


def _smb_response(dialect: int) -> bytes:
    """Builds a minimal SMB2 Negotiate response with the given DialectRevision."""
    header = b"\x00\x00\x00\x78"           # NetBIOS
    header += b"\xfe\x53\x4d\x42"          # SMB2 magic
    header += b"\x00" * 60                 # rest of 64-byte SMB2 header
    # offset 68: start of body; DialectRevision is at offset 72 from packet start
    # body bytes 0-3 are StructureSize + SecurityMode, then DialectRevision at bytes 4-5
    header += b"\x41\x00"                  # StructureSize=65
    header += b"\x00\x00"                  # Reserved
    header += dialect.to_bytes(2, "little")
    return header


# ---------------------------------------------------------------------------
# _parse_http
# ---------------------------------------------------------------------------

class TestParseHttp:
    def test_returns_server_header(self):
        data = "HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\nContent-Type: text/html\r\n\r\n"
        assert _parse_http(data) == "Apache/2.4"

    def test_returns_x_powered_by_when_no_server(self):
        data = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1\r\n\r\n"
        assert _parse_http(data) == "PHP/8.1"

    def test_returns_www_authenticate_realm(self):
        data = 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Admin Panel"\r\n\r\n'
        assert _parse_http(data) == "Admin Panel"

    def test_returns_www_authenticate_full_line_when_no_realm(self):
        data = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\n"
        assert _parse_http(data) == "Bearer"

    def test_returns_html_title(self):
        data = "HTTP/1.1 200 OK\r\n\r\n<html><head><title>My Router</title></head></html>"
        assert _parse_http(data) == "My Router"

    def test_title_collapses_whitespace(self):
        data = "HTTP/1.1 200 OK\r\n\r\n<html><title>  Hello\n  World  </title></html>"
        assert _parse_http(data) == "Hello World"

    def test_server_takes_priority_over_title(self):
        data = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Page</title>"
        assert _parse_http(data) == "nginx"

    def test_returns_none_when_nothing_found(self):
        data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        assert _parse_http(data) is None

    def test_empty_title_returns_none(self):
        data = "HTTP/1.1 200 OK\r\n\r\n<title>   </title>"
        assert _parse_http(data) is None


# ---------------------------------------------------------------------------
# _meta_refresh_path
# ---------------------------------------------------------------------------

class TestMetaRefreshPath:
    def test_returns_relative_path(self):
        data = '<meta http-equiv="refresh" content="0; URL=/login">'
        assert _meta_refresh_path(data) == "/login"

    def test_strips_leading_slash_correctly(self):
        data = '<meta http-equiv="refresh" content="0; URL=dashboard">'
        assert _meta_refresh_path(data) == "/dashboard"

    def test_returns_none_for_absolute_url(self):
        data = '<meta http-equiv="refresh" content="0; URL=http://example.com/login">'
        assert _meta_refresh_path(data) is None

    def test_returns_none_when_no_meta_tag(self):
        data = "<html><body>No redirect here</body></html>"
        assert _meta_refresh_path(data) is None


# ---------------------------------------------------------------------------
# _smb_banner
# ---------------------------------------------------------------------------

class TestSmbBanner:
    def test_returns_dialect_string_for_known_dialect(self):
        for dialect, expected in _SMB_DIALECTS.items():
            sock = _mock_socket(recv_data=_smb_response(dialect))
            with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
                result = _smb_banner("10.0.0.1", 445, timeout=1.0)
            assert result == expected

    def test_returns_none_for_unknown_dialect(self):
        sock = _mock_socket(recv_data=_smb_response(0xFFFF))
        with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
            result = _smb_banner("10.0.0.1", 445, timeout=1.0)
        assert result is None

    def test_returns_none_when_response_too_short(self):
        sock = _mock_socket(recv_data=b"\x00" * 10)
        with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
            result = _smb_banner("10.0.0.1", 445, timeout=1.0)
        assert result is None

    def test_returns_none_when_wrong_magic(self):
        bad = _smb_response(0x0210)
        bad = bad[:4] + b"\xffSMB" + bad[8:]  # corrupt magic
        sock = _mock_socket(recv_data=bad)
        with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
            result = _smb_banner("10.0.0.1", 445, timeout=1.0)
        assert result is None

    def test_returns_none_on_connection_error(self):
        with patch("sondare.utils.banners.socket.create_connection", side_effect=OSError):
            result = _smb_banner("10.0.0.1", 445, timeout=1.0)
        assert result is None


# ---------------------------------------------------------------------------
# grab_banner — raw (non-HTTP, non-SMB) ports
# ---------------------------------------------------------------------------

class TestGrabBannerRaw:
    def test_returns_banner_text(self):
        sock = _mock_socket(recv_data=b"SSH-2.0-OpenSSH_8.9\r\n")
        with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
            assert grab_banner("10.0.0.1", 22, timeout=1.0) == "SSH-2.0-OpenSSH_8.9"

    def test_strips_whitespace(self):
        sock = _mock_socket(recv_data=b"  220 FTP ready  \r\n")
        with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
            assert grab_banner("10.0.0.1", 21, timeout=1.0) == "220 FTP ready"

    def test_returns_none_when_empty_response(self):
        sock = _mock_socket(recv_data=b"")
        with patch("sondare.utils.banners.socket.create_connection", return_value=sock):
            assert grab_banner("10.0.0.1", 22, timeout=1.0) is None

    def test_returns_none_on_connection_error(self):
        with patch("sondare.utils.banners.socket.create_connection", side_effect=OSError):
            assert grab_banner("10.0.0.1", 22, timeout=1.0) is None

    def test_returns_none_on_timeout(self):
        import socket
        with patch("sondare.utils.banners.socket.create_connection", side_effect=socket.timeout):
            assert grab_banner("10.0.0.1", 22, timeout=1.0) is None


# ---------------------------------------------------------------------------
# grab_banner — SMB ports
# ---------------------------------------------------------------------------

class TestGrabBannerSmb:
    def test_delegates_to_smb_banner(self):
        for port in (139, 445):
            with patch("sondare.utils.banners._smb_banner", return_value="SMB 2.1") as mock_smb:
                result = grab_banner("10.0.0.1", port, timeout=1.0)
            mock_smb.assert_called_once_with("10.0.0.1", port, 1.0)
            assert result == "SMB 2.1"


# ---------------------------------------------------------------------------
# grab_banner — HTTP ports
# ---------------------------------------------------------------------------

class TestGrabBannerHttp:
    def test_returns_server_header(self):
        response = "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n"
        with patch("sondare.utils.banners._fetch_http", return_value=response):
            assert grab_banner("10.0.0.1", 80, timeout=1.0) == "nginx/1.24"

    def test_follows_meta_refresh_on_first_page(self):
        first = "HTTP/1.1 200 OK\r\n\r\n" \
                '<meta http-equiv="refresh" content="0; URL=/admin">'
        second = "HTTP/1.1 200 OK\r\nServer: lighttpd\r\n\r\n"
        with patch("sondare.utils.banners._fetch_http", side_effect=[first, second]) as mock_fetch:
            result = grab_banner("10.0.0.1", 8080, timeout=1.0)
        assert result == "lighttpd"
        assert mock_fetch.call_args_list == [
            call("10.0.0.1", 8080, "/", 1.0, tls=False),
            call("10.0.0.1", 8080, "/admin", 1.0, tls=False),
        ]

    def test_falls_back_to_first_line_when_no_headers_or_title(self):
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        with patch("sondare.utils.banners._fetch_http", return_value=response):
            result = grab_banner("10.0.0.1", 80, timeout=1.0)
        assert result == "HTTP/1.1 200 OK"

    def test_returns_none_on_fetch_error(self):
        with patch("sondare.utils.banners._fetch_http", side_effect=OSError):
            assert grab_banner("10.0.0.1", 80, timeout=1.0) is None


# ---------------------------------------------------------------------------
# grab_banner — HTTPS ports
# ---------------------------------------------------------------------------

class TestGrabBannerHttps:
    def test_uses_tls_for_https_ports(self):
        response = "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n"
        with patch("sondare.utils.banners._fetch_http", return_value=response) as mock_fetch:
            grab_banner("10.0.0.1", 443, timeout=2.0)
        mock_fetch.assert_called_once_with("10.0.0.1", 443, "/", 2.0, tls=True)

    def test_port_8443_also_uses_tls(self):
        response = "HTTP/1.1 200 OK\r\nServer: Tomcat\r\n\r\n"
        with patch("sondare.utils.banners._fetch_http", return_value=response) as mock_fetch:
            grab_banner("10.0.0.1", 8443, timeout=1.0)
        mock_fetch.assert_called_once_with("10.0.0.1", 8443, "/", 1.0, tls=True)

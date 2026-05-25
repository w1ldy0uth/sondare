import json
import socket
from unittest.mock import patch, MagicMock
from sondare.models import Host, Port
from sondare.main import main


def _args(**kwargs):
    defaults = dict(scan_method=None, verbose=False, timeout=1, json=False)
    defaults.update(kwargs)
    m = MagicMock()
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


def _net_mocks():
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = "192.168.1.5"
    addr.netmask = "255.255.255.0"
    stat = MagicMock()
    stat.isup = True
    return {"eth0": [addr]}, {"eth0": stat}


class TestArpJsonOutput:
    def test_json_flag_prints_json(self, capsys):
        args = _args(scan_method="arp", json=True)
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = [
            Host(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:01"),
            Host(ip="192.168.1.3", mac="aa:bb:cc:dd:ee:02"),
        ]

        addrs, stats = _net_mocks()
        with patch("sondare.main.system_utils.is_running_as_root", return_value=True), \
             patch("sondare.main.parse_args") as mock_parse_args, \
             patch("sondare.main.Arp", return_value=mock_scanner), \
             patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            mock_parse_args.return_value.parse_args.return_value = args
            main()

        output = capsys.readouterr().out
        parsed = json.loads(output.strip().splitlines()[-1])
        assert parsed == {"hosts": [
            {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:01"},
            {"ip": "192.168.1.3", "mac": "aa:bb:cc:dd:ee:02"},
        ]}

    def test_no_json_flag_prints_table(self, capsys):
        args = _args(scan_method="arp", json=False)
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = [Host(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:01")]

        addrs, stats = _net_mocks()
        with patch("sondare.main.system_utils.is_running_as_root", return_value=True), \
             patch("sondare.main.parse_args") as mock_parse_args, \
             patch("sondare.main.Arp", return_value=mock_scanner), \
             patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            mock_parse_args.return_value.parse_args.return_value = args
            main()

        output = capsys.readouterr().out
        assert "192.168.1.2" in output
        assert "aa:bb:cc:dd:ee:01" in output
        assert output.strip().splitlines()[-1] != "["  # not JSON


class TestPingJsonOutput:
    def test_json_flag_prints_json(self, capsys):
        args = _args(scan_method="ping", threads=1, json=True)
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = ["192.168.1.2", "192.168.1.5"]

        addrs, stats = _net_mocks()
        with patch("sondare.main.system_utils.is_running_as_root", return_value=True), \
             patch("sondare.main.parse_args") as mock_parse_args, \
             patch("sondare.main.Ping", return_value=mock_scanner), \
             patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            mock_parse_args.return_value.parse_args.return_value = args
            main()

        output = capsys.readouterr().out
        parsed = json.loads(output.strip().splitlines()[-1])
        assert parsed == {"hosts": ["192.168.1.2", "192.168.1.5"]}

    def test_no_json_flag_prints_alive(self, capsys):
        args = _args(scan_method="ping", threads=1, json=False)
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = ["192.168.1.2"]

        addrs, stats = _net_mocks()
        with patch("sondare.main.system_utils.is_running_as_root", return_value=True), \
             patch("sondare.main.parse_args") as mock_parse_args, \
             patch("sondare.main.Ping", return_value=mock_scanner), \
             patch("psutil.net_if_addrs", return_value=addrs), \
             patch("psutil.net_if_stats", return_value=stats):
            mock_parse_args.return_value.parse_args.return_value = args
            main()

        assert "192.168.1.2 is alive" in capsys.readouterr().out


class TestTcpJsonOutput:
    def _tcp_args(self, use_json: bool):
        from sondare.main import Target
        args = _args(
            scan_method="tcp",
            threads=1,
            retries=0,
            target=Target("10.0.0.1", 80, 80),
            json=use_json,
        )
        return args

    def test_json_flag_prints_json(self, capsys):
        args = self._tcp_args(use_json=True)
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = [Port(ip="10.0.0.1", port=80)]

        with patch("sondare.main.system_utils.is_running_as_root", return_value=True), \
             patch("sondare.main.parse_args") as mock_parse_args, \
             patch("sondare.main.Tcp", return_value=mock_scanner):
            mock_parse_args.return_value.parse_args.return_value = args
            main()

        output = capsys.readouterr().out
        parsed = json.loads(output.strip().splitlines()[-1])
        assert parsed == {"host": "10.0.0.1", "ports": [80]}

    def test_no_json_flag_prints_open(self, capsys):
        args = self._tcp_args(use_json=False)
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = [Port(ip="10.0.0.1", port=80)]

        with patch("sondare.main.system_utils.is_running_as_root", return_value=True), \
             patch("sondare.main.parse_args") as mock_parse_args, \
             patch("sondare.main.Tcp", return_value=mock_scanner):
            mock_parse_args.return_value.parse_args.return_value = args
            main()

        assert "10.0.0.1:80 is open" in capsys.readouterr().out

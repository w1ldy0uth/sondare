# Contributing to sondare

## Setup

**macOS / Linux**
```bash
git clone https://github.com/w1ldy0uth/sondare.git
cd sondare
./init.sh
source sondare_venv/bin/activate
```

**Windows**
```bat
git clone https://github.com/w1ldy0uth/sondare.git
cd sondare
init.bat
call sondare_venv\Scripts\activate
```

`init.sh` / `init.bat` creates a virtual environment and installs the package in editable mode (`pip install -e .`). No separate dependency installation step is needed.

For development extras (pytest, build, twine):
```bash
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/
```

All tests are fully mocked — no real network interfaces or root privileges are required. The CI matrix runs Python 3.10–3.13 on Ubuntu.

If you add a new utility that touches `psutil.net_if_addrs` or `psutil.net_if_stats`, use the `net_mocks` fixture from `tests/conftest.py` rather than writing your own mock.

## Project layout

```
sondare/
  services/       # Protocol scanners: arp, icmp, tcp, udp, fingerprint, graph
  monitors/       # Real-time watchers: arp_watcher, hosts_watcher, port_watcher, traffic_sniffer
  utils/          # Shared infrastructure: network, banners, adaptive_pool, root
  models.py       # NamedTuple data models: Host, Port, Fingerprint
  main.py         # CLI entry point (argparse + dispatch)
tests/            # One test file per module, named test_<module>.py
```

## Adding a feature

### New scan command

1. Add a service class in `sondare/services/` with `scan()` and `get_results()` methods.
2. Register the subparser in `parse_args()` in `main.py`.
3. Add the dispatch block in `main()`.
4. Add table and `--json` output handling.
5. Add an example line to the epilog in `parse_args()`.
6. Update `README.md` — the command table, examples, and options sections.

### New utility function

Add it to `sondare/utils/network.py` if it is network-related, or create a new file under `sondare/utils/` for larger concerns (see `banners.py` as an example). Import it explicitly — avoid wildcard imports.

### Data model changes

`Host`, `Port`, and `Fingerprint` in `models.py` are `NamedTuple`s. New fields must have a default value to remain backward compatible with existing test fixtures and JSON output.

## Writing tests

- One test file per module: `tests/test_<module>.py`.
- Mock Scapy calls at the service level (e.g. `patch("sondare.services.tcp.sr1")`), not at the Scapy package level.
- JSON output tests should assert the full parsed structure, not just substrings.
- Do not write tests that require root or send real packets.

## Commit and branch naming

Branches and commit messages follow this pattern:

```
feat/<version>-<short_description>      # new feature
chore/<version>-<short_description>     # refactor, config, tooling
fix/<version>-<short_description>       # bug fix
```

Examples: `feat/1.0.4-udp_service_names`, `fix/1.0.4-adaptive_pool_edge_case`, `chore/1.0.4-ci_zeroconf_dep`.

## Dependencies

Runtime dependencies are declared in `pyproject.toml`. Before adding a new dependency, consider whether the feature can be implemented with the standard library or with Scapy (already required). New dependencies must work on Python 3.10–3.13 and across macOS, Linux, and Windows.

If a dependency is only needed for an optional feature, discuss it in the PR — the current precedent is to add it as a required dependency if the feature it enables is always available in the CLI (see `zeroconf` added for hostname resolution in v1.0.3).

## Raw packet requirements

sondare uses Scapy for raw packet crafting and requires root on Unix and Npcap on Windows at runtime. This does not affect test authoring — all tests mock the network layer and run unprivileged.

When implementing a new scan method, always pass `promisc=False` to Scapy's `sr`, `sr1`, and `srp` calls. Omitting it causes promiscuous mode errors on macOS BPF sockets.

# sondare - Backend Migration Plan

**Status:** Pre Development

**Author:** Ivan w1ldy0uth Shurygin

**Goal:** Own the scan engine above libpcap/pnet/Npcap - codec, TX/RX logic, state machines, rate limiter - and ship sondare as a high-performance binary competitive with nmap on LAN-specific depth.

## 1. Why migrate

sondare is mature in features and architecture, but structurally it is **glue**: thin service classes orchestrating Scapy, `zeroconf`, `cryptography`, and `psutil`. As a scan engine that has concrete costs:

- **Per-packet Python overhead.** Every `sr1()`/`srp()` builds a Python object graph and dissects responses into Python layers. At scale (a /16 ≈ 65k hosts × wide port range) this dominates wall-clock time; at /8 (16M hosts) it is simply unusable.
- **Synchronous, thread-per-probe model.** sondare blocks one OS thread per probe inside `sr1()`; the GIL serializes the work, and `AdaptivePool` exists mostly to fight the resulting congestion. This is the opposite of how fast scanners are built.
- **No ownership of the scan engine.** The timing model, concurrency strategy, packet codec, and retransmit logic all live inside Scapy. There is no path to nmap-class depth - OS fingerprinting improvements, custom probe sequences, sub-second /16 sweeps - without owning those layers.

## 2. Architectural decisions

### 2.1 Language - **Rust**

- **Memory safety without a GC** for an untrusted-bytes packet parser, and no pause jitter in the TX/RX loop or long-running monitors (we measure RTT).
- **Best-in-class Python interop** via PyO3 + `maturin` for the migration scaffold and optional library.
- **Single binary** as the eventual distribution artifact. Precedent: nmap, RustScan.

Runner-up was Go (great concurrency, easy binaries) but it loses on GC jitter and clunky `cgo` embedding. C/C++ give control but reintroduce memory-safety risk in the riskiest component.

### 2.2 Key concepts

- **Abstraction over libpcap/pnet/Npcap.** One `Datalink` trait (`send` / `recv` / `set_filter`) with thin per-OS backends: `AF_PACKET` (Linux), `/dev/bpf` (macOS/BSD), Npcap (Windows). We own the logic above this trait - codec, engine, state machines - not the OS-facing I/O primitives below it. Npcap on Windows is the one accepted platform driver, the same as nmap and Wireshark.
- **Stateless asynchronous engine.** Split transmit from receive; encode probe identity into the packet (e.g. TCP seq = `hash(ip, port, secret)`) so the receiver validates by recomputing the hash - no connection table, O(1) state. Rate-limit instead of thread-limit; batch syscalls (`sendmmsg`/`recvmmsg`); reuse buffers. Keep configurable retransmits so LAN-audit accuracy stays high.
- **Hand-rolled protocol codec.** Ether / ARP / IPv4 / IPv6 / TCP (+ options) / UDP / ICMP / ICMPv6 / minimal DNS are fixed byte layouts - write and unit-test them directly, no protocol library. Fully testable without privileges.
- **Serial per-scanner migration with hard TTL.** Each scanner: rewrite in Rust -> differential parity test -> cut over -> delete Python version. The next scanner starts only after deletion. No indefinite dual-engine drift.
- **`models.py` is the FFI contract.** `Host`, `Port`, `Fingerprint`, `Hop`, `MdnsRecord`, `TlsCert` are frozen the moment the first Rust scanner goes live via PyO3. Every field addition is an FFI renegotiation.
- **Standalone binary is a consequence, not a goal.** The binary ships when the engine is proven. The Python module is a secondary artifact - useful, not the product.

### 2.3 Open decision

Phase 6 self-containment depth: vetted Rust crates (`rustls`/`x509-parser` for TLS, `hickory-dns` for mDNS) versus hand-rolling. Vetted crates are not a goal violation - they are the engine boundary judgment call deferred to when Phase 5 is done and the scope is clear.

## 3. Roadmap

Each phase is independently shippable and keeps the tool working. Scanner replacement is serial - rewrite -> parity -> cut over -> delete - never parallel.

| Phase | Deliverable | Exit criterion |
| ------- | ------------- | ---------------- |
| **0. Foundations** | Cargo workspace + PyO3/`maturin` scaffold; CI wheels (Linux/macOS/Windows); differential parity harness (Scapy vs Rust on identical packet captures); freeze `models.py` contract. | Trivial Rust extension `pip install`s on all three OSes in CI. |
| **1. Codec** | Hand-written encode/decode + checksums for all protocols sondare uses, no I/O, no root. | Our bytes == Scapy's bytes on golden tests; zero `unsafe`. |
| **2. Datalink** | `Datalink` trait + `AF_PACKET` / BPF / Npcap backends; interface discovery; BPF filter install. | ARP who-has sent and reply received on each OS. |
| **3. Engine** | Stateless TX/RX split, identity-in-packet validation, pps rate limiter, retransmit, adaptive timeout. Replaces `sr1`/`sr`/`srp`. | /16 ICMP sweep measurably outperforms Python; same host set returned. |
| **4. Scan ops** | Scanners via PyO3, serial order: ICMP -> ARP -> TCP SYN -> UDP -> fingerprint -> NDP/trace -> graph. Each: rewrite -> differential parity -> cut over -> delete Python. | All Scapy scanner imports deleted; pytest suite green against Rust engine. |
| **5. Capture** | Sniffer + monitors over the datalink RX loop + BPF (`traffic`, `arp`, `ndp`, `hosts`, `ports`). | Monitors run with no Scapy import. |
| **6. Self-contained** | Native OUI table, mDNS, TLS cert parsing, interface/cache enumeration; drop `scapy`/`zeroconf`/`cryptography`/`psutil`/subprocess. Vetted crates (`rustls`, `x509-parser`, `hickory-dns`) acceptable; scope decided at Phase 5 completion. | No Python runtime required; Npcap remains the one accepted platform dep on Windows. |
| **7. Cutover** | Promote `sondare` binary as primary release artifact (prebuilt CI binaries); update README/CLAUDE.md/publish workflow. | Standalone binary is the shipped product; Python module optional. |

## 4. Key risks

- **Privileges** - raw sockets need root / `CAP_NET_RAW` / admin+Npcap (sondare already requires root; document `setcap`).
- **Cross-platform raw I/O divergence** - isolate behind the `Datalink` trait; per-OS CI; golden tests.
- **Windows/Npcap distribution** - blocking problem for "standalone binary primary"; must be solved and CI-validated before Phase 4 scanner 3 (TCP SYN) ships.
- **FFI contract freeze** - `models.py` fields must not change once any Rust scanner is live; track as a hard constraint from Phase 0.
- **Silent correctness regressions** - hand-rolled codec can produce subtly wrong packets that look like success; the differential parity harness (Phase 0) is the guard against this throughout Phases 1–4.
- **Stateless scan precision** - retransmits + adaptive timing keep accuracy above internet-scale tools.
- **Release matrix** (wheels/binaries × OS × arch) - set up `cibuildwheel`-style CI in Phase 0.

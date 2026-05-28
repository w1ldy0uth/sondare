# Security Policy

## Supported Versions

| Version   | Supported |
| --------- | --------- |
| >= 1.0.1  | Yes       |
| < 1.0     | No        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report them via one of these channels:

- **GitHub private advisory** — [Report a vulnerability](https://github.com/w1ldy0uth/sondare/security/advisories/new)
- **Email** — shurygin1vs@gmail.com

Include as much detail as you can: steps to reproduce, affected version, and potential impact.

## Scope

sondare is a local-network scanning tool intended for use on networks you own or have explicit permission to scan. Vulnerabilities in scope include:

- Code execution or privilege escalation via crafted network responses
- Dependency vulnerabilities with a realistic attack path
- Unsafe handling of user-supplied input (e.g. target addresses, BPF filters)

Out of scope: issues that require the attacker to already have root access on the machine running sondare.

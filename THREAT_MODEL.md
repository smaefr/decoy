# Threat model

decoy is an internet-facing honeypot. Assume the HTTP and SSH sockets are
reachable by anyone. The process stores attacker-supplied data, never operator
secrets, and never grants access to a real account.

## Assets

| Asset | Sensitivity | Handling |
| --- | --- | --- |
| SQLite telemetry | Low–medium (attacker payloads, source IPs) | Local file or volume; truncate snippets; redact captured passwords in snippets |
| Process memory | Low | No real credentials, API keys, or private keys |
| Host network | High if misbound | Bind only the intended interfaces; do not share a network with production data stores |
| Operator workstation | High | Query CLI is read-only against the decoy database |

This software must not be given real user passwords, cloud keys, or SSH host
keys. The SSH listener does not implement protocol, kex, or authentication.

## Trust boundary

The trust boundary is the listening sockets (`:8080` HTTP, `:2222` SSH banner).
Every byte past `accept()` / `do_*` is untrusted. Parser, scorer, and SQLite
treat payloads as opaque hostile input.

## STRIDE

### Spoofing

- Attackers can fake source IPs only to the extent the network path allows
  (typical for any internet socket). Events record the TCP peer the kernel saw.
- The HTTP `Server` header and SSH identification string are intentionally
  generic decoy banners. They do not imply a real Apache or OpenSSH instance.
- Mitigation: do not authenticate anyone; do not trust captured usernames.

### Tampering

- Attackers can send oversized, binary, or malformed bodies. Reads are capped
  (1 MiB HTTP, 4 KiB SSH) and decoded with replacement.
- SQLite file on disk can be modified by anyone with host access.
- Mitigation: run as an unprivileged user; put the database on a dedicated
  volume; do not reuse this database as an application backend.

### Repudiation

- Telemetry timestamps are UTC ISO-8601 from the host clock. They are not a
  legal audit log and can be lost if the process or disk fails.
- Mitigation: treat events as operational signals, not evidence of identity.

### Information disclosure

- The fake login form and SSH banner advertise a service that does not exist.
  That is the point, but it also reveals that a honeypot may be present if
  probed carefully (always-fail auth, banner-then-close SSH).
- Snippets could echo attacker secrets *they typed into the decoy*. Those are
  still attacker-controlled strings, not operator secrets. Long values are
  truncated; password fields are redacted in snippets when length ≥ 3.
- Mitigation: never configure real credentials; restrict who can `decoy query`
  or read the SQLite file.

### Denial of service

- Unauthenticated clients can open many connections or POST large bodies.
  Thread-per-connection handlers can exhaust file descriptors or RAM.
- Mitigation: rate scoring is observational only (it does not drop traffic).
  Put decoy behind a firewall, connection limit, or dedicated host. Docker
  resource limits are recommended.

### Elevation of privilege

- There is no real login and no SSH auth to bypass. Successful “auth” is not
  implemented and must not be added.
- SQLite path traversal via `DECOY_DB` is an operator configuration issue.
- Mitigation: keep the process unprivileged; do not run as root; do not mount
  sensitive host paths into the container.

## Non-goals

- Not a production IDP, WAF, or SSH server.
- Not a credential-harvesting tutorial and not a place to store real secrets.
- Signatures detect common probe tokens; they are not exploit documentation.
- No outbound beacons, no payload execution, no shelling out on request data.

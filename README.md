# IPv6 readiness check

Check whether a domain or the server you are on is ready for IPv6. IPv6 (Internet
Protocol version 6) is the newer version of the addressing system that lets devices
find each other on the internet. It succeeds IPv4 (version 4), the older system
whose addresses are running out. This repository measures whether a service still
works when it is reached over IPv6.

The method is MGv6C-1.0 (Malaysian Government IPv6 Compliance, version 1.0), the
standard used by the National IPv6 Readiness Monitor at https://ipv6.my6.my. The
checks and the scoring here match that monitor.

It is built to be driven by an AI coding agent. Point Claude Code, Codex CLI, Gemini
CLI or any chat assistant with a terminal at this repository and ask, in one
sentence, to check a domain or to audit the server. The agent reads `AGENTS.md` and
follows it. It also works by hand.

## What it does

- **Scenario A: check a domain.** Runs 22 scored checks across the website, DNS and
  DNSSEC, email and the existing IPv4 service, then produces a score out of 100 and a
  plain list of what to fix. DNS (the Domain Name System, which turns names into
  addresses) is queried over HTTPS, so no extra tools are needed. DNSSEC (DNS
  Security Extensions) lets a resolver detect forged DNS answers.
- **Scenario B: audit this server.** A strictly read-only audit of the server's IPv6
  configuration, connectivity, listening sockets, service settings and firewall
  state. It ends with findings ranked as blockers, gaps and notes.

## Requirements

- Scenario A needs Python 3.8 or newer and uses only the standard library. It runs on
  Windows, macOS and Linux.
- Scenario B needs Bash on Linux. It uses common tools such as `ip`, `ss` and `curl`
  where they are present.
- Neither script needs root. Neither installs anything.

## Quick start

Check a domain and compare with the official monitor score:

```bash
python3 scripts/ipv6check.py example.gov.my --official
```

Audit the server you are on and also write a JSON (machine-readable text) file:

```bash
bash scripts/server-audit.sh --json
```

Replace `example.gov.my` with the domain you care about. Add `--json` to the first
command if you want machine-readable output instead of the human report.

## What the scripts send over the network

Scenario A sends only:

- DNS over HTTPS (DoH) lookups to Google Public DNS (`dns.google`) and, as a
  fallback, Cloudflare (`cloudflare-dns.com`), to resolve the domain's records.
- Probes to the target itself: web requests on ports 80 and 443, DNS queries on port
  53 to its name servers and SMTP (the protocol that moves mail between servers)
  connections on port 25 to its mail servers. The web requests follow up to three
  redirects, which may lead to another host.
- Short connections to test whether this computer has IPv6, to `ipv6.my6.my` on port
  443 and to the DoH resolvers (`dns.google` and `cloudflare-dns.com`) on port 443,
  all over IPv6. It never connects to port 53 of a public resolver.
- With `--official` only, one request to the official API at
  `https://ipv6.my6.my/api/v1/domains/<domain>`.

Scenario B sends only three outbound connectivity tests: HTTPS to `ipv6.my6.my` over
IPv6, a TCP connection to the Cloudflare DoH resolver `[2606:4700:4700::1111]` on port
443 over IPv6 and an HTTPS request to `1.1.1.1` over IPv4 as a baseline for
comparison. Everything else is a local read. Pass `--no-outbound` to skip the three
tests.

There is no telemetry and nothing is sent anywhere else.

## The safety promise for scenario B

The server audit is strictly read-only. It:

- changes no setting, installs nothing and restarts nothing;
- never uses `sudo`; where a detail needs root to read, such as firewall rules, it
  says "needs root to read" and carries on;
- writes nothing outside the current directory, and only writes `ipv6-audit.json`
  when you pass `--json`;
- never prints private keys, passwords, tokens, `.env` contents or full firewall rule
  dumps. It reads only the IPv6-relevant lines of service configuration.

## The score

The score is a weighted percentage:

| Part | Scored checks | Weight |
| --- | --- | --- |
| Website | 8 | 35 |
| DNS and DNSSEC | 5 | 25 |
| Email | 6 | 25 |
| Existing IPv4 service | 3 | 15 |

The levels are: 90 to 100 "Compliant: fully ready", 60 to 89 "Partially compliant"
and 0 to 59 "Non-compliant: not ready". Four more items are reported as information
and do not affect the score: the DS record (the anchor that links a domain's DNSSEC
keys to its parent zone), RRSIG validity (whether the DNSSEC signatures are still in
date), the DNSSEC algorithm (the cryptographic method used to sign) and the DKIM
selector (the name that locates the key used to verify email signatures). See
`docs/METHOD.md` for the full method and a worked example.

### Not measured is not failed

The script first tests whether this computer has working outbound IPv6. If it does
not, every check that needs an IPv6 connection is reported as NOT MEASURED, never as
failed, and the score is marked PROVISIONAL. To simulate this for a test or a demo,
set `IPV6CHECK_FORCE_NO_V6=1`:

```bash
IPV6CHECK_FORCE_NO_V6=1 python3 scripts/ipv6check.py example.gov.my
```

The same principle applies to SMTP over IPv6: a timeout is treated as not measured,
while a refused connection is a real failure.

## Relationship to ipv6.my6.my and MGv6C-1.0

This repository is an independent, offline implementation of the MGv6C-1.0 method
that the National IPv6 Readiness Monitor publishes at https://ipv6.my6.my. It runs
the same 22 checks with the same weights and the same not-measured rule, from the
computer you run it on. With `--official` it fetches the monitor's own score for a
monitored domain and shows it beside the local score, so you can compare the two.
It is not affiliated with or endorsed by the monitor; it simply implements the
published method.

## For AI agents

Read `AGENTS.md`. It contains the safety rules, the two scenarios, how to interpret
each result and the exact report to give the user. `CLAUDE.md` and `GEMINI.md` point
to it.

## Repository layout

```
scripts/ipv6check.py       scenario A, the domain checker
scripts/server-audit.sh    scenario B, the read-only server audit
tests/test_scoring.py      offline unit tests for the scoring
docs/METHOD.md             the 22 checks, scoring, levels and limits
docs/REPORT-TEMPLATE.md    the report layout for both scenarios
docs/DEMO.md               a live demonstration script
AGENTS.md                  instructions for an AI agent
```

## Tests

Run the offline unit tests with:

```bash
python3 -m unittest discover tests
```

## Licence

MIT. Copyright 2026 My6 Initiative Berhad. See `LICENSE`.

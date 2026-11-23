# Changelog

## 23 November 2026

- Name-server, mail-server and address look-ups no longer fail when a domain's
  DNSSEC chain is broken. The look-ups now ask the resolver not to validate, as
  the monitor's own look-ups do; only the DNSSEC check validates.
- A redirect that cannot be followed over IPv6 (for example http to https on a
  name that has no AAAA record) no longer turns a working HTTP answer into a
  failure. The last status received counts, as in the monitor.
- If a computer cannot look up the names of the two public DNS-over-HTTPS resolvers, the script now uses their fixed IPv4 addresses (the certificate is still checked against the name).
- AGENTS.md and docs: how to read the levels, the DNS-only survey levels, the two
  government deadlines, a clearer no-IPv6 route, and the `--official` comparison.
- Criteria version stays 1.0 (the site publishes "My6 IPv6 Readiness Criteria
  1.0"); the site's internal scoring rules are at 1.4; this script matches them.

## 17 November 2026

- IPv6-only check accepts 307 and 308 and retries with GET when HEAD is refused.

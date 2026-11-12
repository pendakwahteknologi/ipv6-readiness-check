# The MGv6C-1.0 method, as implemented in this repository

This document describes the 22 scored checks, how this repository runs each one,
the scoring formula, the compliance levels and the limits of an outside test. It
follows MGv6C-1.0 (Malaysian Government IPv6 Compliance, version 1.0), the method
used by the National IPv6 Readiness Monitor at https://ipv6.my6.my.

The checks are grouped into four parts. Each part has a fixed weight in the final
score. A further four items are reported as information and do not affect the score.

## Terms used in this document

- **IPv6:** Internet Protocol version 6, the newer internet addressing system.
- **IPv4:** Internet Protocol version 4, the older addressing system still in wide use.
- **DNS:** the Domain Name System, which turns names like example.gov.my into addresses.
- **AAAA record:** a DNS record that holds an IPv6 address.
- **A record:** a DNS record that holds an IPv4 address.
- **NS record:** a DNS record that names an authoritative name server for a domain.
- **MX record:** a DNS record that names a mail server for a domain.
- **TXT record:** a DNS record that holds text, used for email authentication policies.
- **PTR record:** a reverse DNS record that maps an address back to a name.
- **DoH:** DNS over HTTPS, a way to ask DNS questions over an encrypted web connection.
  This repository uses the JSON API of Google Public DNS with Cloudflare as a fallback.
- **AD flag:** the Authenticated Data flag in a DNS answer. A validating resolver sets it
  when DNSSEC validation of the answer succeeded.
- **DNSSEC:** DNS Security Extensions, signatures that let a resolver detect forged DNS answers.
- **DS record:** the Delegation Signer record that links a zone's DNSSEC key to its parent zone.
- **RRSIG:** the DNSSEC signature record that covers a set of DNS records.
- **DNSKEY:** the DNS record that holds a DNSSEC public key.
- **SOA record:** the Start of Authority record, the DNS record that carries a zone's administrative details.
- **TLS:** Transport Layer Security, the encryption that protects HTTPS connections.
- **SNI:** Server Name Indication, the field that tells a server which hostname the client wants.
- **SMTP:** Simple Mail Transfer Protocol, the protocol that moves mail between servers.
- **STARTTLS:** the SMTP command that upgrades a mail connection to an encrypted one.
- **SPF:** Sender Policy Framework, a record listing servers allowed to send mail for a domain.
- **DMARC:** a policy record telling receivers how to handle mail that fails authentication.
- **DKIM:** DomainKeys Identified Mail, a signature that lets a receiver verify a mail's origin.
- **HTTP/3:** the newest version of the web protocol, built on the QUIC transport.
- **QUIC:** the UDP-based transport that HTTP/3 runs on.
- **Alt-Svc:** a response header a server uses to advertise alternative protocols such as HTTP/3.
- **Dual stack:** running IPv4 and IPv6 at the same time.
- **ULA:** a unique local address, an IPv6 address for private networks, not the public internet.

## Part 1: website (8 checks, weight 35)

| Check | What it tests | How this repository tests it | Standard |
| --- | --- | --- | --- |
| A1 AAAA record | The domain publishes an IPv6 address. | DoH AAAA query, trying the www prefix if the root has none. | RFC 3596 |
| A2 Globally routable IPv6 | The address is public, not reserved or private. | Classify each AAAA address, excluding loopback, link-local, ULA and documentation ranges. | RFC 8200, RFC 6724 |
| A3 HTTP over IPv6 | The web server answers on port 80 over IPv6. | A HEAD request to port 80 over an IPv6 socket, following up to three redirects over IPv6 only. Any HTTP response counts. | RFC 8200, RFC 8305 |
| A4 HTTPS over IPv6 | The web server answers on port 443 over IPv6. | A HEAD request to port 443 over an IPv6 socket with TLS and SNI, following up to three redirects over IPv6 only. | RFC 8200, RFC 9325 |
| A5 IPv6-only reachability | The site loads with no IPv4 fallback. | A separate no-follow HEAD probe over IPv6 only, accepting status 200, 301, 302 or 303. | RFC 8200, RFC 8305 |
| A6 TLS certificate valid (IPv6) | The certificate over IPv6 is valid and matches the name. | A TLS handshake over IPv6 with full certificate validation and SNI. The verdict comes from the handshake alone, not the HTTP status. | RFC 9325, RFC 9846 |
| A7 Dual-stack | Both A and AAAA records exist. | DoH A and AAAA queries, both must return an address. | RFC 6724, RFC 8305 |
| A8 HTTP/3 (QUIC) | The server advertises HTTP/3. | Read the Alt-Svc header over IPv6, trying every AAAA address until one advertises h3. | RFC 9114 |

These website checks follow the monitor's decision rules. The HTTP and HTTPS checks
follow up to three redirects, and every hop must stay on IPv6. A redirect may move to
another host, but each new target is re-resolved to an AAAA address, and a target with
no IPv6 address ends the chain as a failure. The IPv6-only check is deliberately
separate: it sends one HEAD request with no redirect following, so a site that only
reaches IPv6 through a redirect is not counted as natively reachable. Separately, the
DoH lookups and the official API call refuse any redirect that leaves their own host,
so a lookup cannot be silently sent to a third party.

## Part 2: DNS and DNSSEC (5 checks, weight 25)

| Check | What it tests | How this repository tests it | Standard |
| --- | --- | --- | --- |
| B1 NS has AAAA record | At least one name server has an IPv6 address. | DoH NS query, then a DoH AAAA query for up to four name servers. | RFC 3596, RFC 10001 |
| B2 NS reachable via IPv6 | A name server accepts TCP on port 53 over IPv6. | Open a TCP connection to a name server's IPv6 address on port 53. | RFC 10001, RFC 8200 |
| B3 NS answers queries via IPv6 | The name server actually answers over IPv6. | Send a hand-built DNS A query over IPv6, UDP first with TCP as a fallback, and check for answer records. | RFC 10001 |
| B4 DNSSEC validated | The zone's DNSSEC chain of trust validates. | Read the AD flag from the validating DoH resolver for the zone. It passes only when Status is 0 and AD is true. This is a stand-in for the monitor's own validating resolver. | RFC 4033, RFC 4034, RFC 4035, RFC 9364 |
| B5 Reverse DNS (PTR) | A PTR record exists for the IPv6 address. | DoH PTR query on the address's ip6.arpa name. | RFC 3596 |

## Part 3: email (6 checks, weight 25)

| Check | What it tests | How this repository tests it | Standard |
| --- | --- | --- | --- |
| C1 MX record exists | The domain names a mail server. | DoH MX query. | RFC 5321 |
| C2 MX server has IPv6 | The highest-priority mail server has an IPv6 address. | DoH AAAA query for the first MX host. | RFC 3596, RFC 5321 |
| C3 SMTP reachable via IPv6 | The mail server answers on port 25 over IPv6. | Connect over IPv6 to port 25 and read the 220 banner, with up to three attempts of five seconds each while the outcome is indeterminate. | RFC 5321 |
| C4 STARTTLS over IPv6 | The mail server offers encryption over IPv6. | Send EHLO on the same IPv6 connection and look for STARTTLS, using the same limited retries. | RFC 3207 |
| C5 SPF record | A v=spf1 TXT record exists. | DoH TXT query and look for v=spf1. | RFC 7208 |
| C6 DMARC record | A v=dmarc1 record exists at _dmarc. | DoH TXT query at _dmarc.<domain> and look for v=dmarc1. | RFC 9989 |

## Part 4: existing IPv4 service (3 checks, weight 15)

| Check | What it tests | How this repository tests it | Standard |
| --- | --- | --- | --- |
| D1 A record | The domain still publishes an IPv4 address. | DoH A query, trying the www prefix if the root has none. | RFC 6724, RFC 8305 |
| D2 HTTP over IPv4 | The web server answers on port 80 over IPv4. | A HEAD request to port 80 over an IPv4 socket. | RFC 8305 |
| D3 HTTPS over IPv4 | The web server answers on port 443 over IPv4. | A HEAD request to port 443 over an IPv4 socket with TLS and SNI. | RFC 8305, RFC 9325 |

## Information items (not scored)

These are reported for transparency and troubleshooting. They do not change the score.

| Item | What it shows | How this repository finds it | Standard |
| --- | --- | --- | --- |
| DS record at parent | Whether the parent zone holds a DS record. | DoH DS query. | RFC 4033, RFC 4034, RFC 4035 |
| RRSIG valid | Whether the SOA signature is present and unexpired. | DoH SOA query with DNSSEC records, then check the RRSIG expiry. | RFC 4033, RFC 4034, RFC 4035 |
| Signing algorithm | The DNSSEC algorithm of the key-signing key. | DoH DNSKEY query, read the algorithm of the key-signing key, the DNSKEY record with flags 257. | RFC 4033, RFC 4034, RFC 4035 |
| DKIM selector | A published DKIM key at a common selector. | DoH TXT queries at common selectors such as default and google. | RFC 6376 |

The Malaysian requirement that underpins the whole method is MCMC MTSFB TC G046:2024,
the Malaysian Communications and Multimedia Commission standard for IPv6 security.

## The scoring formula

Each part contributes its weight multiplied by the fraction of its checks that passed.
The score is the sum, rounded to a whole number:

```
score = round( web/web_max * 35 + dns/dns_max * 25 + email/email_max * 25 + ipv4/ipv4_max * 15 )
```

Here `web`, `dns`, `email` and `ipv4` are the numbers of passed checks, and
`web_max`, `dns_max`, `email_max` and `ipv4_max` are the numbers of checks that
were actually measured. When every check is measured those are 8, 5, 6 and 3, so
the formula reduces to web/8 * 35 + dns/5 * 25 + email/6 * 25 + ipv4/3 * 15.
Rounding is half away from zero, so 86.5 becomes 87.

### Worked example

Suppose a domain passes all 8 website checks, 4 of the 5 DNS checks, all 6 email
checks and all 3 IPv4 checks.

| Part | Passed / measured | Calculation | Points |
| --- | --- | --- | --- |
| Website | 8 / 8 | 8/8 x 35 | 35 |
| DNS and DNSSEC | 4 / 5 | 4/5 x 25 | 20 |
| Email | 6 / 6 | 6/6 x 25 | 25 |
| Existing IPv4 | 3 / 3 | 3/3 x 15 | 15 |
| **Total** | | | **95** |

The score is 95, which is the level "Compliant: fully ready".

## Compliance levels

| Score | Level |
| --- | --- |
| 90 to 100 | Compliant: fully ready |
| 60 to 89 | Partially compliant |
| 0 to 59 | Non-compliant: not ready |

## Not measured is not failed

A check that cannot be run from this computer is reported as NOT MEASURED, never as
failed, and it is removed from the denominator of its part. This keeps the score
honest about what was actually tested.

Three situations use this rule:

1. **No local IPv6.** The script first tests whether this computer has working
   outbound IPv6. If it does not, every check that needs an outbound IPv6 connection
   is NOT MEASURED and the score is marked PROVISIONAL. Set the environment variable
   `IPV6CHECK_FORCE_NO_V6=1` to simulate this for testing or a demonstration.

2. **SMTP over IPv6 cannot be measured.** If the connection to port 25 times out or
   is unreachable, the SMTP and STARTTLS checks are removed from the email
   denominator, so it drops from 6 to 4. A timeout may be caused by the local network
   filtering outbound port 25, so it is not counted against the domain. A refused
   connection is different: it proves the host was reached and declined, so it is a
   real failure and stays in the denominator.

3. **The overall time limit is reached.** The whole run has a hard budget of 60
   seconds. Any check that cannot finish within that budget is reported as NOT
   MEASURED with the reason "time limit reached", and it is removed from its part's
   denominator. The report says plainly that the time limit was reached. This is not
   a failure of the domain.

For example, if a domain passes the four other email checks and SMTP and STARTTLS
are not measurable, the email part is 4/4 x 25 = 25 points, not 4/6 x 25.

## The limits of an outside test

This repository measures a service from the outside, the same way a visitor would.
That has limits you should state when you report a result:

- **It sees the public path only.** It cannot see internal network design, internal
  services or configuration that is not exposed. A passing outside test does not
  prove the internal setup is correct.
- **It depends on the vantage point.** The result reflects the network the script
  runs from. A firewall or filtered port on that network can change the outcome.
  This is why SMTP timeouts are treated as not measured.
- **DNSSEC uses the resolver's verdict.** This repository reads the AD flag from a
  validating DoH resolver rather than running a full local validation. The check
  passes only when the answer has Status 0 and the AD flag set to true. This is a
  stand-in for the monitor's own validating resolver: it reports whether a public
  validating resolver accepted the answer, which is the practical signal a visitor
  receives, not a local cryptographic proof.
- **Reachability is not correctness.** A service can answer over IPv6 and still have
  application problems. These checks confirm transport and DNS readiness, not the
  behaviour of the application itself.
- **A single run is a snapshot.** DNS answers and network paths change. Treat a
  result as a measurement at a point in time, and repeat it if a decision depends on it.

## Standards reference

The standards behind the checks, as listed in section 6 of the MGv6C standard page:

- RFC 8200: the IPv6 protocol specification.
- RFC 6724: default address selection behaviour.
- RFC 8305: dual-stack connection behaviour, known as Happy Eyeballs.
- RFC 9114: HTTP/3.
- RFC 3596: AAAA records and reverse DNS for IPv6.
- RFC 10001: operating DNS where IPv4 and IPv6 are both in use.
- RFC 4033, RFC 4034 and RFC 4035: DNSSEC requirements, records and protocol.
- RFC 9364: DNSSEC as best current practice.
- RFC 9325: recommendations for the secure use of TLS.
- RFC 9846: the TLS 1.3 specification.
- RFC 5321: SMTP transport.
- RFC 3207: STARTTLS encryption for SMTP.
- RFC 7208: SPF.
- RFC 6376: DKIM.
- RFC 9989: DMARC.
- MCMC MTSFB TC G046:2024: Malaysian IPv6 security requirements.

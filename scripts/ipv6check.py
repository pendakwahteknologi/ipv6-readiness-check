#!/usr/bin/env python3
"""Check a domain's IPv6 readiness using the My6 IPv6 Readiness Criteria, version 1.0.

This is scenario A of the ipv6-readiness-check repository. It runs the same 22
scored checks as the National IPv6 Readiness Monitor at https://ipv6.my6.my,
from the computer it is run on, using only the Python standard library.

Usage:
    python3 scripts/ipv6check.py example.gov.my [--json] [--official]

Design notes:
  * DNS questions are answered with DNS over HTTPS (DoH) JSON, so no dig or
    other external tool is needed. Google Public DNS is tried first and
    Cloudflare is the fallback. DoH is forced to IPv4 so a broken local IPv6
    path cannot stall the lookups. The AD (Authenticated Data) flag from the
    validating resolver is used as a public-resolver stand-in for the monitor's
    own validating resolver; DNSSEC passes only when Status is 0 and AD is true.
  * Reachability checks open real sockets over IPv6 (AF_INET6) and IPv4. The
    HTTP and HTTPS checks follow up to three redirects over IPv6 only. The
    IPv6-only check uses a separate no-follow probe. The name-server query is
    sent over UDP first with TCP as a fallback. HTTP/3 is tested against every
    AAAA address.
  * The script first tests whether this computer has working outbound IPv6 by
    connecting to ipv6.my6.my on port 443 and to the DoH resolvers over IPv6.
    It never connects to port 53 of a public resolver. If there is no working
    outbound IPv6, every check that needs an outbound IPv6 connection is
    reported as "not measured", never as failed, and the score is marked
    PROVISIONAL. Set IPV6CHECK_FORCE_NO_V6=1 to simulate that case.
  * Independent checks run in threads. There is a hard overall time limit of
    60 seconds. Any check that cannot finish within the limit is reported as
    NOT MEASURED with the reason "time limit reached". No SIGALRM is used, so
    this works on Windows too.
  * Nothing is sent anywhere except the DoH lookups, the probes to the target
    and the optional official API call. Redirects on the DoH and official calls
    are refused unless they stay on the same host. No root privileges needed.

Exit code is 0 unless the arguments are wrong (then 2).
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import math
import os
import random
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONNECT_TIMEOUT = 8          # seconds per web / DNS connection
DOH_TIMEOUT = 8              # seconds per DoH request
SMTP_CONNECT_TIMEOUT = 5     # seconds per SMTP attempt, matching the monitor
SMTP_ATTEMPTS = 3            # retry only while the outcome is indeterminate
SMTP_RETRY_DELAY = 0.25      # seconds between SMTP attempts
MAX_WORKERS = 16
MAX_REDIRECTS = 3            # follow at most three redirects, as the monitor does
MAX_NS_HOSTS = 4             # cap the number of name servers tried
MAX_NS_ADDRS = 2             # cap the addresses tried per name server
TOTAL_TIME_LIMIT = 60        # hard wall-clock budget for the whole run, seconds
TIME_LIMIT_REASON = "time limit reached"
USER_AGENT = "ipv6-readiness-check/1.0 (My6 IPv6 Readiness Criteria 1.0; +https://ipv6.my6.my)"

DOH_ENDPOINTS = [
    ("https://dns.google/resolve", {}),
    ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
]

# Last-resort IPv4 addresses for the two DoH resolvers, used only when the local
# resolver cannot look up their names (some networks and servers block it). The
# connection still checks the certificate against the resolver's name.
DOH_FALLBACK_ADDRESSES = {
    "dns.google": ["8.8.8.8", "8.8.4.4"],
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
}

OFFICIAL_API = "https://ipv6.my6.my/api/v1/domains/{domain}"

REDIRECT_CODES = (301, 302, 303, 307, 308)
IPV6_ONLY_OK_CODES = (200, 301, 302, 303, 307, 308)
# A server that refuses HEAD with one of these is asked again with GET.
HEAD_REFUSED_CODES = (405, 501)

# DNS record type numbers.
RT_A = 1
RT_NS = 2
RT_SOA = 6
RT_PTR = 12
RT_TXT = 16
RT_AAAA = 28
RT_DS = 43
RT_RRSIG = 46
RT_DNSKEY = 48
RT_MX = 15

WEIGHTS = {"web": 35, "dns": 25, "email": 25, "ipv4": 15}
TOTALS = {"web": 8, "dns": 5, "email": 6, "ipv4": 3}
CATEGORY_TITLES = {
    "web": "Website",
    "dns": "DNS and DNSSEC",
    "email": "Email",
    "ipv4": "Existing IPv4 service",
}

# Common DKIM selectors to try, matching the monitor.
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"]

DNSSEC_ALGORITHMS = {
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}


# ---------------------------------------------------------------------------
# Scoring (pure functions, covered by tests/test_scoring.py)
# ---------------------------------------------------------------------------

def round_half_up(value):
    """Round to the nearest whole number, halves away from zero.

    This matches PHP's round() used by the monitor. Python's built-in round()
    uses banker's rounding, which would differ at exactly .5.
    """
    return int(math.floor(value + 0.5))


def compute_score(passed, measured):
    """Return the readiness score from per-category passed and measured counts.

    passed and measured are dicts keyed by category. "measured" is the number
    of scored checks that produced a PASS or FAIL; checks that were NOT
    MEASURED are excluded from the denominator. This is the "not measured is
    not failed" principle.

    When every check is measured the denominators are 8, 5, 6 and 3, so this
    reduces exactly to:
        round(web/8*35 + dns/5*25 + email/6*25 + ipv4/3*15)
    When SMTP and STARTTLS over IPv6 cannot be measured, the email denominator
    drops from 6 to 4, exactly as the monitor does.
    """
    total = 0.0
    for category, weight in WEIGHTS.items():
        denom = measured.get(category, 0)
        if denom > 0:
            total += weight * passed.get(category, 0) / denom
    return round_half_up(total)


def level_for(score):
    """Return the plain-language readiness level for a score."""
    if score >= 90:
        return "Fully ready"
    if score >= 60:
        return "Partly ready"
    return "Not ready"


def dnssec_validated(response):
    """True only when the DoH answer has Status 0 and the AD flag set to true.

    This is a public-resolver stand-in for the monitor's own validating
    resolver. A missing AD flag, a non-zero Status or an absent response all
    fail closed rather than being treated as unsigned.
    """
    if not response:
        return False
    return response.get("Status") == 0 and response.get("AD") is True


def http_pass_code(code):
    """The HTTP and HTTPS checks pass on any positive status code."""
    return code > 0


def ipv6_only_pass_code(code):
    """The IPv6-only check passes on these first-hop status codes."""
    return code in IPV6_ONLY_OK_CODES


# ---------------------------------------------------------------------------
# Overall time budget
# ---------------------------------------------------------------------------

class Budget:
    """A hard wall-clock budget shared across every stage of a run.

    Every blocking probe caps its timeout at the remaining budget and refuses
    to start once the budget is spent, so the whole run finishes within the
    limit without using SIGALRM (which is unavailable on Windows).
    """

    def __init__(self, limit=TOTAL_TIME_LIMIT, start=None):
        self.limit = limit
        self._start = time.monotonic() if start is None else start

    def remaining(self):
        return self.limit - (time.monotonic() - self._start)

    def expired(self):
        return self.remaining() <= 0

    def timeout(self, cap):
        """Return the smaller of cap and the remaining budget, never negative."""
        left = self.remaining()
        if left <= 0:
            return 0.0
        return min(cap, left)


# ---------------------------------------------------------------------------
# Check catalogue (labels and descriptions from the monitor's GuestCheck)
# ---------------------------------------------------------------------------

# Each entry: key, label, category, scored, description, fix (why it matters).
CHECKS = [
    # Website (8 scored, weight 35)
    ("has_aaaa_record", "AAAA record", "web", True,
     "The domain has at least one IPv6 address (AAAA DNS record).",
     "Without an AAAA record, visitors on IPv6 networks cannot find the server's address."),
    ("is_globally_routable", "Globally routable IPv6", "web", True,
     "The IPv6 addresses are publicly routable, not link-local, ULA, loopback or documentation ranges.",
     "A reserved or private IPv6 address cannot be reached by the public."),
    ("http_accessible_v6", "HTTP over IPv6", "web", True,
     "Website reachable on port 80 when connecting via IPv6.",
     "The web server does not answer on port 80 over IPv6, so plain HTTP fails for IPv6 visitors."),
    ("https_accessible_v6", "HTTPS over IPv6", "web", True,
     "Website reachable on port 443 when connecting via IPv6.",
     "The web server does not answer on port 443 over IPv6, so secure browsing fails for IPv6 visitors."),
    ("ipv6_only_reachable", "IPv6-only reachability", "web", True,
     "Website responds when connected exclusively over IPv6, with no IPv4 fallback.",
     "The site cannot be loaded when IPv4 is unavailable, so IPv6-only users are locked out."),
    ("tls_valid_v6", "TLS certificate valid (IPv6)", "web", True,
     "The TLS certificate is valid, not expired and matches the domain when connected via IPv6.",
     "The certificate presented over IPv6 is invalid, expired or does not match the name, so browsers will block the site."),
    ("is_dual_stack", "Dual-stack (IPv4 + IPv6)", "web", True,
     "The domain has both A and AAAA records for backwards compatibility during the transition.",
     "Publishing both A and AAAA records keeps the site reachable while IPv4 remains in use."),
    ("http3_supported", "HTTP/3 (QUIC)", "web", True,
     "Server advertises HTTP/3 support via the Alt-Svc: h3 header.",
     "Advertising HTTP/3 lets modern clients use a faster and more resilient transport."),
    # DNS and DNSSEC (5 scored, weight 25)
    ("ns_has_aaaa", "NS has AAAA record", "dns", True,
     "At least one authoritative name server has an IPv6 address (AAAA record).",
     "Name servers without IPv6 addresses cannot be reached by IPv6-only resolvers."),
    ("ns_reachable_v6", "NS reachable via IPv6", "dns", True,
     "Authoritative name server accepts TCP connections on port 53 over IPv6.",
     "Name servers that do not accept connections on port 53 over IPv6 leave the domain unresolvable for IPv6 clients."),
    ("ns_answers_v6", "NS answers queries via IPv6", "dns", True,
     "Name server actually resolves DNS queries when asked over IPv6, not just TCP open.",
     "A name server must actually answer queries over IPv6, not just accept the connection."),
    ("dnssec_enabled", "DNSSEC validated", "dns", True,
     "Full DNSSEC chain-of-trust validation passes, preventing DNS cache poisoning and spoofing.",
     "DNSSEC signatures let resolvers detect forged DNS answers; without them the zone can be spoofed."),
    ("has_ptr_record", "Reverse DNS (PTR)", "dns", True,
     "A PTR record exists in ip6.arpa for the IPv6 address, important for email delivery and diagnostics.",
     "A reverse DNS (PTR) record supports traceability and is checked by many mail servers."),
    # Email (6 scored, weight 25)
    ("mx_has_record", "MX record exists", "email", True,
     "The domain has at least one MX (Mail Exchange) DNS record pointing to a mail server.",
     "Without MX records, mail for the domain cannot be routed in."),
    ("mx_has_aaaa", "MX server has IPv6", "email", True,
     "The highest-priority MX server resolves to an IPv6 address (AAAA record).",
     "The mail server has no IPv6 address, so mail cannot be delivered over IPv6."),
    ("mx_smtp_v6", "SMTP reachable via IPv6", "email", True,
     "The MX server accepts SMTP connections (port 25) over IPv6 and responds with a 220 banner.",
     "The mail server does not accept SMTP connections over IPv6, so IPv6 mail delivery fails."),
    ("mx_starttls_v6", "STARTTLS over IPv6", "email", True,
     "The MX server supports STARTTLS encryption when connected over IPv6.",
     "Without STARTTLS over IPv6, mail transport cannot be encrypted on that path."),
    ("spf_present", "SPF record", "email", True,
     "A TXT record with v=spf1 exists, declaring which servers may send email for this domain.",
     "An SPF record tells receivers which servers may send mail for the domain, reducing spoofing."),
    ("dmarc_present", "DMARC record", "email", True,
     "A DMARC policy record exists at _dmarc.<domain>, enabling email authentication reporting.",
     "A DMARC policy tells receivers how to handle mail that fails authentication and where to report it."),
    # Existing IPv4 service (3 scored, weight 15)
    ("has_a_record", "A record", "ipv4", True,
     "The domain has at least one IPv4 address (A DNS record).",
     "An A record keeps the site reachable over IPv4 during the transition."),
    ("http_accessible_v4", "HTTP over IPv4", "ipv4", True,
     "Website reachable on port 80 when connecting via IPv4.",
     "The web server does not answer on port 80 over IPv4."),
    ("https_accessible_v4", "HTTPS over IPv4", "ipv4", True,
     "Website reachable on port 443 when connecting via IPv4.",
     "The web server does not answer on port 443 over IPv4."),
    # Information items (not scored)
    ("dnssec_ds_present", "DS record at parent", "dns", False,
     "Delegation Signer record exists in the parent zone.",
     ""),
    ("dnssec_rrsig_valid", "RRSIG valid", "dns", False,
     "RRSIG signatures are present and not expired.",
     ""),
    ("dnssec_algorithm", "Signing algorithm", "dns", False,
     "The cryptographic algorithm used for DNSSEC signing.",
     ""),
    ("dkim_found", "DKIM selector", "email", False,
     "A DKIM public key is published at a common selector, enabling email signature verification.",
     ""),
]

CHECK_BY_KEY = {c[0]: c for c in CHECKS}
# Keys that need an outbound IPv6 connection from this computer.
V6_CONNECTION_KEYS = {
    "http_accessible_v6", "https_accessible_v6", "ipv6_only_reachable",
    "tls_valid_v6", "http3_supported", "ns_reachable_v6", "ns_answers_v6",
    "mx_smtp_v6", "mx_starttls_v6",
}


# ---------------------------------------------------------------------------
# Redirect safety for the DoH and official calls
# ---------------------------------------------------------------------------

class SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow a redirect only when it stays on the same host and scheme.

    A cross-host redirect is refused, which urllib surfaces as an HTTPError.
    This keeps the DoH lookups and the official API call on their intended
    destinations.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener():
    return urllib.request.build_opener(SameHostRedirectHandler)


# Prefer IPv4 for the DoH and official lookups. Every target probe in this
# script connects to a literal address resolved through DoH, so the only name
# resolution that uses socket.getaddrinfo is the urllib traffic. Filtering it
# to IPv4 (with a fallback when no IPv4 answer exists) stops a broken local
# IPv6 path from stalling the lookups.
_ORIG_GETADDRINFO = socket.getaddrinfo
_V4_FILTER_INSTALLED = False


def install_ipv4_preference():
    global _V4_FILTER_INSTALLED
    if _V4_FILTER_INSTALLED:
        return

    def filtered(host, port, family=0, type=0, proto=0, flags=0):
        try:
            results = _ORIG_GETADDRINFO(host, port, family, type, proto, flags)
        except socket.gaierror:
            pinned = DOH_FALLBACK_ADDRESSES.get(str(host).lower())
            if not pinned:
                raise
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                    for ip in pinned]
        v4 = [r for r in results if r[0] == socket.AF_INET]
        return v4 if v4 else results

    socket.getaddrinfo = filtered
    _V4_FILTER_INSTALLED = True


# ---------------------------------------------------------------------------
# DNS over HTTPS resolver
# ---------------------------------------------------------------------------

class Resolver:
    """DoH JSON resolver with a small cache and a Google -> Cloudflare fallback."""

    def __init__(self, budget=None):
        self._cache = {}
        self._lock = threading.Lock()
        self.budget = budget if budget is not None else Budget()
        self._opener = _build_opener()

    def query(self, name, rtype, do=False):
        """Return the parsed DoH JSON dict, or None if both endpoints fail.

        do=True asks for a validated answer with signatures (RRSIG); it is used
        only for the DNSSEC check. Every other lookup sets cd=1 (checking
        disabled), because the monitor's own record lookups do not validate: a
        domain with a broken DNSSEC chain must still show its name servers, mail
        servers and addresses, and lose its point only on the DNSSEC check.
        """
        key = (name.lower(), rtype, do)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        result = self._fetch(name, rtype, do)
        with self._lock:
            self._cache[key] = result
        return result

    def _fetch(self, name, rtype, do):
        params = {"name": name, "type": str(rtype)}
        if do:
            params["do"] = "1"
        else:
            params["cd"] = "1"
        qs = urllib.parse.urlencode(params)
        for base, extra_headers in DOH_ENDPOINTS:
            if self.budget.expired():
                return None
            timeout = self.budget.timeout(DOH_TIMEOUT)
            if timeout <= 0:
                return None
            url = base + "?" + qs
            headers = {"User-Agent": USER_AGENT}
            headers.update(extra_headers)
            req = urllib.request.Request(url, headers=headers)
            try:
                with self._opener.open(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except Exception:
                continue
        return None


def answers_of(response, rtype):
    """Return the data strings of Answer records of the given type."""
    if not response:
        return []
    out = []
    for record in response.get("Answer", []) or []:
        if record.get("type") == rtype and "data" in record:
            out.append(record["data"])
    return out


def is_nxdomain(response):
    return bool(response) and response.get("Status") == 3


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def is_globally_routable(ipv6):
    """True if the IPv6 address is public unicast, matching the monitor.

    Excludes loopback (::1), unspecified (::), link-local (fe80::/10),
    unique local (fc00::/7), documentation (2001:db8::/32), multicast and
    IPv4-mapped addresses. The ipaddress module normalises the address first,
    so an expanded documentation form such as 2001:0db8::1 is still excluded.
    """
    try:
        addr = ipaddress.IPv6Address(ipv6)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_link_local:
        return False
    if addr.is_multicast:
        return False
    if addr.ipv4_mapped is not None:
        return False
    if addr in ipaddress.IPv6Network("fc00::/7"):  # unique-local
        return False
    if addr in ipaddress.IPv6Network("2001:db8::/32"):  # documentation
        return False
    return True


def ptr_name(ipv6):
    """Build the ip6.arpa reverse-DNS name for an IPv6 address."""
    packed = ipaddress.IPv6Address(ipv6).packed
    return ".".join(reversed(packed.hex())) + ".ip6.arpa"


def first_routable(addresses):
    for ip in addresses:
        if is_globally_routable(ip):
            return ip
    return addresses[0] if addresses else None


def routable_first(addresses):
    """Return the addresses with globally routable ones first, order preserved."""
    good = [ip for ip in addresses if is_globally_routable(ip)]
    rest = [ip for ip in addresses if not is_globally_routable(ip)]
    return good + rest


# ---------------------------------------------------------------------------
# Hand-built DNS packet (stdlib only) for the authoritative-server query
# ---------------------------------------------------------------------------

def encode_qname(name):
    """Encode a domain name as a DNS QNAME using IDNA A-labels.

    Each label is limited to 63 octets and the whole QNAME to 255 octets.
    Unicode labels are converted to their punycode A-label form first.
    """
    out = b""
    for label in name.rstrip(".").split("."):
        if any(ord(ch) > 127 for ch in label):
            label = label.encode("idna").decode("ascii")
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("DNS label exceeds 63 octets")
        out += bytes([len(raw)]) + raw
    out += b"\x00"
    if len(out) > 255:
        raise ValueError("DNS name exceeds 255 octets")
    return out


def build_dns_query(name, qtype=RT_A):
    """Build a recursive DNS query packet. Return (packet, transaction_id)."""
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = encode_qname(name) + struct.pack(">HH", qtype, 1)
    return header + question, tid


def _skip_name(packet, pos):
    """Skip a possibly-compressed DNS name, returning the position after it."""
    while pos < len(packet):
        length = packet[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return pos + 2
        pos += 1 + length
    return pos


def dns_response_summary(packet, expected_tid=None):
    """Return (rcode, answer_count, has_answer_data) from a DNS response.

    The transaction ID must match (when given) and the QR bit must be set,
    otherwise the packet is not a usable response and (None, 0, False) is
    returned. has_answer_data is True when any answer record carries non-empty
    RDATA, which is what `dig +short` would print.
    """
    if len(packet) < 12:
        return None, 0, False
    tid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", packet[:12])
    if expected_tid is not None and tid != expected_tid:
        return None, 0, False
    if not flags & 0x8000:  # QR bit must be 1 for a response
        return None, 0, False
    rcode = flags & 0x0F
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(packet, pos)
        pos += 4
        if pos > len(packet):
            return rcode, ancount, False
    has_data = False
    for _ in range(ancount):
        pos = _skip_name(packet, pos)
        if pos + 10 > len(packet):
            break
        _, _, _, rdlength = struct.unpack(">HHIH", packet[pos:pos + 10])
        pos += 10
        if rdlength > 0:
            has_data = True
        pos += rdlength
    return rcode, ancount, has_data


# ---------------------------------------------------------------------------
# Socket probes
# ---------------------------------------------------------------------------

def _classify_oserror(exc):
    text = str(exc).lower()
    winerror = getattr(exc, "winerror", None)
    if winerror in (10060, 10035) or "wsaetimedout" in text:
        return "timeout"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if winerror == 10061 or "refused" in text:
        return "refused"
    return "unreachable"


def tcp_connect(ip, port, family, timeout=CONNECT_TIMEOUT):
    """Open a TCP connection. Return (socket, None) or (None, outcome).

    outcome is one of: refused, timeout, unreachable, error. The socket is
    always closed on failure so handles are not leaked.
    """
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except Exception:
        return None, "error"
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock, None
    except ConnectionRefusedError:
        outcome = "refused"
    except (socket.timeout, TimeoutError):
        outcome = "timeout"
    except OSError as exc:
        outcome = _classify_oserror(exc)
    except Exception:
        outcome = "error"
    try:
        sock.close()
    except Exception:
        pass
    return None, outcome


def http_head(domain, ip, port, family, verify_tls, budget=None, path="/",
              method="HEAD"):
    """Send a HEAD request (or GET, reading the headers only) to ip:port with SNI=domain. Return a result dict.

    For port 443 the connection is wrapped in TLS. verify_tls controls whether
    the certificate is validated; SNI is always sent. No redirects are followed
    here. TLS validity is decided by the handshake alone, not by the HTTP code.
    """
    result = {"code": 0, "latency_ms": None, "headers": {},
              "tls_valid": None, "cert_expires": None, "cert_issuer": None,
              "error": None}
    timeout = budget.timeout(CONNECT_TIMEOUT) if budget else CONNECT_TIMEOUT
    if timeout <= 0:
        result["time_limit"] = True
        return result
    sock = None
    try:
        started = time.monotonic()
        sock, outcome = tcp_connect(ip, port, family, timeout)
        if sock is None:
            result["error"] = outcome
            return result
        if port == 443:
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except Exception:
                pass
            sock = ctx.wrap_socket(sock, server_hostname=domain)
            result["tls_valid"] = True
            try:
                cert = sock.getpeercert()
                if cert:
                    not_after = cert.get("notAfter")
                    if not_after:
                        result["cert_expires"] = not_after
                    issuer = cert.get("issuer")
                    if issuer:
                        for rdn in issuer:
                            for key, value in rdn:
                                if key == "commonName":
                                    result["cert_issuer"] = value
            except Exception:
                pass
        request = (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "User-Agent: {ua}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).format(method=method, path=path, host=domain, ua=USER_AGENT)
        sock.sendall(request.encode("ascii", "replace"))
        sock.settimeout(timeout)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        lines = head.split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split()
            if len(parts) >= 2 and parts[1].isdigit():
                result["code"] = int(parts[1])
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                result["headers"][key.strip().lower()] = value.strip()
        return result
    except ssl.SSLCertVerificationError as exc:
        result["tls_valid"] = False
        result["error"] = "certificate: " + str(exc)
        return result
    except Exception as exc:
        result["error"] = str(exc) or type(exc).__name__
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def ipv6_only_probe(domain, ip, budget=None):
    """No-follow HTTPS probe over IPv6 for the IPv6-only check.

    HEAD first. If the server does not allow HEAD (405 or 501) the same request
    is sent once more as GET, and only the response headers are read.
    """
    result = http_head(domain, ip, 443, socket.AF_INET6, False, budget)
    if result["code"] in HEAD_REFUSED_CODES:
        result = http_head(domain, ip, 443, socket.AF_INET6, False, budget,
                           method="GET")
    return result


def http_with_redirects(domain, aaaa, port, resolver, budget, verify_tls=False):
    """HEAD the domain over IPv6, following up to three redirects over IPv6 only.

    Each redirect Location is re-resolved to an AAAA address through DoH. The
    code returned is the last HTTP status actually received, as with the
    monitor's curl: if a later hop cannot be followed (for example the redirect
    goes to a name with no IPv6 address), the check still passes, because the
    server did answer over IPv6. Only a connection that never gets any HTTP
    answer is a failure.
    """
    result = {"code": 0, "latency_ms": None, "headers": {},
              "tls_valid": None, "cert_expires": None, "cert_issuer": None,
              "error": None, "redirects": 0}
    ip = first_routable(aaaa)
    host = domain
    scheme = "https" if port == 443 else "http"
    path = "/"
    for hop in range(MAX_REDIRECTS + 1):
        if budget.expired():
            result["time_limit"] = True
            return result
        res = http_head(host, ip, port, socket.AF_INET6, verify_tls, budget, path)
        for field in ("latency_ms", "headers", "tls_valid", "cert_expires", "cert_issuer"):
            result[field] = res[field]
        if res.get("time_limit"):
            result["time_limit"] = True
            return result
        if res["code"] == 0:
            result["error"] = res["error"]
            return result
        result["code"] = res["code"]
        if res["code"] not in REDIRECT_CODES:
            return result
        if hop >= MAX_REDIRECTS:
            result["error"] = "too many redirects"
            return result
        location = res["headers"].get("location")
        if not location:
            return result
        base = "{}://{}{}".format(scheme, host, "/")
        parsed = urllib.parse.urlsplit(urllib.parse.urljoin(base, location))
        if parsed.scheme not in ("http", "https"):
            result["error"] = "redirect to an unsupported scheme"
            return result
        new_host = parsed.hostname
        new_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        new_path = parsed.path or "/"
        if parsed.query:
            new_path += "?" + parsed.query
        if new_host != host or new_port != port:
            if budget.expired():
                result["time_limit"] = True
                return result
            ips = answers_of(resolver.query(new_host, RT_AAAA), RT_AAAA)
            if not ips:
                result["error"] = "redirect target has no IPv6 address"
                return result
            ip = first_routable(ips)
            host = new_host
            port = new_port
            scheme = parsed.scheme
        result["redirects"] += 1
        path = new_path
    return result


def probe_ns_query(domain, ns_ipv6, budget=None):
    """Send a real DNS A query to the authoritative server over IPv6.

    UDP is tried first (matching `dig -6`), with TCP as a fallback. The answer
    passes when it carries non-empty answer data, the way `dig +short` would
    print it. The packet is built by hand so no external tool is required.
    """
    try:
        query, tid = build_dns_query(domain, RT_A)
    except Exception:
        return False
    if budget and budget.expired():
        return False
    if _ns_query_udp(ns_ipv6, query, tid, budget):
        return True
    if budget and budget.expired():
        return False
    return _ns_query_tcp(ns_ipv6, query, tid, budget)


def _ns_query_udp(ns_ipv6, query, tid, budget):
    timeout = budget.timeout(CONNECT_TIMEOUT) if budget else CONNECT_TIMEOUT
    if timeout <= 0:
        return False
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except Exception:
        return False
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (ns_ipv6, 53))
        data, _ = sock.recvfrom(4096)
        _, _, has_data = dns_response_summary(data, tid)
        return has_data
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _ns_query_tcp(ns_ipv6, query, tid, budget):
    timeout = budget.timeout(CONNECT_TIMEOUT) if budget else CONNECT_TIMEOUT
    if timeout <= 0:
        return False
    sock, outcome = tcp_connect(ns_ipv6, 53, socket.AF_INET6, timeout)
    if sock is None:
        return False
    try:
        sock.sendall(struct.pack(">H", len(query)) + query)
        sock.settimeout(timeout)
        length_bytes = _recv_exact(sock, 2)
        if not length_bytes:
            return False
        length = struct.unpack(">H", length_bytes)[0]
        response = _recv_exact(sock, length)
        if not response:
            return False
        _, _, has_data = dns_response_summary(response, tid)
        return has_data
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def probe_smtp(domain, mx_ipv6, budget=None):
    """Probe SMTP and STARTTLS over IPv6 on port 25, with limited retries.

    Returns a dict with smtp and starttls verdicts, or None if the time budget
    ran out. Each verdict has ok, outcome and reachable. A refusal is reachable
    (a real failure); a timeout or unreachable is not reachable (not measurable
    from this vantage point). Three attempts at five seconds, 250ms apart,
    match the monitor.
    """
    smtp = starttls = None
    for attempt in range(SMTP_ATTEMPTS):
        if budget and budget.expired():
            return None
        timeout = budget.timeout(SMTP_CONNECT_TIMEOUT) if budget else SMTP_CONNECT_TIMEOUT
        if timeout <= 0:
            return None
        sock, outcome = tcp_connect(mx_ipv6, 25, socket.AF_INET6, timeout)
        if sock is None:
            reachable = outcome == "refused"
            smtp = starttls = {"ok": False, "outcome": outcome,
                               "reachable": reachable}
            if reachable:
                break  # a refusal is definitive
            if attempt < SMTP_ATTEMPTS - 1:
                time.sleep(SMTP_RETRY_DELAY)
            continue
        try:
            sock.settimeout(timeout)
            banner = _read_line(sock)
            if not banner or not banner.startswith("220"):
                smtp = starttls = {"ok": False, "outcome": "no_banner",
                                   "reachable": True}
                break
            smtp = {"ok": True, "outcome": "ok", "reachable": True,
                    "banner": banner}
            has_starttls = _read_starttls(sock, timeout)
            starttls = {"ok": has_starttls,
                        "outcome": "ok" if has_starttls else "no_starttls",
                        "reachable": True}
            break
        except Exception:
            smtp = starttls = {"ok": False, "outcome": "timeout",
                               "reachable": False}
            if attempt < SMTP_ATTEMPTS - 1:
                time.sleep(SMTP_RETRY_DELAY)
            continue
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return {"smtp": smtp, "starttls": starttls}


def _read_line(sock):
    data = b""
    while not data.endswith(b"\n") and len(data) < 1024:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("iso-8859-1", "replace").strip()


def _read_starttls(sock, timeout=CONNECT_TIMEOUT):
    try:
        sock.sendall(b"EHLO ipv6readiness.local\r\n")
    except Exception:
        return False
    has_starttls = False
    deadline = time.monotonic() + timeout
    buffer = b""
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(1024)
        except Exception:
            break
        if not chunk:
            break
        buffer += chunk
        text = buffer.decode("iso-8859-1", "replace")
        if "STARTTLS" in text.upper():
            has_starttls = True
        if re.search(r"^250 ", text, re.MULTILINE):
            break
        if len(buffer) > 8192:
            break
    try:
        sock.sendall(b"QUIT\r\n")
    except Exception:
        pass
    return has_starttls


# ---------------------------------------------------------------------------
# IPv6 capability test
# ---------------------------------------------------------------------------

def test_ipv6_capability(resolver, budget):
    """Return True if this computer has working outbound IPv6.

    Connects over IPv6 to ipv6.my6.my on port 443 and to the DoH resolvers on
    port 443. It never connects to port 53 of a public resolver. Any success
    means IPv6 works. IPV6CHECK_FORCE_NO_V6=1 short-circuits this to False for
    testing and demos.
    """
    if os.environ.get("IPV6CHECK_FORCE_NO_V6") == "1":
        return False

    targets = [("ipv6.my6.my", 443)]
    for base, _ in DOH_ENDPOINTS:
        host = urllib.parse.urlsplit(base).hostname
        if host:
            targets.append((host, 443))

    def try_target(target):
        host, port = target
        if budget.expired():
            return False
        response = resolver.query(host, RT_AAAA)
        for ip in answers_of(response, RT_AAAA):
            if budget.expired():
                return False
            sock, outcome = tcp_connect(ip, port, socket.AF_INET6,
                                        budget.timeout(CONNECT_TIMEOUT))
            if sock is not None:
                sock.close()
                return True
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
        results = list(pool.map(try_target, targets))
    return any(results)


# ---------------------------------------------------------------------------
# Official score
# ---------------------------------------------------------------------------

# Backward compatibility: the API keeps an old level field under this name. It
# is read only as a fallback when the new readiness object is absent, and this
# is the only place the old field name appears in the repository.
LEGACY_LEVEL_FIELD = "mgv6c"


def official_level(data):
    """Return the readiness level from an official API response.

    The new readiness object carries the level directly, so readiness.level is
    preferred. When it is absent the script falls back to the API's old field
    and maps its value to the current level names.
    """
    readiness = data.get("readiness") or {}
    level = readiness.get("level")
    if level:
        return level
    legacy_levels = {
        "Compliant": "Fully ready",
        "Partially Compliant": "Partly ready",
        "Non-Compliant": "Not ready",
    }
    return legacy_levels.get(data.get(LEGACY_LEVEL_FIELD))


def fetch_official(domain, budget=None):
    """Fetch the official monitor score. Return a dict or a polite error dict."""
    url = OFFICIAL_API.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    timeout = budget.timeout(DOH_TIMEOUT) if budget else DOH_TIMEOUT
    opener = _build_opener()
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {
            "available": True,
            "score": data.get("score"),
            "level": official_level(data),
            "status_label": data.get("status_label"),
            "checked_at": data.get("checked_at"),
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"available": False,
                    "reason": "This domain is not monitored by ipv6.my6.my, so no official score is available."}
        return {"available": False,
                "reason": "The official API returned HTTP {}.".format(exc.code)}
    except Exception as exc:
        return {"available": False,
                "reason": "Could not reach the official API ({}).".format(type(exc).__name__)}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class CheckAbort(Exception):
    """Raised when the run must stop with a polite message instead of a score."""


def run_checks(domain, resolver, has_v6, budget=None):
    """Run all checks and return a list of per-check result dicts."""
    if budget is None:
        budget = Budget()
    results = {}

    def put(key, status, detail=""):
        results[key] = {"status": status, "detail": detail}

    def put_dns(key, ok, pass_detail, fail_detail, *sources):
        # A DNS-only check whose source lookup was cut short by the time limit
        # is not measured, not failed.
        if budget.expired() and any(s is None for s in sources):
            put(key, "NOT MEASURED", TIME_LIMIT_REASON)
        else:
            put(key, "PASS" if ok else "FAIL", pass_detail if ok else fail_detail)

    # ---- Stage 1: independent DNS lookups, in parallel ----
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        f_aaaa = pool.submit(resolver.query, domain, RT_AAAA)
        f_a = pool.submit(resolver.query, domain, RT_A)
        f_ns = pool.submit(resolver.query, domain, RT_NS)
        f_mx = pool.submit(resolver.query, domain, RT_MX)
        f_txt = pool.submit(resolver.query, domain, RT_TXT)
        f_dmarc = pool.submit(resolver.query, "_dmarc." + domain, RT_TXT)
        f_soa = pool.submit(resolver.query, domain, RT_SOA, True)
        f_ds = pool.submit(resolver.query, domain, RT_DS)
        f_dnskey = pool.submit(resolver.query, domain, RT_DNSKEY)

    aaaa_resp = f_aaaa.result()
    a_resp = f_a.result()
    ns_resp = f_ns.result()
    mx_resp = f_mx.result()
    txt_resp = f_txt.result()
    dmarc_resp = f_dmarc.result()
    soa_resp = f_soa.result()
    ds_resp = f_ds.result()
    dnskey_resp = f_dnskey.result()

    # Detect a non-existent domain early (NXDOMAIN on both A and AAAA).
    if is_nxdomain(a_resp) and is_nxdomain(aaaa_resp):
        raise CheckAbort("No DNS records were found for '{}'. Please check the "
                         "domain name and try again.".format(domain))
    # A total DoH outage is not an empty zone: stop politely instead of scoring
    # a fictional set of empty records.
    if a_resp is None and aaaa_resp is None:
        raise CheckAbort("The DNS lookups for '{}' could not be completed. "
                         "Please check your connection and try again.".format(domain))

    aaaa = answers_of(aaaa_resp, RT_AAAA)
    a_records = answers_of(a_resp, RT_A)
    ns_hosts = [d.rstrip(".") for d in answers_of(ns_resp, RT_NS)]
    mx_records = _parse_mx(mx_resp)

    # www fallback for A / AAAA / NS, matching the monitor.
    if not aaaa and not domain.startswith("www."):
        aaaa = answers_of(resolver.query("www." + domain, RT_AAAA), RT_AAAA)
    if not a_records and not domain.startswith("www."):
        a_records = answers_of(resolver.query("www." + domain, RT_A), RT_A)
    if not ns_hosts and not domain.startswith("www."):
        ns_hosts = [d.rstrip(".") for d in
                    answers_of(resolver.query("www." + domain, RT_NS), RT_NS)]

    primary_v6 = first_routable(aaaa)
    primary_v4 = a_records[0] if a_records else None

    # ---- Stage 2: everything that depends on stage 1, in parallel ----
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        # Web over IPv6 (only if we have a target address and local IPv6).
        if primary_v6 and has_v6:
            futures["http_v6"] = pool.submit(
                http_with_redirects, domain, aaaa, 80, resolver, budget, False)
            futures["https_v6"] = pool.submit(
                http_with_redirects, domain, aaaa, 443, resolver, budget, False)
            # A dedicated no-follow HTTPS probe for the IPv6-only check.
            futures["ipv6_only"] = pool.submit(
                ipv6_only_probe, domain, primary_v6, budget)
            # A validated handshake for the TLS check.
            futures["tls_v6"] = pool.submit(
                http_head, domain, primary_v6, 443, socket.AF_INET6, True, budget)
            # HTTP/3 across every AAAA address.
            futures["http3"] = pool.submit(_http3_task, domain, aaaa, budget)
        # Web over IPv4.
        if primary_v4:
            futures["http_v4"] = pool.submit(
                http_head, domain, primary_v4, 80, socket.AF_INET, False, budget)
            futures["https_v4"] = pool.submit(
                http_head, domain, primary_v4, 443, socket.AF_INET, False, budget)
        # DNS name-server task (AAAA -> TCP 53 -> real query), sequential inside.
        futures["ns"] = pool.submit(_ns_task, domain, ns_hosts, resolver, has_v6, budget)
        # Email task (MX AAAA -> SMTP), sequential inside.
        futures["email"] = pool.submit(_email_task, mx_records, resolver, has_v6, budget)
        # PTR for the primary IPv6 address.
        if primary_v6:
            futures["ptr"] = pool.submit(resolver.query, ptr_name(primary_v6), RT_PTR)
        # DKIM selectors, queried in parallel.
        futures["dkim"] = pool.submit(_dkim_task, domain, resolver, budget)

    def fres(key):
        fut = futures.get(key)
        if fut is None:
            return None
        try:
            return fut.result()
        except Exception:
            return None

    # ---- Assemble website checks ----
    put_dns("has_aaaa_record", bool(aaaa),
            ", ".join(aaaa) if aaaa else "", "No AAAA record found in DNS.", aaaa_resp)
    if aaaa:
        routable = [ip for ip in aaaa if is_globally_routable(ip)]
        put("is_globally_routable", "PASS" if routable else "FAIL",
            "All addresses are globally routable." if routable
            else "IPv6 address is not globally routable.")
    else:
        put_dns("is_globally_routable", False, "", "No IPv6 address to classify.", aaaa_resp)

    _assemble_web_v6(results, put, futures, aaaa, primary_v6, has_v6)

    dual = bool(a_records and aaaa)
    put_dns("is_dual_stack", dual,
            "Domain has both A and AAAA records.",
            "Domain is IPv6-only or IPv4-only.", a_resp, aaaa_resp)

    # ---- Assemble DNS checks ----
    ns_result = fres("ns") or {"has_aaaa": False, "reachable": False, "answers": False}
    put_dns("ns_has_aaaa", bool(ns_result["has_aaaa"]),
            "Name server has an IPv6 address.",
            "No name server has an AAAA record.", ns_resp)
    _assemble_v6_dep(results, put, "ns_reachable_v6", ns_result["reachable"],
                     ns_result["has_aaaa"], has_v6,
                     "Name server is reachable via IPv6 on port 53.",
                     "No name server is reachable over IPv6.",
                     ns_result.get("reachable_time_limit", False))
    _assemble_v6_dep(results, put, "ns_answers_v6", ns_result["answers"],
                     ns_result["has_aaaa"], has_v6,
                     "DNS queries answered over IPv6.",
                     "Name server does not answer queries over IPv6.",
                     ns_result.get("answers_time_limit", False))

    # DNSSEC validated: Status 0 and the AD flag from the validating resolver.
    if soa_resp is None and budget.expired():
        put("dnssec_enabled", "NOT MEASURED", TIME_LIMIT_REASON)
    else:
        ad = dnssec_validated(soa_resp)
        put("dnssec_enabled", "PASS" if ad else "FAIL",
            "DNSSEC fully validated (AD flag set)." if ad
            else "DNSSEC validation failed or the zone is unsigned.")

    # PTR.
    if primary_v6:
        ptr_resp = fres("ptr")
        ptr_data = answers_of(ptr_resp, RT_PTR)
        put_dns("has_ptr_record", bool(ptr_data),
                "PTR record found: " + ptr_data[0] if ptr_data else "",
                "No PTR record found in ip6.arpa.", ptr_resp)
    else:
        put("has_ptr_record", "FAIL", "No IPv6 address to look up in reverse.")

    # ---- Assemble email checks ----
    email_result = fres("email") or {"has_aaaa": False, "smtp": None, "starttls": None}
    put_dns("mx_has_record", bool(mx_records),
            "MX record found: " + mx_records[0]["host"] if mx_records else "",
            "No MX record found in DNS.", mx_resp)
    put_dns("mx_has_aaaa", bool(email_result["has_aaaa"]),
            "MX server has an AAAA record.",
            "MX server has no IPv6 address.", mx_resp)
    _assemble_smtp(results, put, email_result, has_v6)

    # SPF and DMARC from TXT records.
    spf = any(d.strip().lower().startswith("v=spf1")
              for d in _txt_strings(txt_resp))
    put_dns("spf_present", spf, "SPF record found.", "No SPF record found.", txt_resp)
    dmarc = any(d.strip().lower().startswith("v=dmarc1")
                for d in _txt_strings(dmarc_resp))
    put_dns("dmarc_present", dmarc, "DMARC record found.", "No DMARC record found.", dmarc_resp)

    # ---- Assemble IPv4 baseline ----
    put_dns("has_a_record", bool(a_records),
            ", ".join(a_records) if a_records else "", "No A record found in DNS.", a_resp)
    _assemble_v4(results, put, futures, "http_accessible_v4", "http_v4", primary_v4, 80)
    _assemble_v4(results, put, futures, "https_accessible_v4", "https_v4", primary_v4, 443)

    # ---- Information items (not scored) ----
    ds_data = answers_of(ds_resp, RT_DS)
    put("dnssec_ds_present", "INFO",
        "DS record found at parent zone." if ds_data else "No DS record at parent.")
    rrsig_ok, rrsig_detail = _rrsig_status(soa_resp)
    put("dnssec_rrsig_valid", "INFO", rrsig_detail)
    algo = _dnssec_algorithm(dnskey_resp)
    put("dnssec_algorithm", "INFO", algo or "No DNSKEY record found.")
    dkim_selector = fres("dkim")
    put("dkim_found", "INFO",
        "DKIM selector found: " + dkim_selector + "._domainkey" if dkim_selector
        else "No common DKIM selector found.")

    # Return in catalogue order. Any scored check still missing at the deadline
    # is reported as not measured with the time-limit reason.
    ordered = []
    for key, label, category, scored, description, fix in CHECKS:
        entry = results.get(key)
        if entry is None:
            entry = {"status": "NOT MEASURED",
                     "detail": TIME_LIMIT_REASON if budget.expired() else ""}
        ordered.append({
            "key": key, "label": label, "category": category,
            "scored": scored, "description": description, "fix": fix,
            "status": entry["status"], "detail": entry["detail"],
        })
    return ordered


def _assemble_web_v6(results, put, futures, aaaa, primary_v6, has_v6):
    """Fill the five IPv6 web connection checks with the right status."""
    def fres(key):
        fut = futures.get(key)
        if fut is None:
            return None
        try:
            return fut.result()
        except Exception:
            return None

    def web_status(key, fut_key, ok_fn, pass_detail, fail_detail):
        if not aaaa:
            put(key, "FAIL", "No IPv6 address published, so this cannot work.")
            return
        if not has_v6:
            put(key, "NOT MEASURED", "Not measured from this computer (no outbound IPv6).")
            return
        res = fres(fut_key)
        if res is None or res.get("time_limit"):
            put(key, "NOT MEASURED", TIME_LIMIT_REASON)
            return
        ok = ok_fn(res)
        put(key, "PASS" if ok else "FAIL", pass_detail(res) if ok else fail_detail)

    web_status("http_accessible_v6", "http_v6",
               lambda r: http_pass_code(r["code"]),
               lambda r: "HTTP (port 80) responds over IPv6 ({} ms).".format(r["latency_ms"]),
               "HTTP is not accessible over IPv6.")
    web_status("https_accessible_v6", "https_v6",
               lambda r: http_pass_code(r["code"]),
               lambda r: "HTTPS (port 443) responds over IPv6 ({} ms).".format(r["latency_ms"]),
               "HTTPS is not accessible over IPv6.")
    web_status("ipv6_only_reachable", "ipv6_only",
               lambda r: ipv6_only_pass_code(r["code"]),
               lambda r: "Site is fully reachable via IPv6-only (HTTP {}).".format(r["code"]),
               "Site is not reachable when limited to IPv6-only.")

    # TLS validity is decided by the validated handshake alone.
    if not aaaa:
        put("tls_valid_v6", "FAIL", "No IPv6 address published, so this cannot work.")
    elif not has_v6:
        put("tls_valid_v6", "NOT MEASURED", "Not measured from this computer (no outbound IPv6).")
    else:
        res = fres("tls_v6")
        if res is None or res.get("time_limit"):
            put("tls_valid_v6", "NOT MEASURED", TIME_LIMIT_REASON)
        elif res["tls_valid"]:
            detail = "Certificate valid"
            if res["cert_issuer"]:
                detail += ", issued by " + res["cert_issuer"]
            if res["cert_expires"]:
                detail += ", expires " + res["cert_expires"]
            put("tls_valid_v6", "PASS", detail + ".")
        else:
            put("tls_valid_v6", "FAIL",
                "TLS certificate is invalid, expired or hostname mismatch over IPv6.")

    # HTTP/3 from the Alt-Svc header across every AAAA address.
    if not aaaa:
        put("http3_supported", "FAIL", "No IPv6 address published, so this cannot work.")
    elif not has_v6:
        put("http3_supported", "NOT MEASURED", "Not measured from this computer (no outbound IPv6).")
    else:
        res = fres("http3")
        if res is None or res.get("time_limit"):
            put("http3_supported", "NOT MEASURED", TIME_LIMIT_REASON)
        else:
            ok = res.get("ok", False)
            put("http3_supported", "PASS" if ok else "FAIL",
                "Alt-Svc: h3 header detected." if ok else "No HTTP/3 support detected.")


def _assemble_v6_dep(results, put, key, measured_ok, prerequisite, has_v6,
                     pass_detail, fail_detail, time_limit=False):
    """Assemble a check that depends on a prerequisite and on local IPv6."""
    if not prerequisite:
        put(key, "FAIL", "No IPv6 address published, so this cannot work.")
    elif not has_v6:
        put(key, "NOT MEASURED", "Not measured from this computer (no outbound IPv6).")
    elif time_limit and not measured_ok:
        put(key, "NOT MEASURED", TIME_LIMIT_REASON)
    else:
        put(key, "PASS" if measured_ok else "FAIL",
            pass_detail if measured_ok else fail_detail)


def _assemble_smtp(results, put, email_result, has_v6):
    """Assemble SMTP and STARTTLS, applying the not-measured denominator rule."""
    for key, verdict_key, label in (
        ("mx_smtp_v6", "smtp", "SMTP"),
        ("mx_starttls_v6", "starttls", "STARTTLS"),
    ):
        if not email_result["has_aaaa"]:
            put(key, "FAIL", "Mail server has no IPv6 address, so this cannot work.")
            continue
        if not has_v6:
            put(key, "NOT MEASURED", "Not measured from this computer (no outbound IPv6).")
            continue
        verdict = email_result.get(verdict_key) or {}
        if not verdict:
            put(key, "NOT MEASURED", TIME_LIMIT_REASON)
        elif not verdict.get("reachable", False):
            # Timeout or unreachable: not measurable, excluded from the denominator.
            put(key, "NOT MEASURED",
                "{} over IPv6 not measurable ({}); excluded from scoring.".format(
                    label, verdict.get("outcome", "timeout")))
        elif verdict.get("ok"):
            put(key, "PASS", "{} over IPv6 works.".format(label))
        else:
            put(key, "FAIL", "{} over IPv6 failed ({}).".format(
                label, verdict.get("outcome", "failed")))


def _assemble_v4(results, put, futures, key, fut_key, primary_v4, port):
    if not primary_v4:
        put(key, "FAIL", "No IPv4 address published.")
        return
    fut = futures.get(fut_key)
    res = None
    if fut is not None:
        try:
            res = fut.result()
        except Exception:
            res = None
    if res is None or res.get("time_limit"):
        put(key, "NOT MEASURED", TIME_LIMIT_REASON)
        return
    ok = res["code"] > 0
    put(key, "PASS" if ok else "FAIL",
        "{} (port {}) responds over IPv4 ({} ms).".format(
            "HTTPS" if port == 443 else "HTTP", port, res["latency_ms"]) if ok
        else "{} is not accessible over IPv4.".format("HTTPS" if port == 443 else "HTTP"))


def _ns_task(domain, ns_hosts, resolver, has_v6, budget):
    """Resolve NS AAAA, test TCP 53 reachability and a real query over IPv6."""
    has_aaaa = False
    reachable = False
    answers = False
    target_ip = None
    reachable_tl = False
    answers_tl = False
    for host in ns_hosts[:MAX_NS_HOSTS]:
        if budget.expired():
            break
        ips = answers_of(resolver.query(host, RT_AAAA), RT_AAAA)
        if ips:
            has_aaaa = True
            if has_v6 and target_ip is None:
                for ip in ips[:MAX_NS_ADDRS]:
                    if budget.expired():
                        reachable_tl = True
                        break
                    sock, outcome = tcp_connect(ip, 53, socket.AF_INET6,
                                                budget.timeout(CONNECT_TIMEOUT))
                    if sock is not None:
                        sock.close()
                        reachable = True
                        target_ip = ip
                        break
        if target_ip:
            break
    if has_v6 and target_ip is None and not reachable and budget.expired():
        reachable_tl = True
    if target_ip and has_v6:
        if budget.expired():
            answers_tl = True
        else:
            answers = probe_ns_query(domain, target_ip, budget)
    return {"has_aaaa": has_aaaa, "reachable": reachable, "answers": answers,
            "reachable_time_limit": reachable_tl, "answers_time_limit": answers_tl}


def _email_task(mx_records, resolver, has_v6, budget):
    """Resolve the primary MX AAAA and probe SMTP/STARTTLS over IPv6."""
    has_aaaa = False
    smtp = starttls = None
    if mx_records:
        primary_host = mx_records[0]["host"]
        if budget.expired():
            return {"has_aaaa": False, "smtp": None, "starttls": None}
        ips = answers_of(resolver.query(primary_host, RT_AAAA), RT_AAAA)
        if ips:
            has_aaaa = True
            if has_v6:
                mail = probe_smtp(primary_host, ips[0], budget)
                if mail is not None:
                    smtp = mail["smtp"]
                    starttls = mail["starttls"]
    return {"has_aaaa": has_aaaa, "smtp": smtp, "starttls": starttls}


def _http3_task(domain, aaaa, budget):
    """Walk every AAAA address (routable first) until one advertises h3."""
    for ip in routable_first(aaaa):
        if budget.expired():
            return {"ok": False, "time_limit": True}
        res = http_head(domain, ip, 443, socket.AF_INET6, False, budget)
        if res.get("time_limit"):
            return {"ok": False, "time_limit": True}
        alt_svc = res["headers"].get("alt-svc", "")
        if "h3" in alt_svc.lower():
            return {"ok": True}
    return {"ok": False}


def _dkim_task(domain, resolver, budget):
    """Query the common DKIM selectors in parallel and return the first found."""
    if budget.expired():
        return None
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DKIM_SELECTORS)) as pool:
        for selector in DKIM_SELECTORS:
            futures[selector] = pool.submit(
                resolver.query, selector + "._domainkey." + domain, RT_TXT)
    for selector in DKIM_SELECTORS:
        try:
            response = futures[selector].result()
        except Exception:
            response = None
        if answers_of(response, RT_TXT):
            return selector
    return None


def _parse_mx(response):
    records = []
    for data in answers_of(response, RT_MX):
        parts = data.split()
        if len(parts) >= 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 99
            records.append({"host": parts[1].rstrip("."), "priority": priority})
    records.sort(key=lambda r: r["priority"])
    return records


def _txt_strings(response):
    """DoH TXT data arrives quoted; strip the surrounding quotes."""
    out = []
    for data in answers_of(response, RT_TXT):
        out.append(data.strip().strip('"'))
    return out


def _rrsig_status(soa_response):
    """Return (valid, detail) for the RRSIG covering the SOA record."""
    if not soa_response:
        return False, "RRSIG not measured (no DNS response)."
    for record in soa_response.get("Answer", []) or []:
        if record.get("type") != RT_RRSIG:
            continue
        fields = record.get("data", "").split()
        if len(fields) < 5:
            continue
        expiry_raw = fields[4]
        try:
            if len(expiry_raw) == 14 and expiry_raw.isdigit():
                dt = datetime.datetime.strptime(expiry_raw, "%Y%m%d%H%M%S")
                expiry = dt.replace(tzinfo=datetime.timezone.utc).timestamp()
            else:
                expiry = int(expiry_raw)
        except ValueError:
            continue
        if expiry > time.time():
            return True, "RRSIG signatures are current and valid."
        return False, "RRSIG signature has expired."
    return False, "No RRSIG signature found."


def _dnssec_algorithm(dnskey_response):
    for data in answers_of(dnskey_response, RT_DNSKEY):
        fields = data.split()
        if len(fields) >= 3 and fields[0] == "257":  # KSK
            try:
                algo = int(fields[2])
            except ValueError:
                continue
            return DNSSEC_ALGORITHMS.get(algo, "UNKNOWN({})".format(algo))
    return None


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def summarise(checks, has_v6):
    """Compute parts, score, level and the IPv4-off answers from the checks."""
    passed = {c: 0 for c in WEIGHTS}
    measured = {c: 0 for c in WEIGHTS}
    for check in checks:
        if not check["scored"]:
            continue
        category = check["category"]
        if check["status"] in ("PASS", "FAIL"):
            measured[category] += 1
            if check["status"] == "PASS":
                passed[category] += 1
    score = compute_score(passed, measured)
    provisional = not has_v6
    by_key = {c["key"]: c for c in checks}

    def status(key):
        return by_key.get(key, {}).get("status")

    def off_answer(keys):
        statuses = [status(k) for k in keys]
        if all(s == "PASS" for s in statuses):
            return "yes"
        if any(s == "FAIL" for s in statuses):
            return "no"
        return "not measured"

    ipv4_off = {
        "web": off_answer(["ipv6_only_reachable"]),
        "dns": off_answer(["ns_has_aaaa", "ns_reachable_v6", "ns_answers_v6"]),
        "email": off_answer(["mx_has_record", "mx_has_aaaa", "mx_smtp_v6"]),
    }
    parts = {}
    for category, weight in WEIGHTS.items():
        points = weight * passed[category] / measured[category] if measured[category] else 0.0
        parts[category] = {
            "title": CATEGORY_TITLES[category],
            "passed": passed[category],
            "measured": measured[category],
            "total": TOTALS[category],
            "weight": weight,
            "points": round(points, 1),
        }
    what_to_fix = [c for c in checks if c["scored"] and c["status"] == "FAIL"]
    not_measured = [c for c in checks if c["status"] == "NOT MEASURED"]
    time_limited = any(c["detail"] == TIME_LIMIT_REASON for c in checks)
    return {
        "score": score,
        "level": level_for(score),
        "provisional": provisional,
        "time_limited": time_limited,
        "parts": parts,
        "ipv4_off": ipv4_off,
        "what_to_fix": what_to_fix,
        "not_measured": not_measured,
    }


def render_human(domain, checks, summary, official, has_v6, started_at):
    lines = []
    add = lines.append
    add("IPv6 readiness check: {}".format(domain))
    add("Method: My6 IPv6 Readiness Criteria 1.0 (My6 Initiative Berhad), as used by the National IPv6 Readiness Monitor (ipv6.my6.my)")
    add("Checked at: {} (UTC)".format(started_at))
    add("Local outbound IPv6: {}".format("working" if has_v6 else "not available"))
    add("")
    add("Verdict: {}".format(summary["level"]))
    score_line = "Score: {} / 100".format(summary["score"])
    if summary["provisional"]:
        score_line += "  (PROVISIONAL)"
    add(score_line)
    if official is not None:
        if official.get("available"):
            add("Official score (ipv6.my6.my): {} ({})".format(
                official.get("score"), official.get("level") or official.get("status_label")))
        else:
            add("Official score: {}".format(official.get("reason")))
    if summary["provisional"]:
        add("")
        add("This computer has no working outbound IPv6, so checks that need an IPv6")
        add("connection were not measured and the score is PROVISIONAL. Run with --official")
        add("to compare against the monitor, or run from a computer with IPv6.")
    if summary.get("time_limited"):
        add("")
        add("The 60 second time limit was reached, so some checks were reported as")
        add("NOT MEASURED with the reason 'time limit reached'. They are not failures.")
    add("")
    add("Parts:")
    for category in ("web", "dns", "email", "ipv4"):
        part = summary["parts"][category]
        add("  {:<24} {}/{} passed   {:.1f} / {} points".format(
            part["title"], part["passed"], part["measured"],
            part["points"], part["weight"]))
    add("")
    add("If IPv4 were switched off today, would it keep working?")
    add("  Website: {}".format(summary["ipv4_off"]["web"]))
    add("  DNS:     {}".format(summary["ipv4_off"]["dns"]))
    add("  Email:   {}".format(summary["ipv4_off"]["email"]))
    add("")
    if summary["what_to_fix"]:
        add("What to fix (in order):")
        for index, check in enumerate(summary["what_to_fix"], 1):
            add("  {}. {} - {}".format(index, check["label"], check["fix"]))
    else:
        add("What to fix: nothing, all scored checks passed.")
    add("")
    if summary["not_measured"]:
        add("Not measured from this computer:")
        for check in summary["not_measured"]:
            add("  - {} ({})".format(check["label"], check["detail"]))
        add("")
    add("All checks:")
    for check in checks:
        add("  [{}] {} - {}".format(check["status"], check["label"], check["detail"]))
    add("")
    add("Information items (DS record, RRSIG, signing algorithm, DKIM) are shown above")
    add("as INFO and do not affect the score. Not measured is not failed.")
    return "\n".join(lines)


def render_json(domain, checks, summary, official, has_v6, started_at):
    payload = {
        "domain": domain,
        "method": "My6 IPv6 Readiness Criteria 1.0",
        "checked_at": started_at,
        "local_ipv6": has_v6,
        "provisional": summary["provisional"],
        "time_limited": summary.get("time_limited", False),
        "score": summary["score"],
        "level": summary["level"],
        "official": official,
        "parts": summary["parts"],
        "ipv4_off": summary["ipv4_off"],
        "what_to_fix": [
            {"key": c["key"], "label": c["label"], "why": c["fix"]}
            for c in summary["what_to_fix"]
        ],
        "not_measured": [
            {"key": c["key"], "label": c["label"]} for c in summary["not_measured"]
        ],
        "checks": [
            {"key": c["key"], "label": c["label"], "category": c["category"],
             "scored": c["scored"], "status": c["status"], "detail": c["detail"]}
            for c in checks
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Input handling and main
# ---------------------------------------------------------------------------

def normalize_domain(raw):
    """Clean a user-supplied domain or URL into a bare lowercase hostname.

    Internationalised labels are converted to their IDNA A-label (punycode)
    form so the rest of the script works with ASCII. Existing ASCII labels,
    including xn-- labels, are left unchanged.
    """
    value = raw.strip()
    value = re.sub(r"^(https?)//+", r"\1://", value, flags=re.IGNORECASE)
    if "://" in value:
        parsed = urllib.parse.urlsplit(value)
        if parsed.hostname:
            value = parsed.hostname
    value = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE)
    value = re.split(r"[/?#]", value)[0]
    value = re.sub(r":\d+$", "", value)
    value = value.rstrip(".").lower()
    try:
        labels = []
        for label in value.split("."):
            if any(ord(ch) > 127 for ch in label):
                labels.append(label.encode("idna").decode("ascii"))
            else:
                labels.append(label)
        value = ".".join(labels)
    except (UnicodeError, ValueError):
        pass
    return value


def valid_domain(domain):
    return bool(re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", domain))


def main(argv=None):
    # Make sure Unicode output cannot crash on a legacy Windows console.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="Check a domain's IPv6 readiness using the My6 IPv6 Readiness Criteria, version 1.0.")
    parser.add_argument("domain", help="the domain to check, e.g. example.gov.my")
    parser.add_argument("--json", action="store_true", help="print one JSON object")
    parser.add_argument("--official", action="store_true",
                        help="also fetch the official score from ipv6.my6.my")
    args = parser.parse_args(argv)

    domain = normalize_domain(args.domain)
    if not valid_domain(domain):
        parser.error("please provide a valid domain name, e.g. example.gov.my")

    started_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    budget = Budget(TOTAL_TIME_LIMIT)
    install_ipv4_preference()
    resolver = Resolver(budget)

    try:
        has_v6 = test_ipv6_capability(resolver, budget)
        checks = run_checks(domain, resolver, has_v6, budget)
        summary = summarise(checks, has_v6)
        official = fetch_official(domain, budget) if args.official else None
        if args.json:
            print(render_json(domain, checks, summary, official, has_v6, started_at))
        else:
            print(render_human(domain, checks, summary, official, has_v6, started_at))
        return 0
    except CheckAbort as exc:
        message = str(exc)
        if args.json:
            print(json.dumps({"domain": domain, "error": message}, indent=2))
        else:
            print(message)
        return 0
    except Exception as exc:  # never show a traceback to the user
        message = "The check could not be completed ({}). Please try again.".format(
            type(exc).__name__)
        if args.json:
            print(json.dumps({"domain": domain, "error": message}, indent=2))
        else:
            print(message)
        return 0


if __name__ == "__main__":
    sys.exit(main())
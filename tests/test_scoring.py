"""Unit tests for the My6 IPv6 Readiness Criteria scoring and the not-measured denominator rule.

These tests are offline: they import the pure scoring functions from
scripts/ipv6check.py and never touch the network.

Run with:  python3 -m unittest discover tests
"""

import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import ipv6check  # noqa: E402


def counts(web, dns, email, ipv4):
    """Build a passed dict from four category values."""
    return {"web": web, "dns": dns, "email": email, "ipv4": ipv4}


class TestRounding(unittest.TestCase):
    def test_half_rounds_away_from_zero(self):
        # PHP round() rounds halves away from zero, not to even.
        self.assertEqual(ipv6check.round_half_up(2.5), 3)
        self.assertEqual(ipv6check.round_half_up(3.5), 4)
        self.assertEqual(ipv6check.round_half_up(0.5), 1)

    def test_whole_and_fractional(self):
        self.assertEqual(ipv6check.round_half_up(95.0), 95)
        self.assertEqual(ipv6check.round_half_up(86.6667), 87)
        self.assertEqual(ipv6check.round_half_up(0.0), 0)


class TestScoring(unittest.TestCase):
    def test_worked_example_from_criteria(self):
        # 4 of 5 DNS checks, everything else perfect -> 95.
        passed = counts(8, 4, 6, 3)
        measured = counts(8, 5, 6, 3)
        self.assertEqual(ipv6check.compute_score(passed, measured), 95)

    def test_perfect_score(self):
        passed = counts(8, 5, 6, 3)
        measured = counts(8, 5, 6, 3)
        self.assertEqual(ipv6check.compute_score(passed, measured), 100)

    def test_zero_score(self):
        passed = counts(0, 0, 0, 0)
        measured = counts(8, 5, 6, 3)
        self.assertEqual(ipv6check.compute_score(passed, measured), 0)

    def test_matches_fixed_formula_when_all_measured(self):
        # With every check measured the result must equal the literal formula.
        for web, dns, email, ipv4 in [(8, 4, 6, 3), (3, 4, 6, 1), (5, 2, 3, 2), (0, 0, 0, 0)]:
            passed = counts(web, dns, email, ipv4)
            measured = counts(8, 5, 6, 3)
            expected = ipv6check.round_half_up(
                web / 8 * 35 + dns / 5 * 25 + email / 6 * 25 + ipv4 / 3 * 15)
            self.assertEqual(ipv6check.compute_score(passed, measured), expected)

    def test_empty_measured_does_not_divide_by_zero(self):
        passed = counts(0, 0, 0, 0)
        measured = counts(0, 0, 0, 0)
        self.assertEqual(ipv6check.compute_score(passed, measured), 0)


class TestNotMeasuredDenominator(unittest.TestCase):
    def test_smtp_unmeasurable_removes_two_from_email_denominator(self):
        # SMTP and STARTTLS not measurable: email denominator drops 6 -> 4.
        # 4 passed of 4 measured gives the full 25 email points.
        passed = counts(0, 0, 4, 0)
        measured = counts(0, 0, 4, 0)
        self.assertEqual(ipv6check.compute_score(passed, measured), 25)

    def test_smtp_refused_keeps_denominator_at_six(self):
        # A refusal is a real failure: the two checks stay in the denominator.
        # 4 passed of 6 measured gives only 16.67 -> 17 email points.
        passed = counts(0, 0, 4, 0)
        measured = counts(0, 0, 6, 0)
        self.assertEqual(ipv6check.compute_score(passed, measured), 17)

    def test_unmeasurable_scores_higher_than_refused(self):
        # The whole point of the rule: not measured must not be punished.
        passed = counts(8, 4, 4, 3)
        unmeasured = ipv6check.compute_score(passed, counts(8, 5, 4, 3))
        refused = ipv6check.compute_score(passed, counts(8, 5, 6, 3))
        self.assertGreater(unmeasured, refused)
        self.assertEqual(unmeasured, 95)
        self.assertEqual(refused, 87)

    def test_provisional_no_ipv6_case(self):
        # No local IPv6: connection checks excluded from every denominator.
        passed = counts(3, 2, 4, 3)
        measured = counts(3, 3, 4, 3)
        self.assertEqual(ipv6check.compute_score(passed, measured), 92)


class TestLevels(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(ipv6check.level_for(100), "Fully ready")
        self.assertEqual(ipv6check.level_for(90), "Fully ready")
        self.assertEqual(ipv6check.level_for(89), "Partly ready")
        self.assertEqual(ipv6check.level_for(60), "Partly ready")
        self.assertEqual(ipv6check.level_for(59), "Not ready")
        self.assertEqual(ipv6check.level_for(0), "Not ready")


class TestOfficialLevel(unittest.TestCase):
    def test_prefers_readiness_level(self):
        data = {"readiness": {"criteria": "My6 IPv6 Readiness Criteria",
                              "version": "1.0", "level": "Partly ready"},
                ipv6check.LEGACY_LEVEL_FIELD: "Compliant"}
        self.assertEqual(ipv6check.official_level(data), "Partly ready")

    def test_legacy_field_is_mapped(self):
        # The old field values map to the current level names.
        field = ipv6check.LEGACY_LEVEL_FIELD
        self.assertEqual(ipv6check.official_level({field: "Compliant"}), "Fully ready")
        self.assertEqual(ipv6check.official_level({field: "Partially Compliant"}), "Partly ready")
        self.assertEqual(ipv6check.official_level({field: "Non-Compliant"}), "Not ready")

    def test_missing_fields_return_none(self):
        self.assertIsNone(ipv6check.official_level({}))
        self.assertIsNone(ipv6check.official_level({"readiness": {}}))
        self.assertIsNone(ipv6check.official_level({ipv6check.LEGACY_LEVEL_FIELD: "Unknown"}))


class TestCatalogue(unittest.TestCase):
    def test_weights_and_totals(self):
        self.assertEqual(ipv6check.WEIGHTS, {"web": 35, "dns": 25, "email": 25, "ipv4": 15})
        self.assertEqual(ipv6check.TOTALS, {"web": 8, "dns": 5, "email": 6, "ipv4": 3})

    def test_twenty_two_scored_checks(self):
        scored = [c for c in ipv6check.CHECKS if c[3]]
        self.assertEqual(len(scored), 22)
        per_category = {}
        for c in scored:
            per_category[c[2]] = per_category.get(c[2], 0) + 1
        self.assertEqual(per_category, {"web": 8, "dns": 5, "email": 6, "ipv4": 3})

    def test_four_information_items(self):
        info = [c for c in ipv6check.CHECKS if not c[3]]
        self.assertEqual(len(info), 4)
        self.assertEqual({c[0] for c in info},
                         {"dnssec_ds_present", "dnssec_rrsig_valid",
                          "dnssec_algorithm", "dkim_found"})


class TestDnssecDecision(unittest.TestCase):
    def test_pass_only_status_zero_and_ad_true(self):
        self.assertTrue(ipv6check.dnssec_validated({"Status": 0, "AD": True}))

    def test_missing_ad_fails_closed(self):
        self.assertFalse(ipv6check.dnssec_validated({"Status": 0}))
        self.assertFalse(ipv6check.dnssec_validated({"Status": 0, "AD": False}))

    def test_nonzero_status_fails(self):
        self.assertFalse(ipv6check.dnssec_validated({"Status": 2, "AD": True}))
        self.assertFalse(ipv6check.dnssec_validated({"Status": 3, "AD": True}))

    def test_absent_response_fails(self):
        self.assertFalse(ipv6check.dnssec_validated(None))
        self.assertFalse(ipv6check.dnssec_validated({}))

    def test_ad_must_be_json_true_not_truthy(self):
        self.assertFalse(ipv6check.dnssec_validated({"Status": 0, "AD": "true"}))
        self.assertFalse(ipv6check.dnssec_validated({"Status": 0, "AD": 1}))


class TestWebPassRules(unittest.TestCase):
    def test_http_passes_on_any_positive_code(self):
        for code in (200, 301, 404, 500):
            self.assertTrue(ipv6check.http_pass_code(code))
        self.assertFalse(ipv6check.http_pass_code(0))

    def test_ipv6_only_pass_codes(self):
        for code in (200, 301, 302, 303, 307, 308):
            self.assertTrue(ipv6check.ipv6_only_pass_code(code))
        for code in (0, 403, 404, 405, 500):
            self.assertFalse(ipv6check.ipv6_only_pass_code(code))


class TestBudget(unittest.TestCase):
    def test_fresh_budget_has_time_and_caps_timeout(self):
        budget = ipv6check.Budget(limit=10, start=time.monotonic())
        self.assertFalse(budget.expired())
        self.assertGreater(budget.remaining(), 9)
        self.assertEqual(budget.timeout(3), 3)
        self.assertLessEqual(budget.timeout(50), 10)

    def test_spent_budget_is_expired_and_timeout_zero(self):
        budget = ipv6check.Budget(limit=10, start=time.monotonic() - 20)
        self.assertTrue(budget.expired())
        self.assertLessEqual(budget.remaining(), 0)
        self.assertEqual(budget.timeout(5), 0)

    def test_zero_limit_is_immediately_expired(self):
        budget = ipv6check.Budget(limit=0, start=time.monotonic())
        self.assertTrue(budget.expired())
        self.assertEqual(budget.timeout(8), 0)


class TestTimeLimitReporting(unittest.TestCase):
    def _all_pass_checks(self):
        checks = []
        for key, label, cat, scored, desc, fix in ipv6check.CHECKS:
            checks.append({"key": key, "label": label, "category": cat,
                           "scored": scored, "status": "PASS", "detail": ""})
        return checks

    def test_time_limited_check_is_not_measured_and_excluded(self):
        checks = self._all_pass_checks()
        for c in checks:
            if c["key"] == "http3_supported":
                c["status"] = "NOT MEASURED"
                c["detail"] = ipv6check.TIME_LIMIT_REASON
        summary = ipv6check.summarise(checks, has_v6=True)
        self.assertTrue(summary["time_limited"])
        self.assertEqual(summary["parts"]["web"]["measured"], 7)
        self.assertEqual(summary["parts"]["web"]["passed"], 7)
        # A time-limited check is not a failure, so the score stays at 100.
        self.assertEqual(summary["score"], 100)
        self.assertIn("http3_supported", [c["key"] for c in summary["not_measured"]])
        self.assertEqual(summary["what_to_fix"], [])

    def test_no_time_limit_flag_when_all_measured(self):
        summary = ipv6check.summarise(self._all_pass_checks(), has_v6=True)
        self.assertFalse(summary["time_limited"])


class TestAddressClassification(unittest.TestCase):
    def test_public_address_is_routable(self):
        self.assertTrue(ipv6check.is_globally_routable("2606:4700::1"))

    def test_documentation_range_rejected_even_expanded(self):
        self.assertFalse(ipv6check.is_globally_routable("2001:db8::1"))
        self.assertFalse(ipv6check.is_globally_routable("2001:0db8::1"))

    def test_reserved_and_private_rejected(self):
        for addr in ("::1", "fe80::1", "fd00::1", "fc00::1", "::"):
            self.assertFalse(ipv6check.is_globally_routable(addr), addr)

    def test_multicast_and_ipv4_mapped_rejected(self):
        self.assertFalse(ipv6check.is_globally_routable("ff02::1"))
        self.assertFalse(ipv6check.is_globally_routable("::ffff:1.2.3.4"))

    def test_invalid_address_rejected(self):
        self.assertFalse(ipv6check.is_globally_routable("not-an-address"))

    def test_routable_first_orders_public_before_private(self):
        ordered = ipv6check.routable_first(["fe80::1", "2606:4700::1", "fd00::1"])
        self.assertEqual(ordered[0], "2606:4700::1")
        self.assertEqual(len(ordered), 3)


class TestDnsPacket(unittest.TestCase):
    def test_encode_qname_idna(self):
        qname = ipv6check.encode_qname("münchen.de")
        self.assertIn(b"xn--mnchen-3ya", qname)
        self.assertTrue(qname.endswith(b"\x00"))

    def test_encode_qname_ascii(self):
        qname = ipv6check.encode_qname("example.com")
        self.assertEqual(qname, b"\x07example\x03com\x00")

    def test_label_over_63_octets_rejected(self):
        with self.assertRaises(ValueError):
            ipv6check.encode_qname("a" * 64 + ".com")

    def test_qname_over_255_octets_rejected(self):
        with self.assertRaises(ValueError):
            ipv6check.encode_qname(".".join(["a" * 63] * 5))

    def test_build_dns_query_returns_packet_and_tid(self):
        packet, tid = ipv6check.build_dns_query("example.com", ipv6check.RT_A)
        self.assertIsInstance(packet, bytes)
        self.assertEqual(struct.unpack(">H", packet[:2])[0], tid)
        # RD bit set, question count 1.
        self.assertEqual(struct.unpack(">H", packet[2:4])[0], 0x0100)
        self.assertEqual(struct.unpack(">H", packet[4:6])[0], 1)

    def _response(self, tid, rcode=0, answers=(), qr=True):
        flags = 0x8100 | rcode  # QR + RD
        if not qr:
            flags &= ~0x8000
        question = ipv6check.encode_qname("example.com") + struct.pack(">HH", 1, 1)
        header = struct.pack(">HHHHHH", tid, flags, 1, len(answers), 0, 0)
        body = question
        for rdata in answers:
            body += struct.pack(">HHHIH", 0xC00C, 1, 1, 300, len(rdata)) + rdata
        return header + body

    def test_summary_reads_answer_data(self):
        packet = self._response(1234, answers=[b"\x01\x02\x03\x04"])
        rcode, ancount, has_data = ipv6check.dns_response_summary(packet, 1234)
        self.assertEqual(rcode, 0)
        self.assertEqual(ancount, 1)
        self.assertTrue(has_data)

    def test_summary_empty_answer_has_no_data(self):
        packet = self._response(1234, answers=[])
        rcode, ancount, has_data = ipv6check.dns_response_summary(packet, 1234)
        self.assertEqual(ancount, 0)
        self.assertFalse(has_data)

    def test_summary_zero_length_rdata_has_no_data(self):
        packet = self._response(1234, answers=[b""])
        _, _, has_data = ipv6check.dns_response_summary(packet, 1234)
        self.assertFalse(has_data)

    def test_summary_rejects_tid_mismatch(self):
        packet = self._response(1234, answers=[b"\x01\x02\x03\x04"])
        rcode, ancount, has_data = ipv6check.dns_response_summary(packet, 4321)
        self.assertIsNone(rcode)
        self.assertFalse(has_data)

    def test_summary_rejects_query_without_qr(self):
        packet = self._response(1234, answers=[b"\x01\x02\x03\x04"], qr=False)
        rcode, _, has_data = ipv6check.dns_response_summary(packet, 1234)
        self.assertIsNone(rcode)
        self.assertFalse(has_data)

    def test_summary_nonzero_rcode_still_reports_answer_data(self):
        # dig +short prints answer data regardless of rcode.
        packet = self._response(1234, rcode=3, answers=[b"\x01\x02\x03\x04"])
        rcode, _, has_data = ipv6check.dns_response_summary(packet, 1234)
        self.assertEqual(rcode, 3)
        self.assertTrue(has_data)


class TestNormalizeDomain(unittest.TestCase):
    def test_unicode_is_converted_to_punycode(self):
        self.assertEqual(ipv6check.normalize_domain("München.DE"), "xn--mnchen-3ya.de")

    def test_existing_punycode_unchanged(self):
        self.assertEqual(ipv6check.normalize_domain("xn--mnchen-3ya.de"),
                         "xn--mnchen-3ya.de")

    def test_url_and_port_stripped(self):
        self.assertEqual(ipv6check.normalize_domain("https://Example.gov.my/path?q=1"),
                         "example.gov.my")
        self.assertEqual(ipv6check.normalize_domain("example.gov.my:8080"),
                         "example.gov.my")

    def test_trailing_dot_and_case(self):
        self.assertEqual(ipv6check.normalize_domain("Example.GOV.my."), "example.gov.my")

    def test_valid_domain_accepts_punycode(self):
        self.assertTrue(ipv6check.valid_domain("xn--mnchen-3ya.de"))
        self.assertFalse(ipv6check.valid_domain("münchen.de"))


if __name__ == "__main__":
    unittest.main()

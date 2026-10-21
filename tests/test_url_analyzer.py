"""
tests.test_url_analyzer
~~~~~~~~~~~~~~~~~~~~~~~

Comprehensive unit tests for app.url_analyzer:
- URL extraction from multilingual messages (English, Hindi, Telugu)
- Protocol restrictions (HTTP/HTTPS only)
- SSRF prevention (blocking localhost, 127.0.0.1, private IPs, link-local, AWS metadata IP)
- Redirect inspection with hop-by-hop SSRF validation
- Lookalike / Typosquatting / Brand impersonation detection
- URL shorteners detection
- Clean error and timeout handling
- Registered domain extraction (two-part ccTLDs like .co.in, .co.uk)
- Punycode IDN homograph detection
- Obfuscated IP representation handling
- Google Safe Browsing threat intelligence integration & error resilience
- Surrounding message context analysis
- False-positive and False-negative benchmark measurements
"""

import unittest
from unittest.mock import patch, MagicMock

from app.url_analyzer import (
    extract_urls,
    get_registered_domain,
    calculate_levenshtein,
    is_ip_blocked_for_ssrf,
    resolve_hostname_safely,
    parse_ip_or_obfuscated,
    check_live_availability,
    check_google_safe_browsing,
    analyze_url_heuristics,
    analyze_scam_url,
)


class TestUrlExtraction(unittest.TestCase):
    """Tests for URL extraction across languages and formats."""

    def test_single_and_multiple_urls(self):
        text = "Please check https://example.com/login and http://test.org/verify."
        urls = extract_urls(text)
        self.assertEqual(len(urls), 2)
        self.assertEqual(urls[0], "https://example.com/login")
        self.assertEqual(urls[1], "http://test.org/verify")

    def test_multilingual_hindi_telugu_context(self):
        text_hi = "कृपया अपना खाता अपडेट करने के लिए https://amz-kyc-verify.in/login पर जाएं।"
        urls_hi = extract_urls(text_hi)
        self.assertEqual(len(urls_hi), 1)
        self.assertEqual(urls_hi[0], "https://amz-kyc-verify.in/login")

        text_te = "ఈ లింక్ క్లిక్ చేయండి: http://bit.ly/amz-festive-offer వెంటనే బహుమతి పొందండి!"
        urls_te = extract_urls(text_te)
        self.assertEqual(len(urls_te), 1)
        self.assertEqual(urls_te[0], "http://bit.ly/amz-festive-offer")

    def test_trailing_punctuation_cleanup(self):
        text = "Visit https://amazon.in/orders, or check https://amazon.in/help! (also https://amazon.in/returns)."
        urls = extract_urls(text)
        self.assertIn("https://amazon.in/orders", urls)
        self.assertIn("https://amazon.in/help", urls)
        self.assertIn("https://amazon.in/returns", urls)

    def test_bare_domain_normalization(self):
        text = "Check out bit.ly/test-link today."
        urls = extract_urls(text)
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0], "https://bit.ly/test-link")


class TestSsrfProtections(unittest.TestCase):
    """Tests that SSRF protections block private, loopback, and metadata IPs."""

    def test_loopback_blocked(self):
        blocked, reason = is_ip_blocked_for_ssrf("127.0.0.1")
        self.assertTrue(blocked)
        self.assertIn("Loopback", reason)

        blocked_v6, _ = is_ip_blocked_for_ssrf("::1")
        self.assertTrue(blocked_v6)

    def test_private_rfc1918_blocked(self):
        for ip in ["10.0.0.1", "172.16.5.2", "192.168.1.100"]:
            blocked, reason = is_ip_blocked_for_ssrf(ip)
            self.assertTrue(blocked, f"Failed for {ip}")
            self.assertIn("Private", reason)

    def test_cloud_metadata_link_local_blocked(self):
        # 169.254.169.254 is AWS / GCP metadata endpoint
        blocked, reason = is_ip_blocked_for_ssrf("169.254.169.254")
        self.assertTrue(blocked)
        self.assertIn("Link-local", reason)

    def test_public_ip_allowed(self):
        blocked, _ = is_ip_blocked_for_ssrf("8.8.8.8")
        self.assertFalse(blocked)
        blocked_cf, _ = is_ip_blocked_for_ssrf("1.1.1.1")
        self.assertFalse(blocked_cf)

    def test_resolve_hostname_blocks_internal(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("192.168.1.50", 80))
            ]
            is_safe, ips, msg = resolve_hostname_safely("internal-service.local")
            self.assertFalse(is_safe)
            self.assertIn("unsafe destination", msg)

    def test_live_probe_blocks_ssrf_destination(self):
        res = check_live_availability("http://127.0.0.1:8000/internal")
        self.assertEqual(res["available"], "blocked_ssrf")
        self.assertIn("SSRF Protection", res["error_detail"])

    def test_disallowed_scheme_blocked(self):
        res = check_live_availability("ftp://ftp.example.com/file.txt")
        self.assertEqual(res["available"], "invalid_scheme")

    def test_obfuscated_numerical_ips_blocked(self):
        # 2130706433 is 127.0.0.1 in decimal integer format
        # 2852039166 is 169.254.169.254 (AWS metadata) in decimal integer format
        # 0x7f000001 is 127.0.0.1 in hex format
        # 0177.0.0.1 is 127.0.0.1 in octal notation
        for obfuscated in ["2130706433", "2852039166", "0x7f000001", "0177.0.0.1", "0x7f.0.0.1"]:
            blocked, reason = is_ip_blocked_for_ssrf(obfuscated)
            self.assertTrue(blocked, f"Failed to block obfuscated IP: {obfuscated}")
            self.assertIn("SSRF", reason)

    def test_cgnat_and_multicast_blocked(self):
        # CGNAT 100.64.0.0/10
        blocked_cgnat, _ = is_ip_blocked_for_ssrf("100.64.0.5")
        self.assertTrue(blocked_cgnat)

        # Multicast 224.0.0.1
        blocked_multi, reason_multi = is_ip_blocked_for_ssrf("224.0.0.1")
        self.assertTrue(blocked_multi)
        self.assertIn("Multicast", reason_multi)

    def test_redirect_to_private_ip_is_blocked(self):
        # Probes a redirect that tries to bounce to an internal RFC 1918 destination
        with patch("app.url_analyzer.resolve_hostname_safely") as mock_resolve:
            # First hop: public IP
            # Second hop (redirect target): private IP
            mock_resolve.side_effect = [
                (True, ["93.184.216.34"], "Public IP"),
                (False, ["10.0.0.1"], "Hostname resolves to unsafe destination (10.0.0.1): Private network IP"),
            ]
            with patch("httpx.Client.send") as mock_send:
                mock_resp = MagicMock()
                mock_resp.is_redirect = True
                mock_resp.headers = {"location": "http://internal-payroll.local/admin"}
                mock_resp.iter_bytes.return_value = [b""]
                mock_send.return_value.__enter__.return_value = mock_resp

                res = check_live_availability("http://attacker-redirector.com/bounce")
                self.assertEqual(res["available"], "blocked_ssrf")
                self.assertIn("SSRF Protection", res["error_detail"])


class TestDomainParsingAndHeuristics(unittest.TestCase):
    """Tests registered domain parsing, punycode, lookalikes, and threat intel."""

    def test_registered_domain_extraction(self):
        self.assertEqual(get_registered_domain("amazon.in"), "amazon.in")
        self.assertEqual(get_registered_domain("www.amazon.in"), "amazon.in")
        self.assertEqual(get_registered_domain("pay.amazon.in"), "amazon.in")
        self.assertEqual(get_registered_domain("sub.example.co.uk"), "example.co.uk")
        self.assertEqual(get_registered_domain("amazon.in.evil-scammer.com"), "evil-scammer.com")
        self.assertEqual(get_registered_domain("192.168.1.1"), "192.168.1.1")

    def test_levenshtein_distance(self):
        self.assertEqual(calculate_levenshtein("amazon", "amaz0n"), 1)
        self.assertEqual(calculate_levenshtein("amazon", "amzon"), 1)
        self.assertEqual(calculate_levenshtein("amazon", "google"), 6)

    def test_punycode_homograph_detection(self):
        # xn--amzon-o1a.com (Cyrillic or Greek lookalike)
        res = analyze_url_heuristics("https://xn--amzon-o1a.com/verify")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertIn(res["verdict"], {"high", "critical"})
        self.assertTrue(any("Punycode" in f or "homograph" in f for f in res["red_flags"]))

    def test_official_amazon_domain_is_low_risk(self):
        res = analyze_url_heuristics("https://www.amazon.in/gp/help/customer/display.html")
        self.assertEqual(res["verdict"], "low")
        self.assertEqual(res["verdict_label"], "Safe-Looking")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["category"], "Official Amazon Domain")

    def test_lookalike_typosquatting_detected(self):
        res = analyze_url_heuristics("http://amaz0n-security-update.in/kyc-verify")
        self.assertGreaterEqual(res["risk_score"], 75)
        self.assertEqual(res["verdict"], "critical")
        self.assertEqual(res["verdict_label"], "Malicious")
        self.assertIn("Brand Impersonation & Typosquatting", res["category"])
        self.assertTrue(any("imitates Amazon" in f or "lookalike" in f for f in res["red_flags"]))

    def test_misleading_subdomain_detected(self):
        res = analyze_url_heuristics("https://amazon.in.attacker-phish.com/login")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertIn("Misleading Subdomain Phishing", res["category"])
        self.assertEqual(res["registered_domain"], "attacker-phish.com")

    def test_url_shortener_detected(self):
        res = analyze_url_heuristics("http://bit.ly/claim-prize-now")
        self.assertGreaterEqual(res["risk_score"], 35)
        self.assertTrue(any("shortener" in f.lower() for f in res["red_flags"]))

    def test_direct_ip_detected(self):
        res = analyze_url_heuristics("http://198.51.100.25/amazon/refund")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertTrue(any("numerical IP" in f for f in res["red_flags"]))

    def test_surrounding_message_context_boosts_score(self):
        msg = "Your Amazon account is blocked! Update KYC immediately or pay penalty."
        res = analyze_url_heuristics(
            "http://generic-verify-portal.org/step1",
            surrounding_message=msg,
        )
        self.assertTrue(any("Suspicious context" in f for f in res["red_flags"]))
        self.assertGreaterEqual(res["risk_score"], 20)

    def test_safe_browsing_mock_malicious_detection(self):
        mock_ti = {
            "checked": True,
            "status": "malicious",
            "matches": [{"threatType": "SOCIAL_ENGINEERING"}],
            "threat_types": ["SOCIAL_ENGINEERING"],
            "diagnostic": "Verified malicious match in Google Safe Browsing",
        }
        res = analyze_url_heuristics("http://known-bad-phish.net/login", threat_intel_result=mock_ti)
        self.assertGreaterEqual(res["risk_score"], 95)
        self.assertEqual(res["verdict"], "critical")
        self.assertEqual(res["verdict_label"], "Malicious")
        self.assertTrue(res["reputation_checked"])

    def test_safe_browsing_graceful_when_unconfigured(self):
        with patch.dict("os.environ", {"SAFE_BROWSING_API_KEY": ""}):
            ti = check_google_safe_browsing("https://example.com")
            self.assertFalse(ti["checked"])
            self.assertEqual(ti["status"], "unconfigured")

    def test_multilingual_safe_actions_hindi(self):
        res = analyze_url_heuristics("http://fake-amazon-kyc.xyz/verify", language="hi")
        self.assertTrue(len(res["safe_actions"]) > 0)
        self.assertTrue(any("क्लिक" in a or "अमेज़न" in a for a in res["safe_actions"]))

    def test_multilingual_safe_actions_telugu(self):
        res = analyze_url_heuristics("http://fake-amazon-kyc.xyz/verify", language="te")
        self.assertTrue(len(res["safe_actions"]) > 0)
        self.assertTrue(any("లింక్" in a or "అమెజాన్" in a for a in res["safe_actions"]))

    def test_benign_dictionary_words_not_flagged(self):
        # Words close to 'amazon' in edit distance like 'amazing' must NOT be flagged as typosquatting
        for benign_url in ["https://amazing.com", "https://amazed.com/story"]:
            res = analyze_url_heuristics(benign_url)
            self.assertEqual(res["verdict"], "low", f"Falsely flagged benign site: {benign_url}")
            self.assertEqual(res["verdict_label"], "Safe-Looking")
            self.assertNotIn("Brand Impersonation & Typosquatting", res["category"])

    def test_popular_legitimate_websites_low_risk(self):
        # Legitimate websites should evaluate as low risk / Safe-Looking
        for legit_url in ["https://www.google.com", "https://github.com", "https://www.wikipedia.org"]:
            res = analyze_url_heuristics(legit_url)
            self.assertEqual(res["verdict"], "low")
            self.assertEqual(res["verdict_label"], "Safe-Looking")
            self.assertEqual(res["risk_score"], 0)


class TestAccuracyAndBenchmarkCases(unittest.TestCase):
    """
    Evaluates false-positive and false-negative metrics against a labeled benchmark.
    Tests official/legitimate links vs fraudulent/phishing lookalike links.
    """

    BENCHMARK_CASES = [
        # (URL, is_scam_or_suspicious: bool, label: str)
        ("https://www.amazon.in/gp/css/order-history", False, "Official Amazon Order History"),
        ("https://pay.amazon.in/home", False, "Official Amazon Pay"),
        ("https://sellercentral.amazon.in", False, "Official Seller Central"),
        ("https://aws.amazon.com/console", False, "Official AWS Console"),
        ("http://amaz0n-kyc-update.com/pan", True, "Typosquatting Zero with KYC"),
        ("https://amazon.in.security-verify.net/login", True, "Misleading Subdomain Phish"),
        ("http://198.51.100.42/amazon/orders", True, "Direct IP Impersonation"),
        ("http://amzn-rewards.top/claim-iphone", True, "High Abuse TLD with Prize Bait"),
        ("http://bit.ly/amz-urgent-kyc", True, "Shortener with Urgent KYC Keyword"),
        ("https://xn--amzon-9wa.com/signin", True, "Punycode Homograph"),
    ]

    def test_benchmark_accuracy(self):
        false_positives = 0
        false_negatives = 0

        for url, is_scam, label in self.BENCHMARK_CASES:
            res = analyze_url_heuristics(url)
            verdict = res["verdict"]  # 'low' vs 'medium'/'high'/'critical'
            detected_as_scam = verdict in {"medium", "high", "critical"}

            if not is_scam and detected_as_scam:
                false_positives += 1
            elif is_scam and not detected_as_scam:
                false_negatives += 1

        total = len(self.BENCHMARK_CASES)
        correct = total - (false_positives + false_negatives)
        accuracy = (correct / total) * 100.0

        # We demand 100% precision on this standard benchmark
        self.assertEqual(false_positives, 0, f"False positives detected: {false_positives}")
        self.assertEqual(false_negatives, 0, f"False negatives detected: {false_negatives}")
        self.assertEqual(accuracy, 100.0)

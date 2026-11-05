import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from headers_check import analyse

GOOD_HEADERS = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
    "server": "cloudflare",
}


class AnalyseTests(unittest.TestCase):
    def test_good_site_scores_high(self):
        report = analyse("https://example.com", "https://example.com", 200, GOOD_HEADERS)
        self.assertGreaterEqual(report.score, 85)
        self.assertFalse(any(c.status == "fail" for c in report.checks))

    def test_bare_site_fails_core_headers(self):
        report = analyse("https://example.com", "https://example.com", 200, {})
        failed = {c.header for c in report.checks if c.status == "fail"}
        self.assertIn("Content-Security-Policy", failed)
        self.assertIn("Strict-Transport-Security", failed)
        self.assertIn("X-Content-Type-Options", failed)

    def test_short_hsts_max_age_warns(self):
        headers = dict(GOOD_HEADERS)
        headers["strict-transport-security"] = "max-age=3600"
        report = analyse("https://example.com", "https://example.com", 200, headers)
        hsts = next(c for c in report.checks if c.header == "Strict-Transport-Security")
        self.assertEqual(hsts.status, "warn")

    def test_x_powered_by_warns(self):
        headers = dict(GOOD_HEADERS)
        headers["x-powered-by"] = "PHP/8.1.0"
        report = analyse("https://example.com", "https://example.com", 200, headers)
        disclosure = next(c for c in report.checks if c.header == "Information disclosure")
        self.assertEqual(disclosure.status, "warn")


if __name__ == "__main__":
    unittest.main()

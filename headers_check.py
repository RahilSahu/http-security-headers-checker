#!/usr/bin/env python3
"""HTTP security headers checker.

Fetches a URL and reports which common security response headers are
present, missing, or misconfigured. Read-only: it sends one GET request
and inspects the response. Use it on sites you own or are authorised to
test.

Zero dependencies: Python 3.9+ standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "headers-check/1.0 (+https://github.com/RahilSahu/http-security-headers-checker)"


@dataclass
class Check:
    header: str
    status: str  # "pass", "warn" or "fail"
    detail: str
    value: str | None = None


@dataclass
class Report:
    url: str
    final_url: str
    status_code: int
    checks: list[Check] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Simple 0-100 score: pass = full weight, warn = half."""
        if not self.checks:
            return 0
        points = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
        earned = sum(points[c.status] for c in self.checks)
        return round(100 * earned / len(self.checks))


def _get(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


def analyse(url: str, final_url: str, status_code: int, headers: dict[str, str]) -> Report:
    """Pure analysis step, separated from the network so it can be tested."""
    report = Report(url=url, final_url=final_url, status_code=status_code)
    add = report.checks.append
    is_https = final_url.lower().startswith("https://")

    csp = _get(headers, "content-security-policy")
    if csp:
        weak = any(token in csp for token in ("'unsafe-inline'", "'unsafe-eval'")) and "script-src" in csp
        add(Check("Content-Security-Policy", "warn" if weak else "pass",
                  "Present, but script-src allows unsafe-inline or unsafe-eval." if weak else "Present.",
                  csp))
    else:
        add(Check("Content-Security-Policy", "fail",
                  "Missing. CSP is the main defence-in-depth control against XSS."))

    hsts = _get(headers, "strict-transport-security")
    if not is_https:
        add(Check("Strict-Transport-Security", "warn", "Site is not served over HTTPS."))
    elif hsts:
        low_max_age = False
        for part in hsts.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    low_max_age = int(part.split("=", 1)[1]) < 31536000
                except ValueError:
                    low_max_age = True
        add(Check("Strict-Transport-Security", "warn" if low_max_age else "pass",
                  "Present, but max-age is under one year." if low_max_age else "Present.", hsts))
    else:
        add(Check("Strict-Transport-Security", "fail", "Missing on an HTTPS site."))

    xcto = _get(headers, "x-content-type-options")
    add(Check("X-Content-Type-Options",
              "pass" if (xcto and xcto.strip().lower() == "nosniff") else "fail",
              "Present and set to nosniff." if xcto and xcto.strip().lower() == "nosniff"
              else "Missing or not set to nosniff. Browsers may MIME-sniff responses.",
              xcto))

    xfo = _get(headers, "x-frame-options")
    frame_ancestors = csp and "frame-ancestors" in csp
    if xfo or frame_ancestors:
        add(Check("Clickjacking protection", "pass",
                  "X-Frame-Options present." if xfo else "CSP frame-ancestors present.", xfo))
    else:
        add(Check("Clickjacking protection", "fail",
                  "Neither X-Frame-Options nor CSP frame-ancestors found."))

    referrer = _get(headers, "referrer-policy")
    add(Check("Referrer-Policy", "pass" if referrer else "warn",
              "Present." if referrer else "Missing. Referrers may leak URLs to third parties.",
              referrer))

    permissions = _get(headers, "permissions-policy")
    add(Check("Permissions-Policy", "pass" if permissions else "warn",
              "Present." if permissions else "Missing. Browser features stay enabled by default.",
              permissions))

    coop = _get(headers, "cross-origin-opener-policy")
    add(Check("Cross-Origin-Opener-Policy", "pass" if coop else "warn",
              "Present." if coop else "Missing.", coop))

    server = _get(headers, "server")
    xpb = _get(headers, "x-powered-by")
    if xpb:
        add(Check("Information disclosure", "warn",
                  f"X-Powered-By reveals the stack: {xpb}", xpb))
    elif server and any(ch.isdigit() for ch in server):
        add(Check("Information disclosure", "warn",
                  f"Server header reveals a version: {server}", server))
    else:
        add(Check("Information disclosure", "pass", "No version-revealing headers found.", server))

    return report


def fetch(url: str, timeout: float = 15.0) -> Report:
    if "://" not in url:
        url = "https://" + url
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            return analyse(url, response.geturl(), response.status, headers)
    except urllib.error.HTTPError as exc:  # an HTTP error still carries headers worth checking
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return analyse(url, exc.geturl() or url, exc.code, headers)


def print_report(report: Report) -> None:
    icons = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
    print(f"\nURL:        {report.url}")
    print(f"Final URL:  {report.final_url}")
    print(f"Status:     {report.status_code}")
    print(f"Score:      {report.score}/100\n")
    for check in report.checks:
        print(f"[{icons[check.status]}] {check.header}")
        print(f"       {check.detail}")
        if check.value:
            print(f"       Value: {check.value}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check HTTP security response headers.")
    parser.add_argument("url", help="URL or hostname to check, for example https://example.com")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    args = parser.parse_args(argv)

    try:
        report = fetch(args.url, timeout=args.timeout)
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        print(f"Error: could not fetch {args.url}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "url": report.url, "final_url": report.final_url,
            "status_code": report.status_code, "score": report.score,
            "checks": [vars(c) for c in report.checks],
        }, indent=2))
    else:
        print_report(report)
    return 1 if any(c.status == "fail" for c in report.checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())

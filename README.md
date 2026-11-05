# HTTP Security Headers Checker

A small, zero-dependency Python tool that checks a website for the HTTP
security response headers that matter, explains what each missing header
means, and gives the site a simple score out of 100.

Built for quick checks during web application security assessments and
for site owners who want a plain-language answer to "are my headers OK?"

## What it checks

- Content-Security-Policy (and whether script-src is weakened by
  unsafe-inline or unsafe-eval)
- Strict-Transport-Security, including a max-age under one year
- X-Content-Type-Options: nosniff
- Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Information disclosure via Server version strings and X-Powered-By

## Usage

```bash
python3 headers_check.py https://example.com
python3 headers_check.py example.com --json
```

Example output:

```text
URL:        https://example.com
Final URL:  https://example.com
Status:     200
Score:      44/100

[FAIL] Content-Security-Policy
       Missing. CSP is the main defence-in-depth control against XSS.
```

Exit code is 1 when any check fails, 0 when all pass, so it can be used
in scripts and CI.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only scan sites you own or are authorised to test. This tool sends a
single normal GET request, the same as a browser visiting the page.

## License

MIT, see LICENSE.

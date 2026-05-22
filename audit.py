#!/usr/bin/env python3
"""
HTTP Security Header Auditor
Checks a target URL for missing/misconfigured security headers.
Targets: OWASP recommended headers, CSP, HSTS, X-Frame-Options, etc.
"""

import sys
import json
import urllib.request
import urllib.error
import ssl
import argparse
from dataclasses import dataclass, field
from typing import Optional

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "check": lambda v: "max-age=" in v and int(v.split("max-age=")[1].split(";")[0].strip()) >= 31536000,
        "hint": "max-age must be >= 31536000 (1 year). Add includeSubDomains.",
        "severity": "HIGH",
    },
    "Content-Security-Policy": {
        "check": lambda v: "default-src" in v or "script-src" in v,
        "hint": "No effective CSP directive found. At minimum: default-src 'self'",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "hint": "Value must be DENY or SAMEORIGIN to prevent clickjacking.",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "check": lambda v: v.lower() == "nosniff",
        "hint": "Value must be 'nosniff'.",
        "severity": "MEDIUM",
    },
    "Referrer-Policy": {
        "check": lambda v: v.lower() in (
            "no-referrer", "no-referrer-when-downgrade",
            "strict-origin", "strict-origin-when-cross-origin",
        ),
        "hint": "Recommended: strict-origin-when-cross-origin",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "check": lambda v: len(v) > 0,
        "hint": "Consider restricting camera, microphone, geolocation, etc.",
        "severity": "LOW",
    },
    "X-XSS-Protection": {
        "check": lambda v: "1" in v,
        "hint": "Legacy header. Set to '1; mode=block' or '0' (modern browsers ignore it).",
        "severity": "INFO",
    },
}

DANGEROUS_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_COLOR = {
    "HIGH":   "\033[91m",  # red
    "MEDIUM": "\033[93m",  # yellow
    "LOW":    "\033[94m",  # blue
    "INFO":   "\033[90m",  # grey
    "OK":     "\033[92m",  # green
    "RESET":  "\033[0m",
}


@dataclass
class Finding:
    header: str
    severity: str
    status: str   # MISSING | BAD_VALUE | EXPOSED | PRESENT
    value: Optional[str] = None
    hint: str = ""


def fetch_headers(url: str, timeout: int = 10) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "SecurityHeaderAudit/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return dict(resp.headers)
    except urllib.error.HTTPError as e:
        return dict(e.headers)


def audit(url: str) -> list[Finding]:
    headers_raw = fetch_headers(url)
    headers = {k.lower(): v for k, v in headers_raw.items()}
    findings: list[Finding] = []

    for name, rule in REQUIRED_HEADERS.items():
        key = name.lower()
        if key not in headers:
            findings.append(Finding(
                header=name, severity=rule["severity"],
                status="MISSING", hint=rule["hint"],
            ))
        else:
            val = headers[key]
            if not rule["check"](val):
                findings.append(Finding(
                    header=name, severity=rule["severity"],
                    status="BAD_VALUE", value=val, hint=rule["hint"],
                ))
            else:
                findings.append(Finding(
                    header=name, severity="OK",
                    status="PRESENT", value=val,
                ))

    for name in DANGEROUS_HEADERS:
        if name.lower() in headers:
            findings.append(Finding(
                header=name, severity="MEDIUM",
                status="EXPOSED", value=headers[name.lower()],
                hint=f"Remove or obscure '{name}' to reduce fingerprinting.",
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def print_report(url: str, findings: list[Finding], use_color: bool = True) -> None:
    c = SEVERITY_COLOR if use_color else {k: "" for k in SEVERITY_COLOR}
    print(f"\n{'='*60}")
    print(f" Security Header Audit: {url}")
    print(f"{'='*60}")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OK": 0}
    for f in findings:
        sev = f.severity
        counts[sev] = counts.get(sev, 0) + 1
        col = c.get(sev, "")
        rst = c["RESET"]
        status_tag = f"[{f.status}]".ljust(12)
        sev_tag = f"[{sev}]".ljust(8)
        print(f"  {col}{sev_tag}{rst} {status_tag} {f.header}")
        if f.value:
            print(f"           Value: {f.value[:120]}")
        if f.hint and sev != "OK":
            print(f"           Hint:  {f.hint}")

    print(f"\n{'─'*60}")
    print(f"  {c['HIGH']}HIGH: {counts['HIGH']}{c['RESET']}  "
          f"{c['MEDIUM']}MEDIUM: {counts['MEDIUM']}{c['RESET']}  "
          f"{c['LOW']}LOW: {counts['LOW']}{c['RESET']}  "
          f"{c['INFO']}INFO: {counts['INFO']}{c['RESET']}  "
          f"{c['OK']}OK: {counts['OK']}{c['RESET']}")
    print()


def print_json(url: str, findings: list[Finding]) -> None:
    out = {
        "url": url,
        "findings": [
            {
                "header": f.header,
                "severity": f.severity,
                "status": f.status,
                "value": f.value,
                "hint": f.hint,
            }
            for f in findings
        ],
    }
    print(json.dumps(out, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit HTTP security headers of a target URL."
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        findings = audit(url)
    except Exception as e:
        print(f"[ERROR] Could not reach {url}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print_json(url, findings)
    else:
        print_report(url, findings, use_color=not args.no_color)

    has_high = any(f.severity == "HIGH" for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
HTTP Security Header Auditor
Checks a target URL for missing/misconfigured security headers.
Targets: OWASP recommended headers, CSP, HSTS, X-Frame-Options, etc.

Extended checks:
  - Cookie security (HttpOnly, Secure, SameSite)
  - Advanced CSP directive validation
  - CORS header analysis (origin reflection, credentials)
  - Cache-Control leakage detection
  - Expanded dangerous headers
  - HTTP→HTTPS redirect check
  - --batch FILE  : scan multiple URLs from a file
  - --redirect-chain : follow redirects, inspect each hop
"""

import sys
import json
import re
import urllib.request
import urllib.error
import urllib.parse
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

# Headers that leak info — plain exposure flag
DANGEROUS_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    # Extended — always flag when present
    "X-Debug",
    "Via",
    "X-Forwarded-For",
]

# These are only flagged when they appear to contain version/build info
VERSION_LEAK_HEADERS = [
    "X-Runtime",
    "X-Version",
    "X-Build",
    "X-Request-Id",
]

# Regex that suggests a version string inside a header value
VERSION_PATTERN = re.compile(r'\d+\.\d+', re.IGNORECASE)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}
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
    status: str   # MISSING | BAD_VALUE | EXPOSED | PRESENT | FLAGGED
    value: Optional[str] = None
    hint: str = ""


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_headers(url: str, timeout: int = 10,
                  extra_headers: Optional[dict] = None) -> dict:
    """Return response headers as a plain dict (case-preserved keys)."""
    ctx = _make_ssl_ctx()
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "SecurityHeaderAudit/1.0")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return dict(resp.headers)
    except urllib.error.HTTPError as e:
        return dict(e.headers)


def fetch_headers_no_redirect(url: str, timeout: int = 10,
                               extra_headers: Optional[dict] = None) -> tuple[int, str, dict]:
    """Return (status_code, final_url, headers) without following redirects."""
    ctx = _make_ssl_ctx()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        # Override the default redirect handler so we capture the first hop
        _NoRedirectHandler(),
    )
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "SecurityHeaderAudit/1.0")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.url, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, url, dict(e.headers)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following any redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # do not follow


# ---------------------------------------------------------------------------
# Feature 1: Cookie Security Audit
# ---------------------------------------------------------------------------

def _audit_cookies(headers: dict, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    # urllib merges multiple Set-Cookie into comma-separated — we get them all
    raw_cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw_cookies.append(v)

    if not raw_cookies:
        return findings

    for raw in raw_cookies:
        # Cookie name is the first token before '='
        name = raw.split("=")[0].strip()
        parts_lower = [p.strip().lower() for p in raw.split(";")]

        if "httponly" not in parts_lower:
            findings.append(Finding(
                header=f"Set-Cookie ({name})",
                severity="MEDIUM",
                status="BAD_VALUE",
                value=raw[:120],
                hint="Cookie is missing HttpOnly flag — accessible via JavaScript.",
            ))

        if is_https and "secure" not in parts_lower:
            findings.append(Finding(
                header=f"Set-Cookie ({name})",
                severity="HIGH",
                status="BAD_VALUE",
                value=raw[:120],
                hint="Cookie missing Secure flag on HTTPS — can be sent over plain HTTP.",
            ))

        samesite_part = next((p for p in parts_lower if p.startswith("samesite")), None)
        if samesite_part is None:
            findings.append(Finding(
                header=f"Set-Cookie ({name})",
                severity="LOW",
                status="BAD_VALUE",
                value=raw[:120],
                hint="Cookie has no SameSite attribute — susceptible to CSRF.",
            ))
        elif samesite_part == "samesite=none" and "secure" not in parts_lower:
            findings.append(Finding(
                header=f"Set-Cookie ({name})",
                severity="HIGH",
                status="BAD_VALUE",
                value=raw[:120],
                hint="SameSite=None requires Secure flag — otherwise cookie is rejected by modern browsers and insecure.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Feature 2: Advanced CSP Validation
# ---------------------------------------------------------------------------

def _parse_csp_directives(csp_value: str) -> dict:
    """Return dict {directive_name: [source, ...]} from CSP header value."""
    directives: dict[str, list[str]] = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _audit_csp(headers: dict) -> list[Finding]:
    findings: list[Finding] = []
    csp_value = headers.get("content-security-policy")
    if not csp_value:
        return findings  # already flagged by REQUIRED_HEADERS check

    directives = _parse_csp_directives(csp_value)
    script_src = directives.get("script-src", directives.get("default-src", []))
    style_src = directives.get("style-src", directives.get("default-src", []))

    if "'unsafe-inline'" in script_src:
        findings.append(Finding(
            header="Content-Security-Policy",
            severity="HIGH",
            status="BAD_VALUE",
            value=csp_value[:200],
            hint="CSP: 'unsafe-inline' in script-src allows inline script execution — defeats XSS protection.",
        ))

    if "'unsafe-eval'" in script_src:
        findings.append(Finding(
            header="Content-Security-Policy",
            severity="HIGH",
            status="BAD_VALUE",
            value=csp_value[:200],
            hint="CSP: 'unsafe-eval' in script-src allows eval() — enables DOM-based XSS.",
        ))

    if "'unsafe-inline'" in style_src:
        findings.append(Finding(
            header="Content-Security-Policy",
            severity="MEDIUM",
            status="BAD_VALUE",
            value=csp_value[:200],
            hint="CSP: 'unsafe-inline' in style-src allows inline styles — risk of CSS injection.",
        ))

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(Finding(
            header="Content-Security-Policy",
            severity="HIGH",
            status="BAD_VALUE",
            value=csp_value[:200],
            hint="CSP: neither default-src nor script-src defined — no script execution policy.",
        ))

    for src_list, directive_name in [(script_src, "script-src"), (directives.get("default-src", []), "default-src")]:
        if "*" in src_list:
            findings.append(Finding(
                header="Content-Security-Policy",
                severity="HIGH",
                status="BAD_VALUE",
                value=csp_value[:200],
                hint=f"CSP: wildcard '*' in {directive_name} allows loading scripts from any origin.",
            ))

    object_src = directives.get("object-src", None)
    if object_src is None:
        findings.append(Finding(
            header="Content-Security-Policy",
            severity="MEDIUM",
            status="BAD_VALUE",
            value=csp_value[:200],
            hint="CSP: object-src not defined — Flash/plugin injection possible via default-src fallback.",
        ))
    elif "*" in object_src:
        findings.append(Finding(
            header="Content-Security-Policy",
            severity="MEDIUM",
            status="BAD_VALUE",
            value=csp_value[:200],
            hint="CSP: object-src * allows unrestricted plugin/object embedding.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Feature 3: CORS Header Analysis
# ---------------------------------------------------------------------------

def _audit_cors(url: str, headers: dict, timeout: int = 10) -> list[Finding]:
    """
    Perform CORS analysis:
      - Static wildcard ACAO → INFO
      - Origin reflection → MEDIUM
      - ACAO non-null + ACAC: true → HIGH
    """
    findings: list[Finding] = []
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()

    if not acao:
        return findings

    if acao == "*":
        findings.append(Finding(
            header="Access-Control-Allow-Origin",
            severity="INFO",
            status="FLAGGED",
            value=acao,
            hint="CORS: wildcard '*' allows any origin to read responses — acceptable for public APIs, dangerous for auth-bearing endpoints.",
        ))
    else:
        # Check for origin reflection
        canary = "http://evil.com"
        try:
            reflected_headers = fetch_headers(url, timeout=timeout,
                                               extra_headers={"Origin": canary})
            reflected_acao = reflected_headers.get(
                "Access-Control-Allow-Origin",
                reflected_headers.get("access-control-allow-origin", ""),
            ).strip()
            if reflected_acao == canary:
                findings.append(Finding(
                    header="Access-Control-Allow-Origin",
                    severity="MEDIUM",
                    status="FLAGGED",
                    value=reflected_acao,
                    hint="CORS: server reflects arbitrary Origin header — combined with credentials this is a critical misconfiguration.",
                ))
        except Exception:
            pass  # reflection check is best-effort

    if acac == "true" and acao not in ("", "*"):
        findings.append(Finding(
            header="Access-Control-Allow-Credentials",
            severity="HIGH",
            status="FLAGGED",
            value=f"ACAO={acao}, ACAC=true",
            hint="CORS: Allow-Credentials: true with a specific origin allows cross-origin requests to send cookies/auth — HIGH risk if origin is attacker-controlled.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Feature 4: Cache-Control Leakage
# ---------------------------------------------------------------------------

def _looks_like_auth_endpoint(url: str, headers: dict) -> bool:
    """Heuristic: does this look like an authenticated/sensitive endpoint?"""
    url_lower = url.lower()
    sensitive_paths = ("/api/", "/account", "/profile", "/dashboard",
                       "/admin", "/user", "/me", "/auth", "/login", "/session")
    if any(p in url_lower for p in sensitive_paths):
        return True
    # If the response sets cookies it's almost always auth-related
    if any(k.lower() == "set-cookie" for k in headers):
        return True
    return False


def _audit_cache_control(url: str, headers: dict) -> list[Finding]:
    findings: list[Finding] = []
    cc = headers.get("cache-control", "").lower()
    has_cookies = any(k.lower() == "set-cookie" for k in headers)
    has_auth_header = any(k.lower() == "authorization" for k in headers)

    if has_cookies and not cc:
        findings.append(Finding(
            header="Cache-Control",
            severity="MEDIUM",
            status="MISSING",
            hint="Cache-Control missing on a response that sets cookies — intermediary caches may store session cookies.",
        ))

    if cc and "no-store" not in cc and _looks_like_auth_endpoint(url, headers):
        findings.append(Finding(
            header="Cache-Control",
            severity="LOW",
            status="BAD_VALUE",
            value=cc[:120],
            hint="Cache-Control: no-store not set for an apparently authenticated endpoint — sensitive data may be cached.",
        ))

    if "public" in cc and (has_auth_header or _looks_like_auth_endpoint(url, headers)):
        findings.append(Finding(
            header="Cache-Control",
            severity="MEDIUM",
            status="BAD_VALUE",
            value=cc[:120],
            hint="Cache-Control: public on an endpoint that appears to require authentication — responses may be stored in shared caches.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Feature 5: Expanded Dangerous Headers (version-leak headers)
# ---------------------------------------------------------------------------

def _audit_version_leak_headers(headers: dict) -> list[Finding]:
    findings: list[Finding] = []
    for name in VERSION_LEAK_HEADERS:
        val = headers.get(name.lower(), "")
        if val and VERSION_PATTERN.search(val):
            findings.append(Finding(
                header=name,
                severity="MEDIUM",
                status="EXPOSED",
                value=val[:120],
                hint=f"'{name}' exposes version/build information — remove or sanitise this header.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Feature 6: HTTP→HTTPS Redirect Check
# ---------------------------------------------------------------------------

def _audit_https_redirect(url: str, timeout: int = 10) -> list[Finding]:
    """Only called when url starts with http://"""
    findings: list[Finding] = []
    status, _final_url, resp_headers = fetch_headers_no_redirect(url, timeout=timeout)

    if status in (301, 302, 303, 307, 308):
        location = resp_headers.get("Location", resp_headers.get("location", ""))
        if not location.lower().startswith("https://"):
            findings.append(Finding(
                header="HTTP→HTTPS Redirect",
                severity="HIGH",
                status="FLAGGED",
                value=f"Redirects to: {location}",
                hint="HTTP redirect does not point to HTTPS — traffic can be intercepted.",
            ))
    else:
        findings.append(Finding(
            header="HTTP→HTTPS Redirect",
            severity="HIGH",
            status="MISSING",
            hint="HTTP URL does not redirect to HTTPS (no 3xx response) — plaintext communication allowed.",
        ))

    # HSTS on plain HTTP is incorrect (and ignored by browsers)
    h_lower = {k.lower(): v for k, v in resp_headers.items()}
    if "strict-transport-security" in h_lower:
        findings.append(Finding(
            header="Strict-Transport-Security (HTTP)",
            severity="MEDIUM",
            status="FLAGGED",
            value=h_lower["strict-transport-security"][:120],
            hint="HSTS header sent over plain HTTP — browsers ignore it; it must only be sent over HTTPS.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Feature 7 & 8: Redirect-chain follower
# ---------------------------------------------------------------------------

def follow_redirect_chain(url: str, max_hops: int = 5,
                           timeout: int = 10) -> list[tuple[int, str, dict]]:
    """
    Follow redirects manually, up to max_hops.
    Returns list of (status, url, headers) for each hop.
    """
    hops: list[tuple[int, str, dict]] = []
    current = url
    visited: set[str] = set()

    for _ in range(max_hops + 1):
        if current in visited:
            break
        visited.add(current)
        status, _final, hdrs = fetch_headers_no_redirect(current, timeout=timeout)
        hops.append((status, current, hdrs))
        if status not in (301, 302, 303, 307, 308):
            break
        location = hdrs.get("Location", hdrs.get("location", "")).strip()
        if not location:
            break
        # Resolve relative redirects
        location = urllib.parse.urljoin(current, location)
        current = location

    return hops


def _audit_redirect_chain(url: str, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    hops = follow_redirect_chain(url, timeout=timeout)

    if len(hops) <= 1:
        return findings

    print(f"\n  Redirect chain ({len(hops)} hops):")
    prev_scheme = urllib.parse.urlparse(url).scheme

    for i, (status, hop_url, hdrs) in enumerate(hops):
        scheme = urllib.parse.urlparse(hop_url).scheme
        print(f"    [{i}] {status} {hop_url}")

        # Downgrade detection
        if prev_scheme == "https" and scheme == "http":
            findings.append(Finding(
                header="Redirect Downgrade",
                severity="HIGH",
                status="FLAGGED",
                value=hop_url,
                hint=f"Redirect chain downgrades HTTPS→HTTP at hop {i}: {hop_url}",
            ))
        prev_scheme = scheme

        # Audit headers at each hop
        h_lower = {k.lower(): v for k, v in hdrs.items()}
        # Check for HSTS on intermediate hops (each HTTPS hop should send HSTS)
        if scheme == "https" and "strict-transport-security" not in h_lower and i < len(hops) - 1:
            findings.append(Finding(
                header=f"HSTS (hop {i})",
                severity="LOW",
                status="MISSING",
                value=hop_url,
                hint=f"Intermediate HTTPS hop {i} missing HSTS header.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Core audit function
# ---------------------------------------------------------------------------

def audit(url: str, timeout: int = 10,
          check_redirect_chain: bool = False) -> list[Finding]:
    is_https = url.lower().startswith("https://")
    headers_raw = fetch_headers(url, timeout=timeout)
    headers = {k.lower(): v for k, v in headers_raw.items()}
    findings: list[Finding] = []

    # --- Required headers ---
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

    # --- Dangerous / info-leaking headers (always flag) ---
    for name in DANGEROUS_HEADERS:
        if name.lower() in headers:
            findings.append(Finding(
                header=name, severity="MEDIUM",
                status="EXPOSED", value=headers[name.lower()],
                hint=f"Remove or obscure '{name}' to reduce fingerprinting.",
            ))

    # --- Version-leak headers (flag only when value contains version string) ---
    findings.extend(_audit_version_leak_headers(headers))

    # --- Feature 1: Cookie security ---
    findings.extend(_audit_cookies(headers_raw, is_https))

    # --- Feature 2: Advanced CSP ---
    findings.extend(_audit_csp(headers))

    # --- Feature 3: CORS ---
    findings.extend(_audit_cors(url, headers, timeout=timeout))

    # --- Feature 4: Cache-Control leakage ---
    findings.extend(_audit_cache_control(url, headers_raw))

    # --- Feature 6: HTTP→HTTPS redirect (only for http:// URLs) ---
    if not is_https:
        findings.extend(_audit_https_redirect(url, timeout=timeout))

    # --- Feature 8: Redirect chain analysis ---
    if check_redirect_chain:
        findings.extend(_audit_redirect_chain(url, timeout=timeout))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(url: str, findings: list[Finding], use_color: bool = True) -> None:
    c = SEVERITY_COLOR if use_color else {k: "" for k in SEVERITY_COLOR}
    print(f"\n{'='*60}")
    print(f" Security Header Audit: {url}")
    print(f"{'='*60}")

    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OK": 0}
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


def _summary_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OK": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit HTTP security headers of a target URL."
    )
    # Positional URL is optional when --batch is used
    parser.add_argument("url", nargs="?", default=None,
                        help="Target URL (e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    # Feature 7: batch mode
    parser.add_argument("--batch", metavar="FILE",
                        help="File with one URL per line — scan each and print summary.")
    # Feature 8: redirect chain
    parser.add_argument("--redirect-chain", action="store_true",
                        help="Follow redirects (up to 5 hops) and audit headers at each hop.")
    args = parser.parse_args()

    use_color = not args.no_color
    c = SEVERITY_COLOR if use_color else {k: "" for k in SEVERITY_COLOR}

    # ---- Build URL list ----
    if args.batch:
        try:
            with open(args.batch, "r", encoding="utf-8") as fh:
                urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError as e:
            print(f"[ERROR] Cannot open batch file: {e}", file=sys.stderr)
            sys.exit(1)
        if not urls:
            print("[ERROR] Batch file contains no URLs.", file=sys.stderr)
            sys.exit(1)
    elif args.url:
        u = args.url
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        urls = [u]
    else:
        parser.error("Provide a URL or use --batch FILE.")

    # ---- Scan each URL ----
    all_results: list[tuple[str, list[Finding]]] = []
    any_high = False

    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            findings = audit(url, timeout=args.timeout,
                             check_redirect_chain=args.redirect_chain)
        except Exception as e:
            print(f"[ERROR] Could not reach {url}: {e}", file=sys.stderr)
            if args.batch:
                # In batch mode keep going; record empty findings
                all_results.append((url, []))
                continue
            sys.exit(1)

        all_results.append((url, findings))
        if any(f.severity == "HIGH" for f in findings):
            any_high = True

        if args.json:
            print_json(url, findings)
        else:
            print_report(url, findings, use_color=use_color)

    # ---- Batch summary ----
    if args.batch and not args.json:
        print(f"\n{'='*60}")
        print(f"  BATCH SUMMARY — {len(all_results)} URL(s) scanned")
        print(f"{'='*60}")
        for url, findings in all_results:
            cnts = _summary_counts(findings)
            high_col = c["HIGH"] if cnts["HIGH"] else c["OK"]
            print(f"  {url}")
            print(f"    {high_col}HIGH:{cnts['HIGH']}{c['RESET']}  "
                  f"{c['MEDIUM']}MEDIUM:{cnts['MEDIUM']}{c['RESET']}  "
                  f"{c['LOW']}LOW:{cnts['LOW']}{c['RESET']}  "
                  f"{c['INFO']}INFO:{cnts['INFO']}{c['RESET']}  "
                  f"{c['OK']}OK:{cnts['OK']}{c['RESET']}")
        total_high = sum(_summary_counts(f)["HIGH"] for _, f in all_results)
        total_medium = sum(_summary_counts(f)["MEDIUM"] for _, f in all_results)
        print(f"\n  Total HIGH: {total_high}  Total MEDIUM: {total_medium}")
        print()

    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()

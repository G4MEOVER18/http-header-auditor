# HTTP Security Header Auditor

A fast, zero-dependency Python 3 tool for auditing HTTP security headers against OWASP recommendations.

No external libraries required — uses only Python stdlib (`urllib`, `ssl`, `json`).

## What it checks

### Required Headers
| Header | Severity | What's checked |
|--------|----------|----------------|
| `Strict-Transport-Security` | HIGH | `max-age` ≥ 1 year |
| `Content-Security-Policy` | HIGH | `default-src` or `script-src` present |
| `X-Frame-Options` | MEDIUM | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | MEDIUM | `nosniff` |
| `Referrer-Policy` | LOW | strict value |
| `Permissions-Policy` | LOW | any value present |
| `X-XSS-Protection` | INFO | legacy check |

### Information Disclosure
Flags server version/technology headers that aid fingerprinting:
- `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`

## Usage

```bash
# Basic audit
python audit.py https://example.com

# JSON output (pipe to jq, save to file, etc.)
python audit.py https://example.com --json

# No ANSI colors (for CI/logging)
python audit.py https://example.com --no-color

# Exit code: 1 if any HIGH severity finding, 0 otherwise
# → Integrate into CI pipeline to fail builds with missing HSTS/CSP
```

## Example output

```
============================================================
 Security Header Audit: https://example.com
============================================================
  [HIGH]   [MISSING]    Strict-Transport-Security
           Hint:  max-age must be >= 31536000 (1 year). Add includeSubDomains.
  [HIGH]   [MISSING]    Content-Security-Policy
           Hint:  No effective CSP directive found. At minimum: default-src 'self'
  [MEDIUM] [EXPOSED]    Server
           Value: Apache/2.4.51 (Ubuntu)
           Hint:  Remove or obscure 'Server' to reduce fingerprinting.
  [OK]     [PRESENT]    X-Content-Type-Options
           Value: nosniff
──────────────────────────────────────────────────────────
  HIGH: 2  MEDIUM: 1  LOW: 0  INFO: 0  OK: 1
```

## CI Integration

```yaml
# GitHub Actions example
- name: Security header audit
  run: python audit.py https://your-site.com
  # Fails (exit code 1) if HIGH severity headers are missing
```

## License

MIT License — Copyright (c) 2026 Yanis Ameseder

---

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

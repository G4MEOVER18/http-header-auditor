# HTTP Security Header Auditor

Ein schnelles Python-3-Tool zum Prüfen von HTTP-Sicherheitsheadern — ohne externe Abhängigkeiten, komplett auf Basis der Python-Standardbibliothek (`urllib`, `ssl`, `json`).

## Was wird geprüft

### Pflicht-Header
| Header | Schweregrad | Was geprüft wird |
|--------|-------------|------------------|
| `Strict-Transport-Security` | HIGH | `max-age` ≥ 1 Jahr |
| `Content-Security-Policy` | HIGH | `default-src` oder `script-src` vorhanden |
| `X-Frame-Options` | MEDIUM | `DENY` oder `SAMEORIGIN` |
| `X-Content-Type-Options` | MEDIUM | `nosniff` |
| `Referrer-Policy` | LOW | strenger Wert gesetzt |
| `Permissions-Policy` | LOW | beliebiger Wert vorhanden |
| `X-XSS-Protection` | INFO | Legacy-Check |

### Informationsoffenlegung
Markiert Header, die Server-Version oder Technologie verraten und Fingerprinting erleichtern:
- `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`

## Verwendung

```bash
# Einfacher Audit
python audit.py https://example.com

# JSON-Ausgabe (an jq weiterleiten, in Datei speichern usw.)
python audit.py https://example.com --json

# Ohne ANSI-Farben (für CI/Logging)
python audit.py https://example.com --no-color

# Exit-Code: 1 bei HIGH-Befunden, 0 sonst
# → In CI-Pipeline einbinden, um Builds mit fehlendem HSTS/CSP fehlzuschlagen
```

## Beispielausgabe

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

## CI-Integration

```yaml
# GitHub Actions Beispiel
- name: Security header audit
  run: python audit.py https://your-site.com
  # Schlägt fehl (Exit-Code 1), wenn HIGH-Header fehlen
```

## Lizenz

MIT License — Copyright (c) 2026 Yanis Ameseder

---

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`

**Kontakt:** [g4me.over.18@gmail.com](mailto:g4me.over.18@gmail.com)
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

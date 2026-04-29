# rampok

> *Rampok* (Indonesian: bandit) — a browser-driven black-box web pentester.

A Claude Code skill that probes a **live** web target for OWASP-aligned issues using only browser automation. No `sqlmap`, no `ffuf`, no Burp — just a real browser and AI reasoning.

Companion to **`satpam-owasp`** (which audits source code). Use rampok when you only have a URL.

## ⛔ Authorization required

Before any active testing, you must confirm authorization. The skill will refuse to proceed otherwise. Acceptable bases:

1. You own the target.
2. Signed pentest engagement.
3. In-scope bug bounty (HackerOne, Bugcrowd, Intigriti, etc.).
4. CTF / intentionally vulnerable lab (DVWA, Juice Shop, HTB, vulhub, PortSwigger Academy).
5. Local / staging environment you control.

Unauthorized testing is illegal under CFAA (US), CMA (UK), ITE Law 11/2008 (ID), and similar laws elsewhere. The skill records your stated basis verbatim in the report.

## How to invoke

```
rampok https://staging.myapp.local
/rampok --url https://juice-shop.example.com --depth quick
test https://target.com for vulnerabilities
black-box pentest https://api.acme.com
```

## Browser MCP requirement

Rampok needs a real browser via MCP. Install one of:

- **Playwright MCP** (recommended): `npm i -g @playwright/mcp` then add to `~/.claude/mcp.json` per its docs
- **Chrome DevTools MCP** (Google's official)
- **Puppeteer MCP**

Without a browser MCP installed, rampok will stop and tell you. It won't fall back to `curl` — real-browser fidelity (JS execution, cookies, real auth flows) is the whole point.

## What it tests

| Playbook | Covers |
|----------|--------|
| `recon.md` | Endpoint inventory, stack fingerprint, well-known paths, JS bundle mining |
| `auth-flows.md` | Login, JWT, sessions, password reset, MFA, OAuth, account enumeration |
| `access-control.md` | IDOR/BOLA, function-level authz, mass assignment, tenant isolation |
| `headers-cookies.md` | Security headers, cookie flags, CORS, CSRF, TLS posture |
| `injection.md` | Reflected/stored/DOM XSS, basic SQLi, SSTI, NoSQLi, CRLF |
| `ssrf-redirect.md` | SSRF (incl. cloud metadata), open redirect, OAuth redirect_uri |
| `business-logic.md` | Workflow skipping, parameter tampering, races, mass assignment |
| `rate-limits.md` | Login throttling, MFA brute force, SMS abuse, signup automation |

## Modes

| Depth | Time | Behavior |
|-------|------|----------|
| `quick` | ~20-40 min | recon + access-control + auth-flows + headers-cookies |
| `deep` (default) | ~1-3 hr | all 8 playbooks |

## Arguments

```
--url <target>            REQUIRED — root URL
--scope <pattern>         path/domain pattern (default: same origin)
--depth quick|deep        default: deep
--creds <login-info>      test credentials, or "interactive"
--output <file.md>        default: PENTEST_REPORT_<YYYY-MM-DD>_<host>.md
--skip <playbooks>        skip specific playbooks
--only <playbooks>        only run these
```

## Output

A markdown report in cwd with:
- Authorization basis (your verbatim consent)
- Executive summary + severity counts + headline issues
- Attack surface inventory (recon output)
- Findings (grouped by severity → category) with reproduction steps, evidence (request/response/screenshot), impact, fix, references
- Methodology, limitations, next steps
- Manual follow-up flags (things browser-only couldn't fully confirm — recommend sqlmap/etc.)

## Layout

```
rampok/
├── SKILL.md                          # entry point, auth gate, workflow, severity rubric
├── README.md                         # this file
├── playbooks/                        # loaded on-demand based on --depth/--skip/--only
│   ├── recon.md
│   ├── auth-flows.md
│   ├── access-control.md
│   ├── headers-cookies.md
│   ├── injection.md
│   ├── ssrf-redirect.md
│   ├── business-logic.md
│   └── rate-limits.md
└── templates/
    ├── auth-confirmation.md          # the legal gate prompt
    └── report.md                     # output report format
```

## Hard rules built into the skill

- ⛔ **No proceed without authorization confirmation.**
- ⛔ **No destructive actions** (DELETE on real records, real payment cards, spam to real users).
- ⛔ **No sustained traffic** (≤2 req/sec default, bursts capped at 20).
- ⛔ **Don't auto-exploit.** Confirm a finding, document, stop. No pivoting from SSRF to internal services, no using leaked IAM creds.
- ⛔ **No scope creep.** If recon reveals a subdomain, re-confirm before testing it.
- ✅ **Evidence required** for every finding (request/response, screenshot, or console output).
- ✅ **Manual follow-up flagged** for blind/heavy checks (sqlmap, amass, testssl) — rampok suggests, doesn't run them.

## What it does NOT do

- Static code analysis → use `satpam-owasp`
- Network/infra (DNS, BGP, port scans) → use nmap/masscan
- Subdomain enumeration → use amass/subfinder
- Heavy fuzzing (blind SQLi, dir busting) → use sqlmap/ffuf
- Comprehensive TLS testing → use testssl.sh
- Social engineering, phishing simulations
- DoS / load testing
- Wireless / mobile pentest

## Companion skills

- [`satpam-owasp`](../satpam-owasp/) — source-code OWASP audit
- Together: black-box (rampok) + white-box (satpam-owasp) = grey-box coverage

## Standards referenced

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP WSTG (Web Security Testing Guide) v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ASVS v4](https://owasp.org/www-project-application-security-verification-standard/)

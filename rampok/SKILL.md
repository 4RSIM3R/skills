---
name: rampok
description: "Use when the user wants to perform a black-box web application security test, browser-driven pentest, or external security assessment of a live URL. Triggers on phrases like \"black-box test\", \"pentest this URL\", \"browser-based audit\", \"test this site for vulnerabilities\", \"rampok\", \"/rampok\". Drives a real browser via MCP to spider, probe, and verify OWASP-aligned issues against a live target. REQUIRES explicit authorization confirmation before any active testing."
---

# Rampok — Black-Box Web Pentest Skill

A browser-driven security tester that probes a live web target for OWASP-aligned issues using only browser automation (no fuzzers, no exploit frameworks). Companion to `satpam-owasp` (which audits source code).

## When to use

Trigger on:
- "black-box test", "pentest this URL", "browser-based audit"
- "test <url> for vulnerabilities", "external security check"
- "rampok", "/rampok", "rampok this"
- Any request to security-test a live site you don't have source for

**Do NOT use for** source-code audits — that's `satpam-owasp`.

## ⛔ Authorization gate (NON-NEGOTIABLE)

Before any active probing, you MUST confirm the user has authorization to test the target. Run `templates/auth-confirmation.md` as the first interaction and refuse to proceed until the user explicitly confirms one of:

1. **Owner** — "I own this site / it's my app"
2. **Engagement** — "I have a signed pentest engagement"
3. **Bug bounty** — "It's an in-scope bug bounty target on <platform>"
4. **CTF / lab** — "It's an intentionally vulnerable target (DVWA, Juice Shop, HTB, PortSwigger Web Academy, vulhub, etc.)"
5. **Local / staging** — "It's running on localhost or a staging environment I control"

If the user can't confirm ANY of these, stop and explain why. Do not proceed even if the user pushes back. Unauthorized testing is a crime in most jurisdictions (CFAA in US, CMA in UK, ITE Law 11/2008 in Indonesia, etc.) and exposes the user to civil and criminal liability. This is not paranoia — it is the single most important rule in this skill.

Record the confirmation verbatim in the final report under "Authorization basis".

## Browser MCP requirement

Rampok drives a real browser via MCP. Recommended (in order of fit):

1. **Playwright MCP** (`@playwright/mcp`) — best mix of automation + network/DevTools access
2. **Chrome DevTools MCP** — official Google option
3. **Puppeteer MCP** — older but works

Generic verbs used in this skill (map to whichever MCP is installed):
- `navigate(url)` — load a page
- `get_page_content()` — current HTML/text
- `evaluate(js)` — run JS in page context
- `click(selector)` / `fill(selector, value)` — interact
- `get_cookies()` / `get_request_headers()` — inspect transport
- `intercept_request(...)` / `replay_request(...)` — tamper requests
- `screenshot()` — capture evidence

If no browser MCP is available, stop and tell the user how to install one (see README.md). Do not attempt to substitute with `curl` or `wget` — the skill's value is real-browser fidelity (JS execution, cookies, real auth flows).

## Arguments

```
--url <target>            REQUIRED — root URL to test
--scope <pattern>         path prefix or domain pattern (default: same origin as --url)
--depth quick|deep        default: deep
--creds <login-info>      optional test credentials (or "interactive" for manual login)
--output <file.md>        default: PENTEST_REPORT_<YYYY-MM-DD>_<host>.md
--skip <playbooks>        comma-separated, e.g. "injection,ssrf-redirect"
--only <playbooks>        run only these (overrides default order)
```

- `quick` — run recon + access-control + auth-flows + headers-cookies (fastest meaningful pass, ~20-40 min)
- `deep` — run all 8 playbooks (~1-3 hours depending on app size)

## Workflow

```
1. Run authorization gate (templates/auth-confirmation.md). STOP if not confirmed.
2. Confirm browser MCP is available. STOP with install instructions if not.
3. Announce plan to user: target, scope, depth, playbooks to run, expected output file.
4. RECON pass (always first) — playbooks/recon.md
   - Map endpoints, fingerprint stack, find auth surfaces, collect attack surface inventory
5. For each remaining playbook in order:
   a. Load the playbook from playbooks/
   b. Execute its checklist against the recon inventory
   c. For each candidate finding, VERIFY with a follow-up probe before reporting
   d. Capture evidence (request/response, screenshot, console output)
6. Aggregate findings, dedupe, calibrate severity per the rubric below
7. Render report using templates/report.md
8. Write report to --output path; print summary + path to chat
```

## Playbook order (deep mode)

1. `recon.md` — always first
2. `auth-flows.md` — login, reset, session, JWT, MFA
3. `access-control.md` — IDOR, BOLA, function-level authz, admin route discovery
4. `headers-cookies.md` — security headers, cookie flags, CORS, CSP
5. `injection.md` — reflected XSS, basic SQLi, SSTI, command-line — browser-observable only
6. `ssrf-redirect.md` — SSRF on URL inputs, open redirects
7. `business-logic.md` — workflow skipping, race basics, mass assignment via DevTools
8. `rate-limits.md` — login throttling, password reset spam, signup automation

## Severity rubric

| Severity | Criteria |
|----------|----------|
| **Critical** | Unauthenticated remote exploit, account takeover via single request, RCE, mass data exfil, payment bypass |
| **High** | Authenticated privilege escalation, IDOR on PII/billing, stored XSS, working SSRF to internal/metadata |
| **Medium** | Reflected XSS, IDOR on low-sensitivity data, missing rate limit on sensitive endpoint, weak crypto observable from outside |
| **Low** | Missing security headers, info disclosure (versions, debug pages), defense-in-depth gaps |

When in doubt, report **lower** — credibility comes from not crying wolf.

## Active vs passive testing

This skill performs **active** testing (sending crafted requests, attempting logins, submitting payloads). Two ground rules:

1. **Never destructive.** No DROP, no DELETE on real records, no payment submission with real cards, no spam to real users. If a test would create persistent state in a multi-user environment, ask first.
2. **Throttle.** Default to ≤2 requests/sec to avoid being mistaken for a DoS attack. Tighter for known-fragile targets.

## Anti-patterns to avoid

- **Don't proceed without authorization confirmation.** Ever. No exceptions for "but it's just a quick check".
- **Don't blast traffic.** This isn't a load test. Throttle.
- **Don't claim a finding you didn't verify.** "The header is missing" requires actually inspecting the response, not assuming.
- **Don't recommend `sqlmap`/`ffuf`/`burp` as fixes.** Those are tools the user runs separately. This skill is browser-only by design.
- **Don't store evidence to disk without checking.** Screenshots may contain PII. Confirm with user before persisting outside the report.
- **Don't auto-exploit.** If you find a working SSRF, document it — don't pivot to internal services.
- **Don't try credentials that aren't yours.** No password lists, no default-cred sweeps unless the user explicitly says "this is a CTF, try defaults".

## Evidence capture standard

Every finding in the report must include at least one of:
- The exact request that triggered it (method, URL, headers, body)
- The response observed (status, relevant headers, snippet of body)
- A screenshot (if visual — XSS popup, error page)
- Console output (for DOM-based issues)

If you cannot capture evidence, you cannot include the finding.

## Examples

**User:** "rampok https://staging.myapp.local"
→ Authorization gate → confirms staging-they-control → run deep on full origin.

**User:** "/rampok --url https://juice-shop.example.com --depth quick"
→ Authorization gate → confirms CTF target → quick mode (recon + access-control + auth + headers).

**User:** "test https://target.com/v2 for IDOR" *(stranger's site)*
→ Authorization gate → user can't confirm → STOP. Explain.

**User:** "pentest this bug bounty target https://api.acme.com, scope is /v2/*"
→ Authorization gate → confirms HackerOne in-scope → deep mode, scope locked to `/v2/*`.

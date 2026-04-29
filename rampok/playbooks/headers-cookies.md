# Playbook: Headers, Cookies & CORS

**Goal:** Verify presence and correctness of security headers, cookie flags, CORS policy, and TLS posture as observable from the browser.

**Active level:** Mostly passive. A few cross-origin probes count as active but are low-impact.

**Prerequisites:** Recon inventory.

## Steps

### 1. Security header presence (per page type)
Sample at least: root page, an authenticated page, an API JSON response. For each, check response headers:

| Header | What to look for | Notes |
|--------|------------------|-------|
| `Strict-Transport-Security` | Present, `max-age ≥ 15552000` (180d), ideally `includeSubDomains` and `preload` | Missing on HTTPS site = Medium |
| `Content-Security-Policy` | Present, no `unsafe-inline`/`unsafe-eval` for scripts (in modern apps), no `*` in script-src/object-src | Weak/missing CSP makes XSS more impactful |
| `X-Frame-Options` (or CSP `frame-ancestors`) | Present (`DENY` or `SAMEORIGIN`), or CSP equivalent | Missing = clickjacking risk |
| `X-Content-Type-Options` | `nosniff` | Almost always should be present |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | Loose = referer leakage |
| `Permissions-Policy` | Present, restricts camera/mic/geo unless needed | Hardening |
| `Cache-Control` (on auth'd responses) | `no-store` for sensitive pages | Cached PII in shared caches = exposure |
| `X-Powered-By` / `Server` | Should NOT be verbose (hide version numbers) | Info disclosure |

For each missing/weak header, record severity per the rubric below.

### 2. CSP detailed check (if present)
1. Capture the CSP string verbatim.
2. Parse the directives:
   - `script-src` — flag `*`, `'unsafe-inline'`, `'unsafe-eval'`, `data:` (for scripts), broad CDN wildcards
   - `style-src` — `'unsafe-inline'` is common but worth noting
   - `frame-ancestors` — should restrict embedding
   - `connect-src` — should restrict fetch/XHR origins
   - `default-src` — fallback; should ideally be `'none'` or `'self'`
   - Missing `object-src 'none'` is a common gap (Flash/PDF embed risk)
3. Try a CSP bypass: if `script-src` allows a CDN like `https://cdn.jsdelivr.net`, check if that CDN serves arbitrary user content (e.g. via its API). If yes → CSP is bypassable.
4. Use browser DevTools console to check CSP violation reports being logged (indicates the CSP exists but is in report-only mode, vs enforce mode — verify directive name `Content-Security-Policy-Report-Only` vs `Content-Security-Policy`).

### 3. Cookie flag inspection
1. After login, `get_cookies()` and inspect every cookie:

| Flag | Sensitive cookie should have | Finding if missing |
|------|------------------------------|--------------------|
| `httpOnly` | yes (session, auth) | **Medium** (XSS can steal it) |
| `secure` | yes on any HTTPS site | **Medium** (cookie sent over HTTP if site falls back) |
| `sameSite` | `lax` or `strict` for session | **Medium** (CSRF risk if `none` without need) |
| `Domain` | scoped tightly (don't share with subdomains unless needed) | **Low** if over-broad |
| `Path` | typically `/` | not usually a finding |
| `Expires`/`Max-Age` | session: short; persistent: reasonable | **Low** if session cookie persists for years |

2. Check if any cookie name leaks framework info (`PHPSESSID`, `JSESSIONID`, `connect.sid`) — info disclosure (Low).

### 4. CORS policy probe
1. From recon, identify API endpoints that return JSON.
2. Send a cross-origin preflight: `evaluate("fetch('https://target/api/foo', {method:'GET', headers:{'X-Test':'1'}, credentials:'include'}).then(r=>r.headers.get('access-control-allow-origin'))")` from a different origin (you may need to set this up via a local page).
3. Inspect the response:
   - `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` → **High** (browser will reject this combo, but server intent is broken)
   - `Access-Control-Allow-Origin: <reflected from request Origin>` (without validation, accepts any) + credentials → **Critical**
   - `Access-Control-Allow-Origin: null` → **High** (sandboxed iframes / file:// can match)
4. Try `Origin: https://attacker.example.com` to see if reflection happens.
5. Also check `Access-Control-Allow-Headers` for permissive `*`.

### 5. CSRF token presence on state-changing forms
1. From form inventory in recon, list every POST/PUT/PATCH/DELETE form.
2. For each, check:
   - Hidden CSRF token in form? (`<input type="hidden" name="csrf_token" ...>`)
   - SameSite=strict on session cookie (acts as CSRF defense at browser level for top-level navigation)
   - Custom header requirement for AJAX (often `X-Requested-With: XMLHttpRequest`)
3. Test: replay a state-changing request with the CSRF token removed. If still accepted → **High** CSRF.
4. Test: replay with a wrong CSRF token. If accepted → **High**.
5. Test: take CSRF token from User A's session, try to use it in User B's request. If accepted → **High** (token not bound to session).

### 6. TLS posture (browser-observable)
1. Check certificate via DevTools security panel:
   - Issuer
   - Expiry (flag if <30 days)
   - SANs (does it cover the expected hostnames?)
   - Algorithm (RSA 2048+ or ECDSA — flag if RSA <2048 or SHA-1)
2. HTTPS-only: try `http://target/` — does it redirect to HTTPS?
3. Mixed content: open the HTTPS page, check console for "Mixed Content" warnings or DevTools security panel for non-secure origins loaded.
4. Note that comprehensive TLS testing (cipher suites, OCSP, etc.) requires `testssl.sh` / `sslyze` — flag for manual follow-up if needed.

### 7. Subresource Integrity (SRI)
For every `<script src>` and `<link rel="stylesheet">` loading from external CDN:
- Is `integrity="sha256-..."` present?
- Without SRI, a CDN compromise can inject malicious code.
- Missing SRI on third-party assets → **Low** to **Medium** depending on asset criticality.

### 8. WebSocket / EventSource origin checks (if observed)
1. If the app uses WebSockets, inspect the upgrade request.
2. Does the server validate the `Origin` header? Try connecting from a different origin and see if it accepts.

## Severity baselines

| Finding | Severity |
|---------|----------|
| HTTPS not enforced (HTTP works) | **High** |
| HSTS missing | **Medium** |
| CSP missing entirely on user-content pages | **Medium** |
| CSP allows `unsafe-inline` for script-src on auth'd pages | **Medium** |
| CORS `Access-Control-Allow-Origin` reflects + credentials | **Critical** |
| CORS wildcard `*` + credentials | **High** |
| CSRF token absent on state-changing form (and SameSite not strict) | **High** |
| CSRF token validated but reusable cross-session | **High** |
| Session cookie missing `httpOnly` | **Medium** |
| Session cookie missing `secure` flag | **Medium** |
| Session cookie `sameSite=none` without need | **Medium** |
| `X-Frame-Options` and CSP `frame-ancestors` both missing | **Medium** (clickjacking) |
| Missing SRI on third-party scripts | **Low** |
| Verbose `Server`/`X-Powered-By` | **Info** |
| Mixed content (HTTP resource on HTTPS page) | **Medium** |

## Don'ts
- Don't try to actually exploit clickjacking against real users.
- Don't perform a CSRF demonstration that triggers a real action with real consequences (e.g. transferring real money).
- Don't run automated TLS scanners against the target through this skill — recommend manual `testssl.sh` instead.

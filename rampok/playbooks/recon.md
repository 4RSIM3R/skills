# Playbook: Recon

**Goal:** Build an inventory of the in-scope attack surface — endpoints, parameters, auth surfaces, stack fingerprint — that all subsequent playbooks will consume. Always runs first.

**Active level:** Mostly passive (loading public pages). No payloads sent yet.

## Steps

### 1. Initial load and fingerprint
1. `navigate(target_url)`
2. `get_request_headers()` — capture **response** headers from the root page
3. Note: `Server`, `X-Powered-By`, `Set-Cookie` names, `X-Frame-Options`, `Content-Security-Policy`, framework hints (`__NEXT_DATA__`, `<meta name="generator">`, Rails `csrf-token`, Django CSRF cookie, etc.)
4. Screenshot the root page as evidence

### 2. Well-known paths (passive — just GET)
Try each, record status + content-type + first 200 bytes:
- `/robots.txt` — extract any disallowed paths (often points to interesting stuff)
- `/sitemap.xml` — extract URLs
- `/.well-known/security.txt` — record contact info if present
- `/.well-known/openid-configuration` — OIDC endpoints if any
- `/.well-known/oauth-authorization-server`
- `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/docs`, `/redoc`
- `/graphql`, `/graphiql`, `/api/graphql`
- `/healthz`, `/health`, `/status`, `/metrics`, `/actuator`, `/actuator/env`, `/actuator/health`
- `/.git/HEAD`, `/.env`, `/.DS_Store` (info disclosure — these would be Critical findings if present)
- `/admin`, `/wp-admin`, `/phpmyadmin`, `/adminer` (just check for existence)

### 3. Spider in-scope links
1. `get_page_content()` on landing page
2. Extract all `<a href>`, `<form action>`, `<script src>`, `<link href>`, `<iframe src>`, `<img src>`
3. Filter to in-scope (matches `--scope` pattern)
4. Recursively visit (BFS, max depth 3, max 100 pages, throttle 2/sec)
5. For each page, also pull URLs found in inline JS (regex for `'/api/...'`, `"/v1/..."`, etc. — common API path patterns)

### 4. JavaScript bundle mining
1. List all unique `.js` URLs from spidering
2. For each (limit ~20 largest), fetch and search for:
   - API endpoints (regex: `["'`/](api|v1|v2|graphql)/[a-zA-Z0-9_/-]+["'`]`)
   - Hardcoded credentials (`api_key`, `apiKey`, `secret`, `token`, `password` followed by `=` or `:` and a string)
   - AWS keys (`AKIA[0-9A-Z]{16}`)
   - Internal hostnames (`*.internal`, `*.local`, `*.corp`, IP ranges)
   - Comments mentioning TODO/FIXME with security relevance
   - Source maps (`.map` files referenced) — if present, fetch them to recover original source
3. Record each finding with the bundle URL + line context

### 5. Form inventory
For every form found:
- Action URL, method
- All input fields (name, type, placeholder)
- Whether CSRF token is present
- Whether `autocomplete="off"` on password fields
- Whether sensitive fields use `type="password"`

### 6. Cookie inventory
1. After visiting several pages, `get_cookies()`
2. For each cookie record: name, domain, path, `httpOnly`, `secure`, `sameSite`, `expires`
3. Identify which are session cookies (typically the one that disappears on logout)

### 7. Authentication surface
Identify and record:
- Login form URL + method
- Registration URL (if open)
- Password reset URL
- OAuth/SSO buttons (which providers?)
- 2FA / MFA setup pages (if reachable without auth, that's already a finding)
- API auth method (Bearer? Cookie? API key in header/query?)

### 8. Subdomain / related origin observation
- From every loaded page and bundle, note any external origins referenced
- Particularly flag: same-org subdomains (`*.target.com`), CDN origins, third-party SDKs (analytics, CRM, support widgets)
- DO NOT TEST OUT-OF-SCOPE ORIGINS. Just record for the report.

### 9. Tech stack fingerprint summary
Compile from above:
- Web server (from `Server` header)
- Framework (from headers, cookies, HTML hints)
- Frontend framework (from JS bundles, HTML structure)
- CDN/WAF (Cloudflare ray ID, Akamai headers, AWS X-Amz-* headers)
- Auth method
- Notable third-party integrations

## Output: recon inventory

Produce a structured summary that the other playbooks will consume:

```yaml
target: https://example.com
scope: example.com
endpoints:
  - {method: GET, path: /, auth: none, content: html}
  - {method: GET, path: /api/users, auth: bearer, content: json}
  - {method: POST, path: /api/login, auth: none, content: json, fields: [email, password]}
forms:
  - {url: /login, method: POST, csrf: false, fields: [email, password]}
cookies:
  - {name: session, httpOnly: false, secure: true, sameSite: lax}
auth:
  login_url: /login
  reset_url: /password/reset
  oauth: [google]
  api_method: bearer-jwt
stack:
  server: nginx
  framework: nextjs-14
  cdn: cloudflare
info_disclosure:
  - {path: /.env, status: 200, severity: critical}
```

## Severity baselines (recon-direct findings)

| Finding | Severity |
|---------|----------|
| `.env` / `.git/HEAD` / config files exposed at known path | **Critical** |
| `/admin` reachable without auth | **High** (or Critical if it's actually functional) |
| Source maps exposed in production | **Medium** (info disclosure aiding further attacks) |
| Hardcoded API key in JS bundle | **Critical** (rotate immediately) |
| Internal hostnames leaked in JS | **Low** (recon aid) |
| GraphQL introspection enabled | **Medium** (it's intended in dev, not prod) |
| Verbose `Server` / `X-Powered-By` | **Info** (hardening, not exploit) |
| `security.txt` missing | **Info** (best practice, not vuln) |

## Don'ts
- Don't fuzz directories with wordlists. Just check the well-known paths above.
- Don't try credentials. That's the auth-flows playbook.
- Don't follow redirects out-of-scope. Stop at scope boundary.
- Don't recursively crawl >3 levels deep or >100 pages. Spider hygiene.

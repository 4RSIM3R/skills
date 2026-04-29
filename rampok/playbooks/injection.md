# Playbook: Injection (Browser-Observable)

**Goal:** Find reflected XSS, basic SQL injection, SSTI (server-side template injection), and command injection that's observable from the browser. Heavy/blind injection is out of scope — flag for sqlmap follow-up.

**Active level:** Active. Sends payloads to inputs. Each payload is benign (alert dialogs, math expressions) — never destructive.

**Prerequisites:** Recon inventory; list of input parameters from forms and URL params.

## Steps

### 1. Build input parameter inventory
From recon, list:
- All URL query parameters (`?q=...`, `?sort=...`, `?id=...`)
- All form fields (text, search, email, hidden, etc.)
- All JSON body fields in observed API requests
- All HTTP headers the server appears to read (`User-Agent`, `Referer`, custom `X-` headers)
- All path segments that could be user-influenced

### 2. Reflected XSS
For each input, try these in order (escalating; stop at first hit):

#### 2a. Reflection probe (no payload yet)
Submit a **unique, harmless string** like `xx_rampok_99887766_xx` and:
1. `get_page_content()` after submission
2. Search for the string in the rendered HTML
3. Note **where** it appears: `<input value="...">`, `<a href="...">`, `<script>var x="..."</script>`, plain text, URL of a navigation, etc.
4. If not reflected anywhere, skip XSS for that input (server doesn't echo it back).

#### 2b. Context-appropriate payload
Based on where reflection happens, try the **minimal** payload:

| Context | Payload | What you observe |
|---------|---------|------------------|
| HTML body text | `<script>alert(1)</script>` then `<svg/onload=alert(1)>` | Alert dialog fires (or check console for blocked CSP) |
| HTML attribute (single quote) | `'><script>alert(1)</script>` | Same |
| HTML attribute (double quote) | `"><script>alert(1)</script>` | Same |
| `href` attribute | `javascript:alert(1)` | Click link, alert fires |
| Inside `<script>` (string) | `';alert(1);//` or `</script><script>alert(1)</script>` | Alert fires |
| URL parameter reflected in JS | same as above | Alert fires |
| JSON response rendered as HTML | `<img src=x onerror=alert(1)>` | Alert fires |

3. Use `evaluate("window.alertCalled")` after instrumenting page (override `window.alert` to set a flag) — this is more reliable than chasing dialogs.
4. If alert fires → **High** (Reflected XSS). Take screenshot.
5. If reflected but escaped (e.g. you see `&lt;script&gt;`) → ✅ correct, move on.

#### 2c. CSP impact on XSS
If XSS payload triggers a CSP violation in console → still report (Medium, less critical because CSP blocks execution). Note the CSP saved you.

### 3. Stored XSS (cautious)
Only if a stored field is in scope (your own profile, a comment on a test thread you control):
1. Submit a benign probe in an editable field: `xx_rampok_stored_99887766_xx`
2. View the field as rendered. Reflected without escaping?
3. If yes, escalate with `<svg/onload=alert(1)>`. Confirm execution.
4. **Do not store payloads in fields visible to other real users.** If the only reachable stored field is a public comment thread, stop and use a probe-only test.
5. **Critical** if exploitable, **High** if requires admin viewing.

### 4. DOM-based XSS
1. From recon JS bundle mining, identify any code that reads from `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` event, `localStorage`, `sessionStorage` and writes it into:
   - `innerHTML` / `outerHTML`
   - `document.write` / `document.writeln`
   - `eval` / `Function()` / `setTimeout(string)` / `setInterval(string)`
   - `el.src = ...` (if attribute-injected)
2. Craft a URL like `https://target/path#<svg/onload=alert(1)>` and visit. If alert fires → **High** DOM XSS.

### 5. SQL injection (browser-observable only)
For each input parameter that looks like it might hit a DB (search, filter, ID lookup):

#### 5a. Probe with a syntax-breaking payload
Try (one at a time, observe response):
- `'`
- `"`
- `\`
- `' OR '1'='1` (in quoted string contexts)
- `' OR 1=1--`
- `\\ `
- numeric input: try `1 OR 1=1`, `1 AND 1=2`

For each, look for:
- 500 error with stack trace mentioning SQL → **High** (info disclosure + likely SQLi)
- Different result count between `1=1` and `1=2` → **Critical** SQLi (boolean-based)
- Error message containing SQL keywords (`syntax error`, `mysql`, `pg`, `unterminated quoted string`) → **High** at minimum

#### 5b. UNION-based confirmation (only if 5a positive)
1. Determine column count: `' UNION SELECT 1--`, `' UNION SELECT 1,2--`, etc.
2. Once columns match, extract `version()`, `current_user`, `current_database()` (one piece, just to confirm — don't dump real data).
3. **Critical** if data extractable.

#### 5c. Blind / time-based — DON'T attempt
This requires many requests and timing analysis. Not browser-driven friendly. Note in report: "Endpoint X showed `'` rejection without errors — recommend blind/time-based testing with sqlmap."

### 6. Server-Side Template Injection (SSTI)
For any input that may be used in a server-rendered template (subjects in emails, names in greetings, etc.):
1. Submit `{{7*7}}` and look for `49` in response.
2. If `49` appears, also try `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}` to fingerprint engine.
3. **Critical** if confirmed (often leads to RCE).
4. Stop at confirmation — don't escalate to RCE payloads.

### 7. Command injection (limited — browser-observable)
For inputs that might hit shell (file converters, lookups by hostname/IP):
1. Try `; sleep 5` (then time the response — if 5+ sec longer than baseline, suspicious)
2. Try `| id` / `; id` / `\`id\`` and look for `uid=` in response (rare to be reflected, but possible in error pages)
3. **Critical** if confirmed.
4. Generally hard to confirm browser-only — flag for manual follow-up.

### 8. NoSQL injection (Mongo-style)
For login forms or filter endpoints:
1. Try sending `{"$ne": null}` as the password value (via DevTools, modify request body): `{"email":"test@test.com", "password":{"$ne":null}}`
2. If it logs in → **Critical** NoSQL injection (operator injection).

### 9. Header injection / CRLF
For any input echoed into a response header (`Location` redirect, `Set-Cookie`):
1. Try `%0d%0aSet-Cookie: injected=1` (URL-encoded CRLF + cookie)
2. Inspect response headers for the injected one.
3. **High** if successful — leads to response splitting and other attacks.

### 10. XXE — DON'T attempt without explicit XML endpoint
If recon shows an endpoint accepting XML:
- Note for manual follow-up: "POST /api/foo accepts XML — manual XXE test recommended."
- Browser doesn't send XML naturally.

## Severity baselines

| Finding | Severity |
|---------|----------|
| Reflected XSS confirmed | **High** |
| Stored XSS exploitable by any user | **Critical** |
| Stored XSS requires admin to view | **High** |
| DOM XSS confirmed | **High** |
| SQLi (any flavor confirmed) | **Critical** |
| SQL error leaked to client (no exploitation confirmed) | **Medium** to **High** |
| SSTI confirmed | **Critical** |
| Command injection confirmed | **Critical** |
| NoSQL operator injection on auth | **Critical** |
| CRLF / header injection | **High** |

## Don'ts
- Don't fire payloads at endpoints that look like they email/notify other users (you'll spam them with `xx_rampok_xx` strings).
- Don't pivot from a confirmed RCE/SQLi to actually compromise the system. Document and stop.
- Don't run wordlist-style payload sets through every input. Targeted, minimal payloads only.
- Don't store stored-XSS payloads where real users will see them. Use throwaway test data only.

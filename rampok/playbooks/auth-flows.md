# Playbook: Authentication Flows

**Goal:** Probe login, registration, password reset, session management, JWT handling, and MFA for OWASP A07/API2 issues.

**Active level:** Active. Sends crafted credentials, requests reset emails, attempts session manipulation. Use only test accounts you control.

**Prerequisites:** Recon inventory; test credentials (or `--creds interactive` to log in manually first).

## Steps

### 1. Login form analysis
For the login URL identified in recon:
1. Inspect the form. Is there a CSRF token? Is the form protected against framing (X-Frame-Options or CSP frame-ancestors)?
2. Submit a deliberately wrong password for a probably-existing username (e.g. `admin@example.com` with `wrongpassword`) and a probably-non-existent username (`nonexistent_xyz_123@example.com` with `anything`). Compare:
   - Response codes
   - Response body / error text
   - Response timing (wait for full response, note ms)
3. **Account enumeration finding** if responses differ in any of those three.

### 2. Brute-force / rate-limit test
1. With a test account you control, submit 10 wrong-password attempts in quick succession (throttle 1/sec).
2. Observe: does the server start returning 429? Lock the account? Add CAPTCHA?
3. **No rate-limit finding** if all 10 returned the same "wrong password" response with no slowdown.
4. Note: don't use other people's accounts even for this test.

### 3. Login over HTTP (not just HTTPS)
1. If `target` is HTTPS, try `navigate(target.replace('https:', 'http:'))`
2. If it serves the login page over HTTP (vs redirecting to HTTPS), that's a finding.
3. Also check if HSTS header is set on the HTTPS root.

### 4. Session cookie analysis (after successful login)
1. Log in with valid test creds.
2. `get_cookies()` — find the session cookie.
3. Check flags: `httpOnly`, `secure`, `sameSite`. Missing any = finding.
4. Note the cookie value before login (if any) and after — did the session ID **regenerate** on login? If not, **session fixation** finding.
5. Try setting a known cookie value pre-login (`evaluate("document.cookie='SESSIONID=ATTACKERVALUE'")`), log in, check if the same value is honored post-login. Same finding category.

### 5. Logout effectiveness
1. Capture the session cookie value while logged in.
2. Click logout.
3. Replay a previously-authenticated request with the OLD cookie value (use `intercept_request` or a fresh navigation with cookie set).
4. If the old session still works → **broken logout / no server-side session invalidation** finding.

### 6. JWT inspection (if Bearer token observed in recon)
For any JWT seen in `Authorization: Bearer ...`:
1. Decode the three parts (base64url) using `evaluate(...)`. **Don't send to external services** — decode locally.
2. Check the `alg` field in the header. If it's `HS256`, note for next test. If it's `RS256`/`ES256`, that's standard.
3. **Try `alg: none`**: craft a token with `{"alg":"none"}` header, original payload, empty signature. Use `replay_request` to send it. If accepted → **Critical** auth bypass.
4. **Try `alg` confusion**: if RS256, swap header to `HS256` and sign with the public key (if obtainable from `.well-known/jwks.json`). If accepted → **Critical**.
5. Check `exp` claim — does the server actually reject expired tokens? Wait past expiry, replay. If accepted → **High**.
6. Check `aud` and `iss` — if missing, note.
7. Inspect the payload for sensitive data (full PII, internal IDs, role flags). Tokens are not encrypted by default — payload is visible to anyone holding it.

### 7. Password reset flow
1. Trigger a reset for your test account. Capture the email-side details if you have access (or use a catchall test inbox).
2. Inspect the reset URL: is the token long and random (≥32 chars CSPRNG-looking)? Or short/predictable/timestamp-based?
3. Trigger another reset, then try the FIRST token. Is it still valid? **If yes → token not invalidated on re-issue (High).**
4. Use a token, then try to reuse it. **If still valid → token not single-use (High).**
5. Wait past stated expiry (or 24h, whichever is shorter — limit-test) and try reusing. **If still valid → no expiry (High).**
6. Try requesting reset for a non-existent email. Compare response with existent — **enumeration finding** if different.
7. Reset password — does the response page leak the new password back? (Yes, this happens in real apps.)

### 8. Registration flow
1. Try registering with: very short passwords (1-3 chars), common passwords (`password`, `12345678`), only-numeric passwords. Does the server accept any?
2. Email verification: is the new account usable before email is verified? Acceptable in some designs, but note.
3. Can you register with an email already in use? Compare error text against login flow's "user exists" — **enumeration confirmation**.

### 9. MFA / 2FA (if available)
1. Enable MFA on a test account. Capture the setup secret (TOTP) — is it shown to the user with a backup option?
2. Skip the verification step on first login post-MFA-setup — does the server enforce it?
3. Test rate-limit on MFA code attempts. Try 10 wrong codes — does it lock?
4. Backup codes — are they single-use? Can you replay them?
5. Look for "remember this device" — does it bypass MFA forever, or have a sane expiry?

### 10. OAuth / SSO (if observed in recon)
For each OAuth flow:
1. Inspect the redirect_uri parameter. Try modifying it to an attacker-controlled domain (`https://attacker.example.com/oauth-cb`). If the IdP redirects there → **Critical** open redirect / token theft vector.
2. Inspect the `state` parameter. Is it present? Validated server-side after callback?
3. After successful OAuth, what scopes are granted? Are they minimal?

## Severity baselines

| Finding | Severity |
|---------|----------|
| JWT `alg: none` accepted | **Critical** |
| JWT alg confusion (RS256→HS256 with public key) | **Critical** |
| Login over plain HTTP | **High** |
| No session regeneration on login (fixation) | **High** |
| Logout doesn't invalidate session server-side | **High** |
| Password reset token reusable | **High** |
| Password reset token doesn't expire | **High** |
| OAuth redirect_uri unvalidated | **Critical** |
| No rate limit on login | **High** |
| No rate limit on password reset | **High** |
| Account enumeration via login/reset | **Medium** |
| Weak password policy (accepts `12345678`) | **Medium** |
| Session cookie missing `httpOnly` | **Medium** |
| Session cookie missing `secure` flag | **Medium** |
| MFA bypassable / not enforced | **High** |
| MFA backup codes reusable | **High** |

## Don'ts
- Don't try password lists against accounts you don't own. Even one attempt is unauthorized.
- Don't trigger reset emails to real users. Use only your test account.
- Don't proceed past `alg: none` test — don't actually use a forged token to access data.

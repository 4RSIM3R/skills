# Playbook: Rate Limits & Anti-Automation

**Goal:** Verify presence and effectiveness of rate limiting, throttling, account lockout, and anti-bot measures on sensitive endpoints.

**Active level:** Active but bounded. Throttle to ≤2 req/sec; cap total attempts at the threshold defined per test. Never sustained "stress test" — that's a DoS.

**Prerequisites:** Recon inventory; test account.

## Sensitive endpoints to test (in order of priority)

1. **Login** — credential stuffing protection
2. **Password reset request** — email spam / enumeration
3. **MFA / 2FA code submission** — brute force of 6-digit code
4. **Signup** — bot account creation
5. **Send invite / share** — outbound spam
6. **Comment / message post** — abuse / spam
7. **Search / list endpoints** — scraping defense
8. **Coupon redemption** — race / brute (covered partly in business-logic)
9. **OTP / SMS send** — wallet drain via SMS costs
10. **API endpoints generally** — rate limit per token

## Steps

### 1. Login rate limit
1. With your test account, submit 5 wrong passwords back-to-back (1/sec).
2. Then submit the correct password. Does it work, or are you blocked?
3. Submit 10 more wrong, then correct. Lock?
4. Try 20 attempts.
5. Observe:
   - 429 Too Many Requests appears at attempt N — record N, record `Retry-After`
   - Account lockout after N attempts — record N, lockout duration, unlock mechanism (auto-expire? email link? admin?)
   - CAPTCHA appears after N — record N
   - Nothing happens, all attempts go through → **High** finding

6. Try different vectors:
   - Same username, different passwords → tests per-account limit
   - Different usernames, same password → tests credential stuffing defense (per-IP)
   - From different IPs (if you can — VPN, mobile hotspot) → tests if limit is per-IP only (which is bypassable)

7. **Lockout grief**: if account locks after N failures, can an attacker lock OUT a legitimate user by guessing their email + 10 wrong passwords? **Medium** finding (DoS by lockout).

### 2. Password reset rate limit
1. Trigger password reset for your test account 10 times in a row.
2. Observe:
   - Same email queued each time? → spam vector (Medium)
   - Throttled with 429 after N? → ✅
   - Silently dropped after N (no error to user)? → reasonable
3. Trigger reset for non-existent emails — same throttle?
4. **High** if fully unrestricted (lets attacker spam any user's inbox).

### 3. MFA brute force
With MFA enabled on test account:
1. Trigger login (user/pass succeeds, MFA prompt appears).
2. Submit 10 wrong 6-digit codes back-to-back.
3. Observe:
   - Lock after N → ✅
   - All 10 accepted with same "wrong code" response → **Critical** (6-digit space is only 1M, brute-forceable in hours)
4. **Critical** if MFA can be brute-forced.

### 4. Signup rate limit
1. Try creating 10 accounts in quick succession (use email aliases or disposable email service).
2. Observe:
   - CAPTCHA after N → ✅
   - All 10 succeed → **Medium** (or **High** if free credits/trial granted to each)
3. If app awards free trial credits → bot can farm credits. Calculate $ value of farmable credits over an hour as impact.

### 5. SMS / OTP send abuse
If the app sends SMS for any purpose (verification, login, alerts):
1. Trigger 10 SMS sends to your test phone (or to a freshly-acquired test number).
2. Each SMS costs the company money (~$0.01 to $0.05 typically).
3. Look for: throttle? cooldown? max-per-day per number/account?
4. **High** to **Critical** if unrestricted (wallet drain).

### 6. Invite / share spam
If the app lets users invite others (referral, calendar invite, share doc with email):
1. Try inviting 20 emails (use addresses you control).
2. Confirm each invitation actually sent.
3. Look for per-day or per-hour caps.
4. **Medium** if abusable for spam blast (real recipients = real spam impact).

### 7. Comment / message flood
On a test thread you control:
1. Post 20 comments back-to-back.
2. Are they all accepted, or rate-limited?
3. **Medium** if no limit (enables harassment / spam to other users).

### 8. Search / list scraping defense
If the app exposes search or list endpoints:
1. Page through results: `?page=1`, `?page=2`, ..., `?page=100`.
2. Throttle? Or all 100 succeed?
3. Try `?limit=1000000` or `?per_page=10000` — does it accept and return everything?
4. Observe response time growing — at some point a slow query is itself a finding (Medium DoS-via-pagination).

### 9. API token rate limits
If the app uses Bearer tokens / API keys:
1. With a valid token, fire 50 requests in 5 seconds at a generic endpoint.
2. 429 appears? At what threshold?
3. Are limits per-token, per-account, per-IP?
4. Are limit headers exposed (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`)?

### 10. Differentiated limits by user / account tier
If the app has paid tiers, test whether limits differ:
- Free tier hits limit at 100/day, paid at 10000/day — that's intentional.
- But if free tier has NO limit on signup → bot abuse of free tier features.

### 11. Bypass attempts (if rate limit found)
If rate limit exists, test if it can be bypassed:
- Different `X-Forwarded-For` header values (server might trust proxy headers naively)
- Different `User-Agent`
- Add random query parameter (`?cachebust=12345`) — caching layer might key on full URL
- Switch HTTP/1.1 ↔ HTTP/2
- Use the endpoint via different paths if multiple aliases exist

If any bypass works → reduce the original "rate limit present" finding's effectiveness; report the bypass as **Medium** to **High**.

## Severity baselines

| Finding | Severity |
|---------|----------|
| No rate limit on login (any) | **High** |
| MFA code brute-forceable | **Critical** |
| No rate limit on password reset (spam) | **High** |
| No rate limit on SMS/OTP send (wallet drain) | **Critical** |
| No rate limit on signup with free credits | **High** |
| No rate limit on signup without credits | **Medium** |
| Rate limit bypassable via `X-Forwarded-For` | **High** |
| Account lockout used as DoS (no unlock) | **Medium** |
| Pagination unbounded (`?limit=1000000`) | **High** (DoS + scraping) |
| Comment / message flood unrestricted | **Medium** |

## Don'ts
- **Don't run 1000-attempt brute force.** 10-20 is enough to confirm "no limit". More is needlessly hostile to the target's infra.
- **Don't actually drain SMS wallets.** Send 5-10 to confirm absence of limit, then stop.
- **Don't spam invites to real people**, even your own contacts. Use email addresses you control or `+` aliases on your own gmail.
- **Don't enumerate user emails** at rate. If account-enumeration is the test, 5 emails is enough.
- **Don't sustain traffic.** Burst, observe, stop. Anything looking like load testing is out of scope.

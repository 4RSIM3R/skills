# Playbook: Business Logic & Mass Assignment

**Goal:** Find flaws in how the app's *intended* workflows can be subverted — step skipping, replay, race conditions, mass assignment, parameter tampering.

**Active level:** Active. Often touches money/inventory flows — use ONLY test accounts and test data.

**Prerequisites:** Recon inventory; understanding of the app's main user flows (signup, checkout, password reset, transfer, etc.).

## Steps

### 1. Identify high-value business flows
Common flows to inspect (in order of common abuse):
- **Checkout / payment** — coupons, totals, line items, currency
- **Signup / trial** — new account → free credits / trial period
- **Password reset / email change** — account takeover potential
- **Refund / cancellation** — sometimes underdefended
- **Transfer / withdrawal** — money or points moving
- **Promo code redemption** — race conditions, replay
- **Referral / invite** — bonus farming
- **Subscription upgrade/downgrade** — pay for cheap, get expensive
- **Quota / rate-limited features** — bypass via parallel requests

### 2. Workflow step skipping
For multi-step flows (e.g. checkout: cart → shipping → payment → confirm):
1. Walk the legitimate flow once. Capture every request via DevTools.
2. Note the URLs, methods, request bodies, and expected progression.
3. Try sending the FINAL step request directly without the intermediate ones.
   - E.g. POST /checkout/confirm without first POSTing /checkout/payment
4. Try in different orders: payment before shipping, confirm before payment, etc.
5. Look for:
   - Order created with no payment recorded
   - Discount applied without eligibility check
   - Status fields set without server-side verification
6. **Critical** if checkout completes without payment.

### 3. Parameter tampering on prices/quantities
1. Capture the checkout request. Look for fields like `price`, `total`, `discount`, `subtotal`, `shipping_cost`, `tax`, `currency`.
2. Modify them via DevTools/intercept and replay:
   - Set `price: 0.01`
   - Set `discount: 100` (or 9999)
   - Set `quantity: -1` (negative — sometimes refunds you)
   - Change `currency: USD` → `currency: IDR` (and watch if conversion happens vs amount kept)
3. Submit and check what total was actually charged.
4. **Critical** if you can pay less than the legitimate price.

### 4. Coupon / promo replay
1. Apply a one-use coupon. Note the response.
2. Apply the same coupon again in a new cart.
3. Apply it in 5 parallel carts (open 5 browser contexts; submit simultaneously).
4. Look for:
   - Single coupon used multiple times → **High**
   - Race condition: 5 simultaneous applications all succeed → **High**
   - Bonus stacking: applying expired/disabled coupon by tampering its ID → **Medium** to **High**

### 5. Mass assignment via DevTools
For any "edit profile" / "update settings" form:
1. Capture the legitimate PATCH/PUT request.
2. Examine the response — does it return all fields of the updated object? Note any fields beyond what the form shows (`role`, `tenantId`, `verifiedEmail`, `createdAt`, `accountBalance`, `permissions`, `flags`).
3. Replay the request with extra fields:
   ```json
   {
     "name": "test",
     "role": "admin",
     "isAdmin": true,
     "is_staff": true,
     "tenantId": "<other tenant>",
     "balance": 999999,
     "credits": 999999,
     "emailVerified": true,
     "id": "<other user id>",
     "permissions": ["*"],
     "stripe_customer_id": "<other user's customer id>"
   }
   ```
4. Reload the profile / re-fetch the object. Did any field stick?
5. **Critical** if `role`/`isAdmin`/`tenantId`/`balance` stuck. **High** if `emailVerified`/`permissions` stuck.

Also try GraphQL mutations with extra arguments — same idea.

### 6. Race conditions (basic, browser-doable)
For transfers / withdrawals / coupon use / inventory holds:
1. Open 5+ browser tabs to the same form, pre-filled.
2. Submit all simultaneously (use `Promise.all` via DevTools `evaluate`):
   ```js
   Promise.all([0,1,2,3,4].map(()=>fetch('/api/withdraw',{method:'POST',body:JSON.stringify({amount:100}),headers:{'content-type':'application/json'}}))).then(rs=>Promise.all(rs.map(r=>r.json())))
   ```
3. Compare the resulting balance to expected. Did all 5 succeed when only 1 should have (insufficient balance for 5)?
4. **High** if race-induced double-spend / double-redemption confirmed.

### 7. Negative / boundary values
For numeric inputs (transfer amount, quantity, age, rating):
- `0` — does it process? Should usually not.
- Negative — `-1`, `-100`, `-9999999` — does it process? Refund effect?
- Very large — `9999999999` — overflow / DoS?
- Floats where ints expected — `1.5` items? Some apps round and refund the difference.
- Scientific notation — `1e308` — sometimes parses oddly.
- Hex/octal in numeric strings — `"0x10"`, `"010"`.

### 8. ID / state field tampering
For any form that includes hidden fields like `<input type="hidden" name="status" value="pending">`:
1. Modify the hidden field via DevTools before submit.
2. Try `status: completed`, `status: paid`, `status: shipped` to skip workflow gates.
3. Try `userId: <other user>` to assign actions to others.

### 9. Time-based abuse
- Trial reset: cancel and re-signup with same email — does trial reset?
- Token expiry not checked: capture a JWT, wait past `exp`, replay.
- Coupon validity: try "future" coupons by changing system time? (only if the app exposes time-based features and you can adjust client clock)

### 10. Multi-account abuse
If the app gives bonuses for invites/referrals:
1. Create test account A. Generate referral link.
2. Sign up account B via that link. Confirm bonus to A.
3. Try recursively: B refers C, C refers D — does it pyramid?
4. Try referring yourself with email aliasing (`me+1@gmail.com`, `me+2@gmail.com`) — does it accept?

## Severity baselines

| Finding | Severity |
|---------|----------|
| Checkout completes with `price: 0.01` after tampering | **Critical** |
| Mass assignment to `role`/`isAdmin`/`tenantId` | **Critical** |
| Mass assignment to balance/credits | **Critical** |
| Mass assignment to `emailVerified` | **High** |
| One-time coupon redeemable many times via race | **High** |
| One-time coupon redeemable serially (not race) | **High** |
| Workflow step skip → unpaid order completed | **Critical** |
| Negative-quantity refund effect | **Critical** |
| Trial reset by re-signup | **Medium** (depends on $) |
| Email alias bypassing one-account-per-email | **Medium** |
| Hidden field tampering changes user/owner | **Critical** |

## Don'ts
- **Don't submit real payment cards.** Use test cards (Stripe `4242 4242 4242 4242`, etc.) and confirm target is in test mode.
- **Don't hold real inventory.** Carts that block stock for other users are real-impact even on a test account.
- **Don't drain real balances** even if you find a way. Document; stop.
- Don't refer real friends to inflate referral bonuses.
- Don't submit racing requests in volumes that look like a DoS — 5 parallel is enough to demonstrate.

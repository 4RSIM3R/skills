# Authorization Gate

Before any active testing begins, the user MUST confirm authorization. Send the following message verbatim (or close paraphrase) and wait for an explicit answer:

---

> ⛔ **Authorization required**
>
> Before I start probing `<target_url>`, I need you to confirm you have authorization to test it. Active security testing of systems you don't own or have permission to test is illegal in most jurisdictions (CFAA in US, CMA in UK, ITE Law 11/2008 in Indonesia, similar laws elsewhere).
>
> Please reply with **one** of the following:
>
> 1. **"I own this target"** — it's your app / your infrastructure
> 2. **"I have a signed pentest engagement"** — name the client/scope (won't be shared, just for the report)
> 3. **"It's an in-scope bug bounty"** — name the program (HackerOne, Bugcrowd, Intigriti, self-hosted, etc.) and confirm the URL is in scope
> 4. **"It's a CTF / intentionally vulnerable lab"** — name it (DVWA, Juice Shop, HTB, PortSwigger Web Academy, vulhub, custom training env, etc.)
> 5. **"It's local / staging that I control"** — confirm it's not exposed to external users
>
> If none of these apply, say so and I'll stop. I won't ask you to prove it — your confirmation is on the record, and the responsibility is yours.

---

## What to do with the response

| User response | Action |
|---------------|--------|
| One of options 1-5, with specifics | Record the basis verbatim. Proceed. |
| "Yes" / "go ahead" without specifics | Re-ask. Need the specific basis for the report. |
| Refuses to confirm or evasive | STOP. Do not proceed. Suggest they retry with explicit authorization. |
| Claims authorization but specifics seem fishy (random commercial site, "I work there but no engagement letter") | Ask one clarifying question. If still unclear, stop and recommend they get written authorization first. |

## Recording in the report

In the final report, under "Authorization basis", quote the user's confirmation verbatim:

```markdown
## Authorization basis
> "It's a HackerOne program (acme-corp). The target https://api.acme.com/* is in-scope per their policy."
> — User, 2026-04-29 14:32 WIB
```

This is not legal protection for you — the user is responsible for the truth of their statement — but it documents that consent was sought and given.

## When to re-confirm

If the engagement extends beyond the originally scoped target (e.g. recon reveals a subdomain you want to probe, but it's outside the original scope), STOP and re-confirm scope before testing the new surface. Don't assume scope expansion.

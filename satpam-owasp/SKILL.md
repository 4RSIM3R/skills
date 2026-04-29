---
name: satpam-owasp
description: "Use when the user asks for a security audit, security review, OWASP audit, pentest, or wants to find common security flaws in code. Also triggers on phrases like \"audit this code\", \"check for vulnerabilities\", \"security check\", \"find security issues\", \"satpam\", \"/satpam-owasp\". Walks the OWASP Top 10:2025 (web), API Top 10:2023, and LLM Top 10:2025 against the codebase and produces a markdown audit report with severity-rated findings."
---

# Satpam OWASP — Security Audit Skill

A stack-agnostic security auditor that walks the current OWASP standards against any codebase and produces a structured findings report.

## When to use

Trigger on any of:
- "security audit", "security review", "audit this code"
- "check for vulnerabilities", "find security issues", "security check"
- "OWASP audit", "pentest this", "vulnerability scan"
- "/satpam-owasp", "satpam", "run satpam"

## Modes

The skill supports four modes — auto-detect by default:

| Mode | Rulebook | When to use |
|------|----------|-------------|
| `web` | OWASP Top 10:2025 | Server-rendered apps, forms, sessions, browser-facing |
| `api` | OWASP API Top 10:2023 | REST/GraphQL/RPC services, OpenAPI specs, no views |
| `llm` | OWASP LLM Top 10:2025 | Apps calling Claude/OpenAI/LangChain, RAG, agents |
| `all` | All three rulebooks | Mixed codebases (most modern apps) |

### Auto-detection heuristics

Run these checks on the target directory in order. First strong match wins; if multiple match, use `all`:

- **LLM signals**: imports of `openai`, `anthropic`, `@anthropic-ai/sdk`, `langchain`, `llamaindex`; presence of prompt templates; vector DB clients (`pinecone`, `weaviate`, `qdrant`, `chroma`, `pgvector`); files matching `*prompt*`, `*agent*`, `*rag*`.
- **API signals**: OpenAPI/Swagger files (`openapi.{yaml,json}`, `swagger.{yaml,json}`); GraphQL schemas (`*.graphql`, `schema.gql`); routes returning JSON only; no template engine installed.
- **Web signals**: template directories (`views/`, `templates/`, `*.ejs`, `*.hbs`, `*.jinja`, `*.blade.php`, `*.erb`); session middleware; CSRF tokens; form rendering.

If multiple categories of signals appear, default to `all`.

## Arguments

```
--mode web|api|llm|all     (default: auto-detect)
--depth quick|deep         (default: deep)
--path <dir-or-file>       (default: cwd)
--output <file.md>         (default: SECURITY_AUDIT_<YYYY-MM-DD>.md in cwd)
```

- `quick` — runs Discover + Report only (no Verify pass). Faster, noisier, ~5 min.
- `deep` — runs Discover + Verify + Report. Slower, fewer false positives, ~15-30 min depending on repo size.

## Workflow

```
1. Parse args. If --mode missing, run auto-detect heuristics.
2. Announce plan to user: mode(s), depth, path, expected output file.
3. For each selected mode, load the matching rulebook from rulebooks/.
4. For each rule in the rulebook, perform 3 passes:
   a. DISCOVER  — grep/glob for relevant patterns (routes, sinks, configs, etc.)
   b. VERIFY    — for each candidate, read surrounding code; ask: does the protection exist?
                  (skip this pass if --depth quick)
   c. REPORT    — only flag if verification fails (or always flag if --depth quick)
5. Aggregate findings, dedupe, calibrate severity per the rubric below.
6. Render report using templates/report.md.
7. Write report to --output path.
8. Print summary to chat: counts per severity, top 3 issues, output file path.
```

## Severity rubric

Calibrated, not arbitrary — apply consistently:

| Severity | Criteria |
|----------|----------|
| **Critical** | Unauthenticated remote exploit, OR data exfiltration of secrets/PII at scale, OR remote code execution |
| **High** | Authenticated exploit with privilege escalation, OR sensitive data exposure, OR account takeover |
| **Medium** | Exploitable but limited impact (single user, requires unusual conditions), OR information disclosure |
| **Low** | Defense-in-depth gap, hardening recommendation, no direct exploit path |

If a finding could plausibly be two severities, pick the **lower** one — the report's credibility depends on not crying wolf.

## Output

A single markdown file (default `SECURITY_AUDIT_<YYYY-MM-DD>.md`) following `templates/report.md`. Contains:
- Header (repo, date, modes, depth, files scanned)
- Summary table (counts per severity, top categories)
- Findings grouped by severity, then by OWASP category
- Each finding: file:line, CWE, evidence snippet, fix suggestion, references

## Rulebooks

Loaded on-demand to save context — only load what `--mode` selects:

- `rulebooks/web-top10-2025.md` — OWASP Top 10:2025
- `rulebooks/api-top10-2023.md` — OWASP API Top 10:2023
- `rulebooks/llm-top10-2025.md` — OWASP LLM Top 10:2025

## Anti-patterns to avoid

- **Don't report theoretical issues you didn't verify.** A report full of "might be vulnerable if X" is worse than a short report of confirmed issues.
- **Don't dump generic OWASP descriptions.** Every finding must reference a specific file and line in this codebase.
- **Don't suggest fixes you haven't reasoned about.** If the right fix depends on architecture context you don't have, say so and propose two options.
- **Don't claim Critical when it's Medium.** Inflated severity destroys trust with the dev team receiving the report.
- **Don't skip the Verify pass on `deep` runs.** That's the whole value-add over a static linter.

## Stack-agnostic detection patterns

Cheat sheet for the Discover pass — universal patterns that work across languages:

| Looking for | Grep patterns |
|-------------|---------------|
| Route definitions | `(app\|router)\.(get\|post\|put\|delete\|patch)`, `@app.route`, `@router.`, `Route::`, `gin.(GET\|POST)`, `http.HandleFunc`, `def \w+\(request`, `func.*\(.*ctx.*echo.Context\)` |
| SQL queries | `SELECT \|INSERT \|UPDATE \|DELETE `, `\.query\(`, `\.exec\(`, `\.raw\(`, `db\.`, `cursor\.execute` |
| User input | `req\.(body\|params\|query\|headers)`, `request\.(GET\|POST\|json)`, `\$_(GET\|POST\|REQUEST)`, `params\[`, `c\.Param\(`, `r\.URL\.Query` |
| Auth/session | `jwt`, `session`, `cookie`, `passport`, `bcrypt`, `argon2`, `requireAuth`, `authenticate`, `@login_required`, `middleware.*auth` |
| Secrets | `password\s*=`, `api[_-]?key`, `secret\s*=`, `token\s*=`, `BEGIN (RSA \|EC )?PRIVATE KEY`, hex strings ≥32 chars |
| LLM calls | `anthropic\.`, `openai\.`, `\.messages\.create`, `\.chat\.completions`, `langchain`, `llm\.invoke` |
| Shell exec | `exec\(`, `system\(`, `subprocess`, `child_process`, `os\.system`, `Runtime\.exec`, `eval\(` |
| Deserialization | `pickle\.loads`, `yaml\.load[^_]`, `unserialize`, `Marshal\.load`, `JSON\.parse.*req` |
| File operations | `fs\.(read\|write)`, `open\(`, `path\.join.*req`, `fopen\(`, `File\.read` |

## Examples

**User:** "audit this repo for security issues"
→ Auto-detect mode, deep depth, output to cwd.

**User:** "/satpam-owasp --mode api --depth quick"
→ API mode only, quick scan.

**User:** "satpam check just the auth folder"
→ Auto-detect mode, deep depth, --path ./auth.

**User:** "do an OWASP LLM audit of src/agent"
→ Mode: llm, depth: deep, path: src/agent.

# satpam-owasp

> *Satpam* (Indonesian: security guard) for your codebase.

A stack-agnostic Claude Code skill that audits any repo against the current OWASP standards and produces a structured findings report.

## What it covers

- **OWASP Top 10:2025** — web applications
- **OWASP API Security Top 10:2023** — REST/GraphQL/RPC services
- **OWASP Top 10 for LLM Applications:2025** — apps using Claude, OpenAI, LangChain, RAG, agents

## How to invoke

Inside Claude Code, in a repo you want audited:

```
satpam audit this repo
/satpam-owasp
do an OWASP audit
audit src/ for security issues
check this for vulnerabilities
```

Any of those phrases triggers the skill.

## Modes

| Mode | Rulebook | Auto-detected when |
|------|----------|--------------------|
| `web` | Top 10:2025 | views/templates, sessions, forms |
| `api` | API Top 10:2023 | OpenAPI spec, REST/GraphQL routes only |
| `llm` | LLM Top 10:2025 | imports anthropic/openai/langchain, vector DB |
| `all` | all three | mixed signals (most modern apps) |

Override with `--mode`:
```
/satpam-owasp --mode api
satpam --mode llm src/agent
```

## Depth

| Depth | Speed | Behavior |
|-------|-------|----------|
| `quick` | ~5 min | Discover + Report (no Verify pass) — fast, more false positives |
| `deep` (default) | ~15-30 min | Discover + Verify + Report — slower, higher signal |

## Other arguments

```
--path <dir-or-file>   default: cwd
--output <file.md>     default: SECURITY_AUDIT_<YYYY-MM-DD>.md in cwd
```

## Output

A markdown file in the repo root, structured as:

- Header (repo, date, modes, depth, file count)
- Summary table (counts per severity, top categories, headline issues)
- Findings (grouped by severity → category, with file:line, evidence, fix, references)
- Methodology + limitations
- Next steps

## How it works

For each rule in each loaded rulebook, the skill runs three passes:

1. **Discover** — greps/globs for relevant patterns (route definitions, DB calls, LLM calls, configs).
2. **Verify** — reads each candidate's surrounding code and asks "is the protection actually present?" (Skipped on `--depth quick`.)
3. **Report** — only flags confirmed issues. Reduces noise vs static linters.

Severity is calibrated per a written rubric (see `SKILL.md`) — when in doubt, report **lower**, because credibility depends on not crying wolf.

## Layout

```
satpam-owasp/
├── SKILL.md                          # entry point — trigger phrases, workflow, severity rubric
├── README.md                         # this file
├── rulebooks/
│   ├── web-top10-2025.md             # OWASP Top 10:2025
│   ├── api-top10-2023.md             # OWASP API Top 10:2023
│   └── llm-top10-2025.md             # OWASP LLM Top 10:2025
└── templates/
    └── report.md                     # output report format
```

Rulebooks are loaded on-demand based on `--mode`, so the skill doesn't pull every rule into context unless needed.

## Known limitations

- Static analysis only. No dynamic / runtime testing.
- Business-logic flaws outside the OWASP categories are not covered.
- Vendored binaries, native modules, and external services are out of scope unless reflected in repo configs.
- For very large repos, prefer `--path` to scope the audit.

## Standards referenced

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP Top 10 for LLM Applications:2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

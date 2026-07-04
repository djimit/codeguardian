# CodeGuardian

Multi-repo code security scanner met maturity scoring, CVE detectie, en Nederlandse PII scanning. Geïnspireerd door Git Guardian.

**Documentatie**: [docs/API.md](docs/API.md) — Volledige CLI reference, API docs, deployment guide.

## Features

- **Secrets & Tokens** — API keys, wachtwoorden, private keys, database URLs (via `security-review-commons`)
- **Dependency CVEs** — Kwetsbaarheden in npm, PyPI, Go, Maven, Cargo, RubyGems, uv.lock via OSV.dev
- **PII Scanning** — BSN (elfproef), IBAN (mod-97), KvK (context), e-mail, telefoon, postcode (NL-specifiek)
- **Maturity Scoring** — 1-5 score per dimensie (Secrets, Dependencies, PII) + gewogen overall
- **Risk Scoring** — 1-100 risk score per finding op basis van severity, exploitability, exposure, context (test vs productie), en recency
- **Auto-Fix** — Genereert patches voor dependency CVEs, safe bumps automatisch toe te passen
- **Incremental Scans** — Alleen changed files sinds laatste scan, 10x sneller
- **Asset Inventory** — Overzicht van alle dependencies, secrets, en PII per repo
- **Enhanced Pre-commit Hook** — Scant ook dependency manifests in staged files
- **SARIF Output** — Compatibel met GitHub Advanced Security en andere SARIF consumers
- **Server Mode** — HTTP API voor scanning, geschikt voor Docker deployments
- **Compliance Mapping** — Elke finding gekoppeld aan BIO2, NORA, AVG, NIS2 controls
- **PR Review** — Line-specific comments op findings in pull requests
- **Secret Rotation** — Playbooks met `gh secret set` integratie per secret type
- **Supply Chain** — Typosquatting detectie + GitHub Advisory Database cross-reference
- **Init Wizard** — `codeguardian init` voor interactieve setup
- **Auto-PR** — Genereert branch + PR met dependency fixes
- **Scheduled Scans** — GitHub Action voor dagelijkse/weekly scans met issue creation
- **Secret Scanning** — 20+ patronen (GitHub tokens, API keys, DB URLs, private keys, JWT) + entropy analyse
- **Best Practices** — SSL bypass, debug mode, insecure fallbacks, eval, weak crypto, CORS
- **Urgency Labels** — [ONMIDDELLIJK], [DEZE WEEK], [GEPLAND], [VOLGENDE SPRINT]
- **Baseline Diff** — Nieuwe en opgeloste bevindingen t.o.v. vorige scan
- **Multi-repo** — Parallel scanning van GitHub organisatie of lokale paden
- **Smart Suppressions** — Configureer onderdrukkingen per regel, path, met expiry
- **Pre-commit Hook** — Blokkeert commits met CRITICAL/HIGH findings
- **Trend Tracking** — History over tijd met dashboard visualisatie
- **Dashboard** — Standalone HTML dashboard met upload + trend grafieken
- **GitHub Action** — Klaar voor CI/CD integratie met PR comments
- **SARIF-compatible** — JSON output bruikbaar voor verwerking in andere tools

## Use cases

| Use case | Wanneer inzetten | Wat CodeGuardian oplevert |
|----------|------------------|---------------------------|
| **Pull request security gate** | Bij elke PR in een productrepo waar secrets, kwetsbare dependencies of PII niet ongemerkt mogen binnenkomen. | Een scanrapport, optionele PR-comments op gewijzigde regels, baseline diff en een duidelijke merge-block op `high` of `critical` findings. |
| **Multi-repo security snapshot** | Voor een GitHub organisatie, klantomgeving of lokale workspace met meerdere repositories. | Een parallel uitgevoerde scan per repo, maturity score per dimensie en een totaalbeeld van secrets, CVEs en Nederlandse PII-risico's. |
| **Nederlandse privacy- en compliancecheck** | Voor projecten met BSN, IBAN, KvK, telefoonnummers, postcodes of e-mailadressen in broncode, fixtures of documentatie. | PII-findings met NL-specifieke validatie en mapping naar BIO2, NORA, AVG en NIS2 controls. |
| **Dependency remediation flow** | Als OSV.dev kwetsbaarheden vindt in npm, PyPI, Go, Maven, Cargo, RubyGems of `uv.lock`. | Safe fix-voorstellen, optioneel automatisch toepassen, en desgewenst een fix-branch plus pull request. |
| **Secret incident response** | Als tokens, API keys, database URLs, wachtwoorden of private keys in code zijn beland. | Finding-context, urgentielabels en rotatie-playbooks met `gh secret set` stappen per secret type. |
| **Security trend dashboard** | Voor periodieke scans waarbij teams willen zien of de security posture verbetert of verslechtert. | JSON history, trendgrafieken, asset inventory en een dashboard voor management- en engineeringoverzicht. |

## Installatie

```bash
npm install
npm link
```

Vereisten: Node.js >= 20, `gh` CLI (voor GitHub repo discovery).

Zodra de losse repository openbaar is, kan installatie ook direct via GitHub:

```bash
npm install -g https://github.com/djimit/codeguardian/archive/refs/heads/main.tar.gz
```

Na npm-publicatie wordt dit:

```bash
npm install -g @djimit/codeguardian
```

## Gebruik

### Scan een lokale repo

```bash
codeguardian scan --path ./mijn-project
```

### Scan meerdere repos

```bash
codeguardian scan --path ./project-a,./project-b
```

### Scan GitHub organisatie

```bash
codeguardian scan --username djimit
```

### JSON rapport voor dashboard

```bash
codeguardian scan --path . --output report.json
codeguardian dashboard --output report.json
```

### Pre-commit hook installeren

```bash
codeguardian install-hook
```

### PR check met baseline vergelijking

```bash
codeguardian scan --path . --output current.json
codeguardian pr-check --output current.json --baseline main-report.json
```

## Configuratie

Maak `.codeguardian.yml` aan in de repo root:

```yaml
# Fail threshold voor pre-commit en CI
fail_on: high

# Suppressions — onderdruk bekende false positives
suppressions:
  - rule_id: pii-bsn
    path: "**/tests/fixtures/**"
    reason: Geanonimiseerde testdata
    expires: 2026-12-31

  - rule_id: dependency-cve
    path: "packages/legacy/**"
    reason: Legacy package, geplande migratie Q2
    expires: 2026-06-30

  # Wildcard: alle regels matchen op dit path
  - rule_id: "*"
    path: "docs/examples/**"
    reason: Intentionele voorbeelden

# History tracking
history:
  enabled: true
  retention_days: 90
```

### Config opties

| Optie | Type | Default | Beschrijving |
|-------|------|---------|--------------|
| `fail_on` | string | `critical` | Severity threshold: `critical`, `high`, `medium`, `low` |
| `suppressions` | list | `[]` | Lijst van suppressie regels |
| `suppressions[].rule_id` | string | — | Regel ID of `*` voor alle regels |
| `suppressions[].path` | string | — | Glob pattern of `*` voor alle paden |
| `suppressions[].reason` | string | — | Toelichting (audit) |
| `suppressions[].expires` | date | — | ISO datum, na deze datum wordt suppressie actief |
| `history.enabled` | boolean | `true` | Schrijf scanresultaten naar `.codeguardian-history.jsonl` |
| `history.retention_days` | int | `90` | Bewaarperiode voor history entries |

### Glob patterns

- `*` — matcht alles behalve `/`
- `**` — matcht alles inclusief `/`
- `**/tests/**` — matcht elk pad met `tests` erin
- `packages/legacy/**` — matcht alles onder `packages/legacy/`

## CLI opties

```
codeguardian scan [options]
  --repos <patterns>     Comma-separated GitHub repo patterns (bijv. "djimit/*")
  --username <name>      GitHub username/org voor auto-discovery
  --path <paths>         Comma-separated lokale paden
  --output <path>        JSON rapport bestand
  --scanners <list>      Comma-separated: secrets,dependencies,pii
  --concurrency <n>      Max parallel scans (default: 4)
  --format <fmt>         Output: markdown, json, sarif (default: markdown)
  --fail-on <severity>   Exit 1 bij finding op of boven severity
  --staged-only          Alleen staged files scannen (voor pre-commit hook)

codeguardian dashboard [options]
  --output <path>        JSON rapport om te laden
  --port <n>             Poort (default: 3000)

codeguardian pr-check [options]
  --output <path>        Huidige scan rapport
  --baseline <path>      Baseline rapport voor vergelijking
  --fail-on <severity>   Block merge threshold

codeguardian install-hook [options]
  --hook-path <path>     Custom hook pad (default: .git/hooks/pre-commit)
  --fail-on <severity>   Hook fail threshold

codeguardian fix [options]
  --output <path>        JSON rapport van vorige scan
  --apply                Pas safe fixes automatisch toe

codeguardian pr-review [options]
  --output <path>        JSON rapport van scan
  --pr <number>          PR nummer
  --post                 Daadwerkelijk posten (anders dry-run)

codeguardian rotation [options]
  --output <path>        JSON rapport van scan
  --type <type>          Filter: api-key, db-url, private-key, password
  --execute              Voer gh secret set uit

codeguardian init [options]
  --path <path>          Project directory (default: .)

codeguardian auto-pr [options]
  --output <path>        JSON rapport van scan
  --path <path>          Repo root
  --auto-pr              Maak branch, commit, push, en PR aan

codeguardian inventory [options]
  --output <path>        Bouw inventory uit scan rapport

Scan modifiers:
  --incremental          Alleen changed files sinds laatste scan
  --since <git-ref>      Specifieke baseline commit voor incremental
```

## GitHub Action

Zie `action.yml` voor integratie in workflows:

```yaml
- uses: ./codeguardian
  with:
    scanners: dependencies,pii
    fail-on: high
```

## Maturity Scoring

| Score | Label | Betekenis |
|-------|-------|-----------|
| 5 | Best practice | Geen bevindingen |
| 4 | Goed | Weinig, lage ernst |
| 3 | Basis | Acceptabel, aandachtspunten |
| 2 | Minimaal | Significante issues |
| 1 | Afwezig | Kritieke problemen |

Scores worden per dimensie (Secrets, Dependencies, PII) en gewogen overall berekend.

## Architectuur

```
src/
  core/
    config.js            # .codeguardian.yml loader
    suppressions.js      # Finding filter engine
    dependency-scanner.js # OSV.dev CVE scanning
    pii-scanner.js       # NL PII pattern matching
    multi-repo.js        # Parallel orchestratie
    maturity.js          # Score berekening
    report-formatter.js  # Markdown + JSON output
    pr-comment.js        # PR comment + merge blocking
    history.js           # JSONL trend tracking
    hook.js              # Pre-commit hook installer
    staged-scan.js       # Staged files scanning
  dashboard/
    server.js            # HTTP server + API
    index.html           # Dashboard UI
  index.js               # Public API exports
```

## Docker & Server Mode

```bash
# Build image
docker build -t codeguardian .

# Run server
docker run -p 8080:8080 -v $(pwd)/repos:/repos:ro -v $(pwd)/reports:/reports codeguardian

# Or use Docker Compose
docker-compose up

# API usage
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{ "paths": ["/repos/my-project"] }'

curl http://localhost:8080/report
curl http://localhost:8080/health
```

## Tests

```bash
npm test
```

## License

MIT

# CodeGuardian Documentatie

## Overzicht

CodeGuardian is een multi-repo code security scanner die secrets, CVEs, PII, en security best practices detecteert. Geschreven in Node.js met een kleine scanner-core dependency.

## Installatie

```bash
# Lokaal
cd codeguardian
npm install

# Globaal
npm install -g https://github.com/djimit/codeguardian/archive/refs/heads/main.tar.gz

# Na npm-publicatie
npm install -g @djimit/codeguardian
```

## Snelstart

```bash
# 1. Initialiseer config
codeguardian init

# 2. Scan een project
codeguardian scan --path ./mijn-project

# 3. Bekijk dashboard
codeguardian scan --path . --output report.json
codeguardian dashboard --output report.json

# 4. Auto-fix veilige issues
codeguardian fix --output report.json --apply
```

## CLI Reference

### `scan` — Scan repositories

```bash
codeguardian scan [options]

Options:
  --path <paths>         Comma-separated lokale paden
  --username <name>      GitHub username/org voor auto-discovery
  --repos <patterns>     Comma-separated GitHub repo patterns
  --scanners <list>      secrets,dependencies,pii (default: alle)
  --format <fmt>         markdown, json, sarif (default: markdown)
  --output <path>        Output bestand
  --fail-on <severity>   critical, high, medium, low (default: critical)
  --concurrency <n>      Max parallel scans (default: 4)
  --incremental          Alleen changed files sinds laatste scan
  --since <git-ref>      Baseline commit voor incremental
  --baseline <path>      Vergelijk met baseline rapport
```

### `dashboard` — Start web dashboard

```bash
codeguardian dashboard --output report.json --port 3000
```

### `fix` — Auto-fix dependency CVEs

```bash
codeguardian fix --output report.json --apply
```

### `inventory` — Asset inventory

```bash
codeguardian inventory --output report.json  # Bouw inventory
codeguardian inventory                        # Bekijk inventory
```

### `pr-review` — PR line comments

```bash
codeguardian pr-review --output report.json --pr 42 --post
```

### `rotation` — Secret rotation playbooks

```bash
codeguardian rotation --output report.json --type api-key --execute
```

### `init` — Setup wizard

```bash
codeguardian init
```

### `auto-pr` — Auto-fix met PR

```bash
codeguardian auto-pr --output report.json --auto-pr
```

### `server` — HTTP API server

```bash
codeguardian server --port 8080
```

### `install-hook` — Pre-commit hook

```bash
codeguardian install-hook
```

## Configuratie

Maak `.codeguardian.yml` aan in de repo root:

```yaml
fail_on: high

scanners:
  secrets: true
  dependencies: true
  pii: true

suppressions:
  - rule_id: pii-bsn
    path: "**/tests/**"
    reason: Test data
    expires: 2026-12-31

history:
  enabled: true
  retention_days: 90
```

### Suppressions

Onderdruk bekende false positives:

```yaml
suppressions:
  - rule_id: "*"           # Alle regels matchen
    path: "docs/**"        # Op dit path
    reason: Documentatie    # Toelichting
    expires: 2026-12-31    # Optioneel
```

## Scanners

### Secrets & Tokens

Detecteert via `security-review-commons` patronen:
- GitHub Personal Access Tokens (ghp_)
- OpenAI API keys (sk-proj-)
- Anthropic API keys (sk-ant-api03-)
- AWS Access Keys (AKIA)
- Database connection strings
- Private keys (RSA, OpenSSH)
- JWT tokens
- High-entropy strings (Shannon entropy > 4.5)

### Dependency CVEs

Via OSV.dev batch API:
- npm, PyPI, Go, Maven, crates.io, RubyGems
- uv.lock support
- Publieke exploit detectie (CISA KEV)

### PII (Nederland-specifiek)

- BSN (elfproef validatie)
- IBAN (mod-97 validatie)
- KvK-nummers (context detectie)
- E-mailadressen (met exclude lists)
- Telefoonnummers (+31, 06 format)
- Postcodes (NL format: 1234 AB)

### Security Best Practices

- SSL/TLS verification disabled
- Debug/development mode in productie
- Insecure environment variable fallbacks
- eval() / dynamic code execution
- Weak cryptography (MD5, SHA-1)
- Permissive CORS
- Missing security headers
- Secret logging

### Supply Chain

- Typosquatting detectie (Levenshtein distance)
- GitHub Advisory Database cross-reference
- Suspicious package heuristics

## API Server Mode

```bash
codeguardian server --port 8080
```

Endpoints:
- `GET /health` — Health check
- `POST /scan` — Start scan (body: `{ paths, username, format }`)
- `GET /report` — Laatste rapport

## Docker

```bash
docker build -t codeguardian .
docker run -p 8080:8080 -v $(pwd)/repos:/repos:ro codeguardian server
```

Of met docker-compose:

```bash
docker-compose up
```

## GitHub Actions

### PR Scan (action.yml)

```yaml
- uses: ./codeguardian
  with:
    scanners: secrets,dependencies,pii
    fail-on: high
```

### Scheduled Scan (action-scheduled.yml)

```yaml
on:
  schedule:
    - cron: "0 6 * * 1"  # Weekly Monday 06:00 UTC

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm install -g https://github.com/djimit/codeguardian/archive/refs/heads/main.tar.gz
      - run: codeguardian scan --path . --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Maturity Scoring

| Score | Label | Betekenis |
|-------|-------|-----------|
| 5 | Best practice | Geen bevindingen |
| 4 | Goed | Weinig, lage ernst |
| 3 | Basis | Acceptabel |
| 2 | Minimaal | Significante issues |
| 1 | Afwezig | Kritieke problemen |

## Risk Scoring

Elke finding krijgt een risk score (1-100) gebaseerd op:
- Severity (40%)
- Exploitability (20%)
- Exposure (15%)
- Context: test vs productie (15%)
- Recency (10%)

## Compliance Mapping

Elke finding wordt gekoppeld aan:
- **BIO2** — Baseline Informatiebeveiliging Overheid
- **NORA** — Referentie Architectuur
- **AVG** — GDPR
- **NIS2** — Cyberbeveiligingswet

## Architecture

```
src/
  core/
    config.js            # .codeguardian.yml loader
    suppressions.js      # Finding filter engine
    dependency-scanner.js # OSV.dev CVE scanning
    pii-scanner.js       # NL PII pattern matching
    multi-repo.js        # Parallel orchestratie
    maturity.js          # Score berekening
    risk-engine.js       # Risk scoring
    compliance.js        # BIO2/NORA/AVG/NIS2 mapping
    report-formatter.js  # Markdown + JSON output
    sarif.js             # SARIF 2.1.0 output
    pr-comment.js        # PR comment + merge blocking
    pr-review.js         # Line-specific PR comments
    history.js           # JSONL trend tracking
    changed-files.js     # Incremental scan support
    inventory.js         # Asset inventory
    hook.js              # Pre-commit hook installer
    staged-scan.js       # Staged files scanning
    autofix.js           # Auto-fix engine
    auto-pr.js           # Auto PR creation
    init.js              # Setup wizard
    best-practices.js    # Security best practices
    entropy.js           # High-entropy string detection
    supply-chain.js      # Typosquatting + advisory DB
    secret-rotation.js   # Rotation playbooks
  dashboard/
    server.js            # HTTP server
    index.html           # Dashboard UI
  server.js              # API server mode
  index.js               # Public API exports
```

## Testing

```bash
npm test
```

78 unit tests.

## License

MIT

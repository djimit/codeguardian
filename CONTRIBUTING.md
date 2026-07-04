# Contributing

## Checks

Run before opening a pull request:

```bash
npm run lint
npm test
```

For scanner behavior changes, add or update one focused test fixture. Keep
generated reports, `.codeguardian-history.jsonl`, and local scan state out of
commits.

## Pull requests

Keep changes small and evidence-based:
- explain the scanner behavior changed
- include the command used to verify it
- note false-positive or false-negative tradeoffs

Do not include real secrets, customer code, or raw private scan reports.

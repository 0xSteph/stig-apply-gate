# Findings Register review UI

This Next.js app reads `src/data/ledger.json`. Generate that file from the repo root:

```bash
python3 -m findings demo --out web/src/data/ledger.json
npm run dev -- --port 43123 --hostname 0.0.0.0
```

See the root README for what the register does, how a bad export is rejected, and how to dry-run or revert a change.

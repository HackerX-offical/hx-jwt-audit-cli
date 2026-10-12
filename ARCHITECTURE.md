# hx-jwt-audit-cli architecture

Modular security audit engine — **not** a single-file script.

```
src/
  analysis/          # Orchestration & scoring
  core/              # JWT parse/decode
  findings/          # One module per attack class (21 modules)
  reporters/         # json, markdown, sarif, table
  verify/            # HMAC verify, RS→HS confusion, weak wordlist
  types/             # Shared types
  utils/             # b64url, time, pem
  cli.ts             # Commander entry
data/                # Weak HMAC wordlist
tests/               # Unit + fixtures
```

## Extension

Add a file under `src/findings/`, export `module`, register in `findings/registry.ts`.

# hx-jwt-audit-cli

**Modular JWT/JWS security audit** — algorithm policy, claim hygiene, JWK abuse signals,
and verification oracles for authorized app reviews.

## Why this exists

JWT misconfigurations (alg:none, RS→HS confusion, weak HMAC secrets) still compromise
production APIs. This CLI decodes tokens offline, runs a registry of findings, scores
risk, and offers targeted verify/crack probes for controlled assessments. Use only on
tokens you are authorized to analyze.

## Features

- `audit` — Full static analysis with `table`, `json`, `markdown`, or `sarif` output
- `batch` — Token list file → multiple reports
- `verify-hmac` — Check HMAC signature against a supplied secret
- `crack-weak` — Built-in weak-secret wordlist (authorized testing only)
- `confusion-test` — RS/ES→HS confusion probe with a PEM public key
- Exit `2` on high-risk audit score or failed security probes

## Install

```bash
git clone https://github.com/HackerX-offical/hx-jwt-audit-cli.git
cd hx-jwt-audit-cli
npm install
npm run build
npm link   # optional: global hx-jwt
```

## Quick start

```bash
hx-jwt audit eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
hx-jwt audit @token.txt --format json
hx-jwt verify-hmac <token> -s "your-secret"
hx-jwt confusion-test <token> -k public.pem
```

## Output

| Mode                          | Description                                            |
| ----------------------------- | ------------------------------------------------------ |
| `table`                       | Colored findings with risk score (default)             |
| `json` / `markdown` / `sarif` | Machine- and report-friendly formats                   |
| Exit `2`                      | Risk score below threshold or probe indicates weakness |

## Develop

```bash
npm run format
npm run build
npm test
npm run test:integration   # optional live JWKS endpoints
npm run format:check
```

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for module layout and extension points.

## Ethics

Use only on systems and content you are **authorized** to test. See
[SECURITY.md](./SECURITY.md).

## License

Licensed under the [HackerX License](./LICENSE). Redistributions must retain copyright,
license text, and [NOTICE](./NOTICE) attribution per the license terms.

# hx-jwt-audit-cli

**Advanced JWT/JWS audit engine** for API, mobile, and SSO engagements. Goes far beyond
`jwt.io` decode: maps findings to real attack classes (algorithm confusion, JKU/X5U/JWK
abuse, `kid` oracles, claim policy).

## Capabilities

| Module              | What it does in the field                                                                                                           |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Finding engine**  | Scores risk from header/payload; flags `none`, embedded `jwk`, remote `jku`/`x5u`, long `exp`, missing `exp`, privilege claims      |
| **Confusion probe** | Tests whether an RS/ES token verifies as **HS256** using the PEM **public key as HMAC secret** (classic CVE-class misconfiguration) |
| **HMAC verify**     | Confirms guessed secrets against captured tokens during authorized assessments                                                      |
| **Batch mode**      | Audits token dumps from mobile proxies, HAR exports, or log files                                                                   |

## Usage

```bash
hx-jwt audit "eyJhbGciOiJSUzI1NiIs..."
hx-jwt audit @captured-token.txt --json
hx-jwt verify-hmac TOKEN -s "weak-secret"
hx-jwt confusion-test TOKEN -k rsa-public.pem
hx-jwt batch tokens.txt
```

## Ethics

Analyze only tokens you are authorized to test. See [SECURITY.md](./SECURITY.md).

MIT — HackerX Official

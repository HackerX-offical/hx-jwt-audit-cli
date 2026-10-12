import type { AuditReport, DecodedJwt, Finding } from './types.js';

const DANGEROUS_ALGS = new Set(['none', 'None', 'NONE', 'nOnE']);
const SYMMETRIC = new Set(['HS256', 'HS384', 'HS512']);
const ASYMMETRIC = new Set(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']);

function numClaim(v: unknown): number | null {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  return null;
}

export function analyzeJwt(decoded: DecodedJwt, nowSec = Math.floor(Date.now() / 1000)): AuditReport {
  const findings: Finding[] = [];
  const alg = String(decoded.header.alg ?? '');

  if (!alg) {
    findings.push({
      id: 'missing-alg',
      severity: 'critical',
      title: 'Missing alg header',
      detail: 'Algorithm header absent — parsers may accept ambiguous algorithms.',
      cwe: 'CWE-347',
    });
  }

  if (DANGEROUS_ALGS.has(alg) || alg.toLowerCase() === 'none') {
    findings.push({
      id: 'alg-none',
      severity: 'critical',
      title: 'Algorithm "none"',
      detail: 'Token advertises unsigned algorithm — classic auth bypass if verifier accepts it.',
      attack: 'alg-none',
      cwe: 'CWE-347',
    });
  }

  if (decoded.header.jku) {
    findings.push({
      id: 'jku-present',
      severity: 'high',
      title: 'JKU (JSON Web Key Set URL) in header',
      detail: `jku=${String(decoded.header.jku)} — remote key injection if verifier fetches attacker-controlled JWKS.`,
      attack: 'jku-injection',
      cwe: 'CWE-347',
    });
  }

  if (decoded.header.x5u) {
    findings.push({
      id: 'x5u-present',
      severity: 'high',
      title: 'X5U certificate URL in header',
      detail: `x5u=${String(decoded.header.x5u)} — trust chain may be loaded from remote URL.`,
      cwe: 'CWE-347',
    });
  }

  if (decoded.header.jwk) {
    findings.push({
      id: 'embedded-jwk',
      severity: 'high',
      title: 'Embedded JWK in header',
      detail: 'Self-signed key material in header enables algorithm/key confusion attacks.',
      attack: 'jwk-embedded',
      cwe: 'CWE-347',
    });
  }

  if (decoded.header.kid !== undefined) {
    const kid = String(decoded.header.kid);
    if (/['";]|\/\.\.|\\/.test(kid)) {
      findings.push({
        id: 'kid-injection',
        severity: 'high',
        title: 'Suspicious kid value',
        detail: `kid contains metacharacters: ${kid}`,
        attack: 'kid-sqli-path',
      });
    } else {
      findings.push({
        id: 'kid-set',
        severity: 'info',
        title: 'kid header present',
        detail: `kid=${kid} — verify key lookup cannot be influenced (SQL/path traversal).`,
      });
    }
  }

  if (ASYMMETRIC.has(alg)) {
    findings.push({
      id: 'asymmetric-alg',
      severity: 'info',
      title: `Asymmetric algorithm ${alg}`,
      detail: 'Test HS256 confusion if verifier accepts HMAC with public key as secret.',
      attack: 'rs256-to-hs256',
    });
  }

  if (SYMMETRIC.has(alg)) {
    findings.push({
      id: 'symmetric-alg',
      severity: 'medium',
      title: `Symmetric algorithm ${alg}`,
      detail: 'Brute-force / weak secret risk if HMAC key is guessable.',
      attack: 'weak-hmac-secret',
    });
  }

  const exp = numClaim(decoded.payload.exp);
  const nbf = numClaim(decoded.payload.nbf);
  const iat = numClaim(decoded.payload.iat);

  if (exp === null) {
    findings.push({
      id: 'no-exp',
      severity: 'medium',
      title: 'No exp claim',
      detail: 'Token may be valid indefinitely if verifier does not enforce session TTL elsewhere.',
    });
  } else if (exp < nowSec) {
    findings.push({
      id: 'expired',
      severity: 'low',
      title: 'Token expired',
      detail: `exp=${exp} (${new Date(exp * 1000).toISOString()})`,
    });
  } else if (exp - nowSec > 86400 * 365) {
    findings.push({
      id: 'long-exp',
      severity: 'medium',
      title: 'Very long validity',
      detail: `Token valid for >365 days (${Math.floor((exp - nowSec) / 86400)} days remaining).`,
    });
  }

  if (nbf !== null && nbf > nowSec) {
    findings.push({
      id: 'not-yet-valid',
      severity: 'info',
      title: 'nbf in the future',
      detail: `nbf=${nbf}`,
    });
  }

  if (iat !== null && iat > nowSec + 300) {
    findings.push({
      id: 'future-iat',
      severity: 'medium',
      title: 'iat far in future',
      detail: 'Clock skew or token minting anomaly.',
    });
  }

  if (decoded.payload.admin === true || decoded.payload.isAdmin === true) {
    findings.push({
      id: 'priv-claim',
      severity: 'info',
      title: 'Privilege claim in payload',
      detail: 'Sensitive boolean privilege claim present — test horizontal/vertical IDOR with modified claims.',
    });
  }

  const weights = { critical: 40, high: 25, medium: 12, low: 5, info: 0 };
  const penalty = findings.reduce((s, f) => s + weights[f.severity], 0);
  const riskScore = Math.max(0, 100 - penalty);

  return { decoded, findings, riskScore };
}

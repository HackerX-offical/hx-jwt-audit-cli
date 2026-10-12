import { analyzeJwt } from '../src/analysis/engine.js';
import { decodeJwt } from '../src/core/decode.js';
import { FINDING_MODULES } from '../src/findings/registry.js';

const NONE_TOKEN = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';

describe('analyzeJwt engine', () => {
  it('runs all registry modules', () => {
    const r = analyzeJwt(decodeJwt(NONE_TOKEN));
    expect(r.modulesRun.length).toBe(FINDING_MODULES.length);
    expect(r.modulesRun.length).toBeGreaterThan(15);
  });

  it('flags alg none and computes risk score', () => {
    const r = analyzeJwt(decodeJwt(NONE_TOKEN));
    expect(r.findings.some((f) => f.id === 'alg-none')).toBe(true);
    expect(r.riskScore).toBeLessThan(100);
  });

  it('respects injected clock for time-based findings', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ sub: 'x', exp: 1_600_000_000 }),
    ).toString('base64url');
    const r = analyzeJwt(decodeJwt(`${header}.${payload}.sig`), 1_700_000_000);
    expect(r.findings.some((f) => f.id === 'expired')).toBe(true);
  });
});

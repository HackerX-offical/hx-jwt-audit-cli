import { analyzeJwt } from '../src/analysis/engine.js';
import { decodeJwt } from '../src/core/decode.js';

const NONE_TOKEN = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';

describe('analyzeJwt modular engine', () => {
  it('flags alg none', () => {
    const r = analyzeJwt(decodeJwt(NONE_TOKEN));
    expect(r.findings.some((f) => f.id === 'alg-none')).toBe(true);
    expect(r.modulesRun.length).toBeGreaterThan(15);
  });

  it('flags jku header', () => {
    const header = Buffer.from(
      JSON.stringify({ alg: 'RS256', jku: 'https://evil.example/jwks.json' }),
    ).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url');
    const r = analyzeJwt(decodeJwt(`${header}.${payload}.sig`));
    expect(r.findings.some((f) => f.id === 'jku-present')).toBe(true);
  });
});

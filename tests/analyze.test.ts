import { analyzeJwt } from '../src/analyze.js';
import { decodeJwt } from '../src/decode.js';

// eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
const NONE_TOKEN =
  'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';

describe('analyzeJwt', () => {
  it('flags alg none', () => {
    const d = decodeJwt(NONE_TOKEN);
    const r = analyzeJwt(d);
    expect(r.findings.some((f) => f.id === 'alg-none')).toBe(true);
    expect(r.riskScore).toBeLessThan(60);
  });

  it('flags jku header', () => {
    const header = Buffer.from(
      JSON.stringify({ alg: 'RS256', jku: 'https://evil.example/jwks.json' }),
    )
      .toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url');
    const token = `${header}.${payload}.sig`;
    const r = analyzeJwt(decodeJwt(token));
    expect(r.findings.some((f) => f.id === 'jku-present')).toBe(true);
  });
});

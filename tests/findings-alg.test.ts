import { buildContext } from '../src/analysis/context.js';
import { module as algNone } from '../src/findings/alg-none.js';
import { module as algMissing } from '../src/findings/alg-missing.js';
import { module as symmetricAlg } from '../src/findings/symmetric-alg.js';
import { decodeJwt } from '../src/core/decode.js';

const NONE_TOKEN = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';

function token(header: Record<string, unknown>, payload: Record<string, unknown>) {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return decodeJwt(`${h}.${p}.sig`);
}

describe('algorithm finding modules', () => {
  it('alg-none flags none variants', () => {
    const ctx = buildContext(decodeJwt(NONE_TOKEN));
    expect(algNone.run(ctx).some((f) => f.id === 'alg-none')).toBe(true);
  });

  it('alg-missing flags absent alg', () => {
    const ctx = buildContext(token({ typ: 'JWT' }, { sub: 'u' }));
    expect(algMissing.run(ctx).some((f) => f.id === 'missing-alg')).toBe(true);
  });

  it('symmetric-alg flags HS256', () => {
    const ctx = buildContext(token({ alg: 'HS256', typ: 'JWT' }, { sub: 'u' }));
    expect(symmetricAlg.run(ctx).length).toBeGreaterThan(0);
  });
});

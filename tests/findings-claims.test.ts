import { buildContext } from '../src/analysis/context.js';
import { module as expMissing } from '../src/findings/exp-missing.js';
import { module as expExpired } from '../src/findings/exp-expired.js';
import { module as subMissing } from '../src/findings/sub-missing.js';
import { module as jku } from '../src/findings/jku.js';
import { decodeJwt } from '../src/core/decode.js';

function token(header: Record<string, unknown>, payload: Record<string, unknown>) {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return decodeJwt(`${h}.${p}.sig`);
}

describe('claim and header abuse modules', () => {
  const now = 1_700_000_000;

  it('exp-missing when no exp', () => {
    const ctx = buildContext(token({ alg: 'HS256' }, { sub: 'x' }), now);
    expect(expMissing.run(ctx).some((f) => f.id === 'no-exp')).toBe(true);
  });

  it('exp-expired when exp in the past', () => {
    const ctx = buildContext(token({ alg: 'HS256' }, { sub: 'x', exp: now - 60 }), now);
    expect(expExpired.run(ctx).some((f) => f.id === 'expired')).toBe(true);
  });

  it('sub-missing without subject', () => {
    const ctx = buildContext(token({ alg: 'HS256' }, { exp: now + 3600 }), now);
    expect(subMissing.run(ctx).some((f) => f.id === 'sub-missing')).toBe(true);
  });

  it('jku-present when jku header set', () => {
    const ctx = buildContext(
      token({ alg: 'RS256', jku: 'https://evil.example/jwks.json' }, { sub: 'x' }),
      now,
    );
    expect(jku.run(ctx).some((f) => f.id === 'jku-present')).toBe(true);
  });
});

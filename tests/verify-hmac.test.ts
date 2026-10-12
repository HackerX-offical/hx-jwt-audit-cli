import * as jose from 'jose';
import { verifyHmac } from '../src/verify/hmac.js';

describe('verifyHmac', () => {
  it('accepts valid HS256 token', async () => {
    const secret = new TextEncoder().encode('hx-test-secret');
    const token = await new jose.SignJWT({ sub: 'audit' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    const r = await verifyHmac(token, 'hx-test-secret');
    expect(r.valid).toBe(true);
    expect(r.algorithm).toBe('HS256');
  });

  it('rejects wrong secret', async () => {
    const secret = new TextEncoder().encode('right');
    const token = await new jose.SignJWT({ sub: 'x' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    const r = await verifyHmac(token, 'wrong');
    expect(r.valid).toBe(false);
    expect(r.error).toBeDefined();
  });

  it('strips Bearer prefix before verify', async () => {
    const secret = new TextEncoder().encode('bearer-test');
    const token = await new jose.SignJWT({ sub: 'x' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    const r = await verifyHmac(`Bearer ${token}`, 'bearer-test');
    expect(r.valid).toBe(true);
  });
});

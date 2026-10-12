import { b64urlDecode, b64urlEncode } from '../src/utils/b64url.js';

describe('b64url', () => {
  it('round-trips UTF-8 strings', () => {
    const raw = '{"alg":"HS256","typ":"JWT"}';
    expect(b64urlDecode(b64urlEncode(raw))).toBe(raw);
  });

  it('decodes standard JWT header segment', () => {
    const json = b64urlDecode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(JSON.parse(json)).toEqual({ alg: 'HS256', typ: 'JWT' });
  });

  it('pads short segments', () => {
    expect(b64urlDecode('YQ')).toBe('a');
  });
});

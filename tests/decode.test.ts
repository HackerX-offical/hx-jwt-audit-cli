import { decodeJwt, decodeJwtBatch } from '../src/core/decode.js';
import { splitJwt } from '../src/core/segments.js';

const VALID =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

describe('decodeJwt', () => {
  it('decodes header and payload', () => {
    const d = decodeJwt(VALID);
    expect(d.header.alg).toBe('HS256');
    expect(d.payload.sub).toBe('1234567890');
    expect(d.signingInput).toMatch(/^[^.]+\.[^.]+$/);
  });

  it('strips Bearer prefix via splitJwt', () => {
    const [h] = splitJwt(`Bearer ${VALID}`);
    expect(h).toBe(VALID.split('.')[0]);
  });

  it('throws on invalid header JSON', () => {
    expect(() => decodeJwt('!!!.eyJzdWIiOiIxIn0.sig')).toThrow('Invalid JWT header JSON');
  });

  it('throws on wrong segment count', () => {
    expect(() => decodeJwt('only.two')).toThrow('Expected 3 JWT segments');
  });
});

describe('decodeJwtBatch', () => {
  it('skips blanks, comments, and bad lines', () => {
    const batch = decodeJwtBatch(`# comment\n\n${VALID}\nnot-a-jwt\n`);
    expect(batch).toHaveLength(1);
    expect(batch[0].payload.sub).toBe('1234567890');
  });
});

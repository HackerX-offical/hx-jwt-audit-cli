import type { DecodedJwt } from '../types/jwt.js';
import type { JwtContext } from '../types/finding.js';

export function buildContext(
  decoded: DecodedJwt,
  nowSec = Math.floor(Date.now() / 1000),
): JwtContext {
  return {
    header: decoded.header,
    payload: decoded.payload,
    raw: decoded.raw,
    signingInput: decoded.signingInput,
    signature: decoded.signature,
    nowSec,
  };
}

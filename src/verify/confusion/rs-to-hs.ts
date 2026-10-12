import { decodeJwt } from '../../core/decode.js';
import { verifyHmac } from '../hmac.js';
import type { VerifyResult } from '../hmac.js';

export async function probeRsToHs(token: string, publicKeyPem: string): Promise<VerifyResult> {
  const decoded = decodeJwt(token);
  const alg = String(decoded.header.alg ?? '');
  if (!/^(RS|ES|PS)/.test(alg)) {
    return { valid: false, error: 'Token is not asymmetric — confusion probe skipped' };
  }
  return verifyHmac(token, publicKeyPem);
}

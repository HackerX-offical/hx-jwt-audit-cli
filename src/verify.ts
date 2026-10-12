import * as jose from 'jose';
import { decodeJwt } from './decode.js';

export interface VerifyResult {
  valid: boolean;
  algorithm?: string;
  error?: string;
}

export async function verifyHs256(token: string, secret: string): Promise<VerifyResult> {
  try {
    const key = new TextEncoder().encode(secret);
    const { protectedHeader } = await jose.jwtVerify(token.trim().replace(/^Bearer\s+/i, ''), key);
    return { valid: true, algorithm: String(protectedHeader.alg) };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Algorithm confusion probe: verify RS256 token using HMAC with public key bytes as secret */
export async function probeHs256WithPublicKeyPem(
  token: string,
  publicKeyPem: string,
): Promise<VerifyResult> {
  const decoded = decodeJwt(token);
  const alg = String(decoded.header.alg ?? '');
  if (!alg.startsWith('RS') && !alg.startsWith('ES') && !alg.startsWith('PS')) {
    return { valid: false, error: 'Token is not asymmetric — confusion probe skipped' };
  }
  return verifyHs256(token, publicKeyPem);
}

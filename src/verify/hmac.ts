import * as jose from 'jose';

export interface VerifyResult {
  valid: boolean;
  algorithm?: string;
  error?: string;
}

export async function verifyHmac(token: string, secret: string): Promise<VerifyResult> {
  try {
    const key = new TextEncoder().encode(secret);
    const { protectedHeader } = await jose.jwtVerify(token.trim().replace(/^Bearer\s+/i, ''), key);
    return { valid: true, algorithm: String(protectedHeader.alg) };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : String(err) };
  }
}

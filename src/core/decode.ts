import type { DecodedJwt } from '../types/jwt.js';
import { b64urlDecode } from '../utils/b64url.js';
import { splitJwt } from './segments.js';

export function decodeJwt(token: string): DecodedJwt {
  const [h, p, s] = splitJwt(token);
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(b64urlDecode(h)) as Record<string, unknown>;
  } catch {
    throw new Error('Invalid JWT header JSON');
  }
  try {
    payload = JSON.parse(b64urlDecode(p)) as Record<string, unknown>;
  } catch {
    throw new Error('Invalid JWT payload JSON');
  }
  return {
    raw: token.trim(),
    header,
    payload,
    signature: s,
    signingInput: `${h}.${p}`,
  };
}

export function decodeJwtBatch(input: string): DecodedJwt[] {
  const out: DecodedJwt[] = [];
  for (const line of input.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    try {
      out.push(decodeJwt(t));
    } catch {
      /* skip */
    }
  }
  return out;
}

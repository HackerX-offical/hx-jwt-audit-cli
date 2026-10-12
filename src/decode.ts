import type { DecodedJwt } from './types.js';

export function splitJwt(token: string): string[] {
  const t = token.trim().replace(/^Bearer\s+/i, '');
  const parts = t.split('.');
  if (parts.length !== 3) {
    throw new Error(`Expected 3 JWT segments, got ${parts.length}`);
  }
  return parts;
}

function b64urlDecode(segment: string): string {
  const pad = '='.repeat((4 - (segment.length % 4)) % 4);
  const b64 = (segment + pad).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64, 'base64').toString('utf8');
}

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

export function decodeJwtUnsafeBatch(input: string): DecodedJwt[] {
  const lines = input.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const tokens: DecodedJwt[] = [];
  for (const line of lines) {
    if (line.startsWith('#')) continue;
    try {
      tokens.push(decodeJwt(line));
    } catch {
      // skip garbage lines in batch mode
    }
  }
  return tokens;
}

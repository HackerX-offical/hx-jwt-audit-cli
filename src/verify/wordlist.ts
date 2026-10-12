import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyHmac } from './hmac.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

export function loadWeakSecrets(): string[] {
  try {
    const p = join(__dirname, '../../data/weak-secrets.txt');
    return readFileSync(p, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
  } catch {
    return ['secret', 'password', '123456', 'jwt_secret', 'changeme'];
  }
}

export async function crackHmacWeakList(
  token: string,
  secrets: string[],
  concurrency = 8,
): Promise<string | null> {
  let i = 0;
  let found: string | null = null;

  async function worker() {
    while (i < secrets.length && !found) {
      const idx = i++;
      const s = secrets[idx];
      const r = await verifyHmac(token, s);
      if (r.valid) found = s;
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return found;
}

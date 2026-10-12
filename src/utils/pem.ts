import { readFileSync } from 'node:fs';

export function readPemFile(path: string): string {
  const pem = readFileSync(path, 'utf8').trim();
  if (!pem.includes('BEGIN')) {
    throw new Error(`File does not look like PEM: ${path}`);
  }
  return pem;
}

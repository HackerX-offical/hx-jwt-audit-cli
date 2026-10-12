export function splitJwt(token: string): [string, string, string] {
  const t = token.trim().replace(/^Bearer\s+/i, '');
  const parts = t.split('.');
  if (parts.length !== 3) {
    throw new Error(`Expected 3 JWT segments, got ${parts.length}`);
  }
  return [parts[0], parts[1], parts[2]];
}

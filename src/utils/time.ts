export function numClaim(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  return null;
}

export function isoFromEpoch(sec: number): string {
  return new Date(sec * 1000).toISOString();
}

import type { FindingModule } from './types.js';

function looksLikeJwtSegment(v: unknown): boolean {
  return typeof v === 'string' && /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\./.test(v);
}

export const module: FindingModule = {
  id: 'nested-claims',
  run(ctx) {
    const nested: string[] = [];
    for (const [k, v] of Object.entries(ctx.payload)) {
      if (looksLikeJwtSegment(v)) nested.push(k);
      if (typeof v === 'object' && v !== null) {
        for (const [k2, v2] of Object.entries(v as Record<string, unknown>)) {
          if (looksLikeJwtSegment(v2)) nested.push(`${k}.${k2}`);
        }
      }
    }
    if (!nested.length) return [];
    return [
      {
        id: 'nested-jwt-claim',
        severity: 'medium',
        title: 'Nested JWT-like strings in payload',
        detail: `Fields: ${nested.join(', ')} — test nested signature bypass.`,
        attack: 'nested-jwt',
      },
    ];
  },
};

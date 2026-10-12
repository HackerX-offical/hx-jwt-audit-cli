import type { FindingModule } from './types.js';

const SYMMETRIC = new Set(['HS256', 'HS384', 'HS512']);

export const module: FindingModule = {
  id: 'symmetric-alg',
  run(ctx) {
    const alg = String(ctx.header.alg ?? '');
    if (!SYMMETRIC.has(alg)) return [];
    return [
      {
        id: 'symmetric-alg',
        severity: 'medium',
        title: `Symmetric algorithm ${alg}`,
        detail: 'Brute-force / weak secret risk if HMAC key is guessable.',
        attack: 'weak-hmac-secret',
      },
    ];
  },
};

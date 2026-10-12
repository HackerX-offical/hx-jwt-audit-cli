import type { FindingModule } from './types.js';

const ASYMMETRIC = new Set([
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
]);

export const module: FindingModule = {
  id: 'asymmetric-alg',
  run(ctx) {
    const alg = String(ctx.header.alg ?? '');
    if (!ASYMMETRIC.has(alg)) return [];
    return [
      {
        id: 'asymmetric-alg',
        severity: 'info',
        title: `Asymmetric algorithm ${alg}`,
        detail: 'Test HS256 confusion if verifier accepts HMAC with public key as secret.',
        attack: 'rs256-to-hs256',
      },
    ];
  },
};

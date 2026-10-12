import type { FindingModule } from './types.js';
import { numClaim } from '../utils/time.js';

export const module: FindingModule = {
  id: 'exp-missing',
  run(ctx) {
    if (numClaim(ctx.payload.exp) !== null) return [];
    return [
      {
        id: 'no-exp',
        severity: 'medium',
        title: 'No exp claim',
        detail:
          'Token may be valid indefinitely if verifier does not enforce session TTL elsewhere.',
      },
    ];
  },
};

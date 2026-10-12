import type { FindingModule } from './types.js';
import { numClaim } from '../utils/time.js';

export const module: FindingModule = {
  id: 'nbf-future',
  run(ctx) {
    const nbf = numClaim(ctx.payload.nbf);
    if (nbf === null || nbf <= ctx.nowSec) return [];
    return [
      {
        id: 'not-yet-valid',
        severity: 'info',
        title: 'nbf in the future',
        detail: `nbf=${nbf}`,
      },
    ];
  },
};

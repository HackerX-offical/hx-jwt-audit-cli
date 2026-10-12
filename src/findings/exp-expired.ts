import type { FindingModule } from './types.js';
import { isoFromEpoch, numClaim } from '../utils/time.js';

export const module: FindingModule = {
  id: 'exp-expired',
  run(ctx) {
    const exp = numClaim(ctx.payload.exp);
    if (exp === null || exp >= ctx.nowSec) return [];
    return [
      {
        id: 'expired',
        severity: 'low',
        title: 'Token expired',
        detail: `exp=${exp} (${isoFromEpoch(exp)})`,
      },
    ];
  },
};

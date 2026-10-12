import type { FindingModule } from './types.js';
import { numClaim } from '../utils/time.js';

export const module: FindingModule = {
  id: 'exp-long-lived',
  run(ctx) {
    const exp = numClaim(ctx.payload.exp);
    if (exp === null || exp < ctx.nowSec) return [];
    if (exp - ctx.nowSec <= 86400 * 365) return [];
    return [
      {
        id: 'long-exp',
        severity: 'medium',
        title: 'Very long validity',
        detail: `Token valid for >365 days (${Math.floor((exp - ctx.nowSec) / 86400)} days remaining).`,
      },
    ];
  },
};

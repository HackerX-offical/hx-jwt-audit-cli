import type { FindingModule } from './types.js';
import { numClaim } from '../utils/time.js';

export const module: FindingModule = {
  id: 'iat-future',
  run(ctx) {
    const iat = numClaim(ctx.payload.iat);
    if (iat === null || iat <= ctx.nowSec + 300) return [];
    return [
      {
        id: 'future-iat',
        severity: 'medium',
        title: 'iat far in future',
        detail: 'Clock skew or token minting anomaly.',
      },
    ];
  },
};

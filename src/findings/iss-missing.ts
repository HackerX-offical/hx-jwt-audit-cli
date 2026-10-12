import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'iss-missing',
  run(ctx) {
    if (ctx.payload.iss !== undefined) return [];
    return [
      {
        id: 'iss-missing',
        severity: 'info',
        title: 'Missing iss claim',
        detail: 'Issuer not specified — harder to validate token provenance.',
      },
    ];
  },
};

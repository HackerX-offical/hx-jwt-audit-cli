import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'aud-missing',
  run(ctx) {
    if (ctx.payload.aud !== undefined) return [];
    if (!ctx.payload.sub && !ctx.payload.scope) return [];
    return [
      {
        id: 'aud-missing',
        severity: 'low',
        title: 'Missing aud claim',
        detail: 'Audience not bound — token may be replayed across services.',
      },
    ];
  },
};

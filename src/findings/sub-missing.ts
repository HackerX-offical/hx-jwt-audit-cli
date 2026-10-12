import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'sub-missing',
  run(ctx) {
    if (ctx.payload.sub !== undefined) return [];
    return [
      {
        id: 'sub-missing',
        severity: 'medium',
        title: 'Missing sub claim',
        detail: 'No subject identifier — authorization may rely on malleable claims only.',
      },
    ];
  },
};

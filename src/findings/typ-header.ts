import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'typ-header',
  run(ctx) {
    const typ = ctx.header.typ;
    if (typ === undefined) return [];
    if (String(typ).toUpperCase() === 'JWT') return [];
    return [
      {
        id: 'typ-unusual',
        severity: 'info',
        title: 'Unusual typ header',
        detail: `typ=${String(typ)} — confirm library handles non-JWT typ values.`,
      },
    ];
  },
};

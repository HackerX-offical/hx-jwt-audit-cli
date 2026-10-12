import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'x5u',
  run(ctx) {
    if (!ctx.header.x5u) return [];
    return [
      {
        id: 'x5u-present',
        severity: 'high',
        title: 'X5U certificate URL in header',
        detail: `x5u=${String(ctx.header.x5u)} — trust chain may be loaded from remote URL.`,
        cwe: 'CWE-347',
      },
    ];
  },
};

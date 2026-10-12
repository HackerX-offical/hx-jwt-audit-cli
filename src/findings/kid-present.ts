import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'kid-present',
  run(ctx) {
    if (ctx.header.kid === undefined) return [];
    const kid = String(ctx.header.kid);
    if (/['";]|\/\.\.|\\/.test(kid)) return [];
    return [
      {
        id: 'kid-set',
        severity: 'info',
        title: 'kid header present',
        detail: `kid=${kid} — verify key lookup cannot be influenced (SQL/path traversal).`,
      },
    ];
  },
};

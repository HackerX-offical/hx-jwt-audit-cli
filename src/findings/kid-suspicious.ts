import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'kid-suspicious',
  run(ctx) {
    if (ctx.header.kid === undefined) return [];
    const kid = String(ctx.header.kid);
    if (!/['";]|\/\.\.|\\/.test(kid)) return [];
    return [
      {
        id: 'kid-injection',
        severity: 'high',
        title: 'Suspicious kid value',
        detail: `kid contains metacharacters: ${kid}`,
        attack: 'kid-sqli-path',
      },
    ];
  },
};

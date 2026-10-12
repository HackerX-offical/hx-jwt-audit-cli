import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'cty-header',
  run(ctx) {
    if (!ctx.header.cty) return [];
    return [
      {
        id: 'cty-set',
        severity: 'info',
        title: 'Content type header in JWS',
        detail: `cty=${String(ctx.header.cty)} — nested JWT (JWT-in-JWT) attacks may apply.`,
        attack: 'nested-jwt',
      },
    ];
  },
};

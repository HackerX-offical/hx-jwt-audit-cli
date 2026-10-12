import type { FindingModule } from './types.js';

const KEYS = ['admin', 'isAdmin', 'is_admin', 'root', 'superuser', 'role'];

export const module: FindingModule = {
  id: 'privilege-claims',
  run(ctx) {
    const hits = KEYS.filter((k) => ctx.payload[k] === true || ctx.payload[k] === 'admin');
    if (!hits.length) return [];
    return [
      {
        id: 'priv-claim',
        severity: 'info',
        title: 'Privilege claim in payload',
        detail: `Claims present: ${hits.join(', ')} — test IDOR via modified tokens.`,
      },
    ];
  },
};

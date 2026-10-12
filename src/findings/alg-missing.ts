import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'alg-missing',
  run(ctx) {
    const alg = String(ctx.header.alg ?? '');
    if (alg) return [];
    return [
      {
        id: 'missing-alg',
        severity: 'critical',
        title: 'Missing alg header',
        detail: 'Algorithm header absent — parsers may accept ambiguous algorithms.',
        cwe: 'CWE-347',
      },
    ];
  },
};

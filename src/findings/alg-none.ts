import type { FindingModule } from './types.js';

const DANGEROUS = new Set(['none', 'None', 'NONE', 'nOnE']);

export const module: FindingModule = {
  id: 'alg-none',
  run(ctx) {
    const alg = String(ctx.header.alg ?? '');
    if (!DANGEROUS.has(alg) && alg.toLowerCase() !== 'none') return [];
    return [
      {
        id: 'alg-none',
        severity: 'critical',
        title: 'Algorithm "none"',
        detail: 'Token advertises unsigned algorithm — classic auth bypass if verifier accepts it.',
        attack: 'alg-none',
        cwe: 'CWE-347',
        references: [
          'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
        ],
      },
    ];
  },
};

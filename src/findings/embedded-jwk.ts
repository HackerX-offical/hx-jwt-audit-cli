import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'embedded-jwk',
  run(ctx) {
    if (!ctx.header.jwk) return [];
    return [
      {
        id: 'embedded-jwk',
        severity: 'high',
        title: 'Embedded JWK in header',
        detail: 'Self-signed key material in header enables algorithm/key confusion attacks.',
        attack: 'jwk-embedded',
        cwe: 'CWE-347',
      },
    ];
  },
};

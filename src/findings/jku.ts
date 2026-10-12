import type { FindingModule } from './types.js';

export const module: FindingModule = {
  id: 'jku',
  run(ctx) {
    if (!ctx.header.jku) return [];
    return [
      {
        id: 'jku-present',
        severity: 'high',
        title: 'JKU (JSON Web Key Set URL) in header',
        detail: `jku=${String(ctx.header.jku)} — remote key injection if verifier fetches attacker-controlled JWKS.`,
        attack: 'jku-injection',
        cwe: 'CWE-347',
      },
    ];
  },
};

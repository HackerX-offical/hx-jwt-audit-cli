import type { Finding, JwtContext } from '../types/index.js';

export interface FindingModule {
  id: string;
  run(ctx: JwtContext): Finding[];
}

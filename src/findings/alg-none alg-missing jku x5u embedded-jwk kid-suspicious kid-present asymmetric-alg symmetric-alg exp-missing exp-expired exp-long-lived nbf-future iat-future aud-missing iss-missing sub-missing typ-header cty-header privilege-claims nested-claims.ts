import type { FindingModule } from './types.js';
import type { Finding, JwtContext } from '../types/index.js';

export const module: FindingModule = {
  id: 'alg-none alg-missing jku x5u embedded-jwk kid-suspicious kid-present asymmetric-alg symmetric-alg exp-missing exp-expired exp-long-lived nbf-future iat-future aud-missing iss-missing sub-missing typ-header cty-header privilege-claims nested-claims',
  run: runImpl,
};

function runImpl(ctx: JwtContext): Finding[] {
  return [];
}

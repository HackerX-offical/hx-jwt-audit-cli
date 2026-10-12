import type { FindingModule } from './types.js';
import { module as algNone } from './alg-none.js';
import { module as algMissing } from './alg-missing.js';
import { module as jku } from './jku.js';
import { module as x5u } from './x5u.js';
import { module as embeddedJwk } from './embedded-jwk.js';
import { module as kidSuspicious } from './kid-suspicious.js';
import { module as kidPresent } from './kid-present.js';
import { module as asymmetricAlg } from './asymmetric-alg.js';
import { module as symmetricAlg } from './symmetric-alg.js';
import { module as expMissing } from './exp-missing.js';
import { module as expExpired } from './exp-expired.js';
import { module as expLongLived } from './exp-long-lived.js';
import { module as nbfFuture } from './nbf-future.js';
import { module as iatFuture } from './iat-future.js';
import { module as audMissing } from './aud-missing.js';
import { module as issMissing } from './iss-missing.js';
import { module as subMissing } from './sub-missing.js';
import { module as typHeader } from './typ-header.js';
import { module as ctyHeader } from './cty-header.js';
import { module as privilegeClaims } from './privilege-claims.js';
import { module as nestedClaims } from './nested-claims.js';

export const FINDING_MODULES: FindingModule[] = [
  algMissing,
  algNone,
  jku,
  x5u,
  embeddedJwk,
  kidSuspicious,
  kidPresent,
  asymmetricAlg,
  symmetricAlg,
  expMissing,
  expExpired,
  expLongLived,
  nbfFuture,
  iatFuture,
  audMissing,
  issMissing,
  subMissing,
  typHeader,
  ctyHeader,
  privilegeClaims,
  nestedClaims,
];

import type { Finding } from './finding.js';
import type { DecodedJwt } from './jwt.js';

export interface AuditReport {
  decoded: DecodedJwt;
  findings: Finding[];
  riskScore: number;
  modulesRun: string[];
}

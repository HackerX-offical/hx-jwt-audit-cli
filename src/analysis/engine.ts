import { buildContext } from './context.js';
import { scoreFindings } from './scoring.js';
import type { DecodedJwt } from '../types/jwt.js';
import type { AuditReport } from '../types/report.js';
import { FINDING_MODULES } from '../findings/registry.js';

export function analyzeJwt(
  decoded: DecodedJwt,
  nowSec = Math.floor(Date.now() / 1000),
): AuditReport {
  const ctx = buildContext(decoded, nowSec);
  const findings = FINDING_MODULES.flatMap((m) => m.run(ctx));
  const modulesRun = FINDING_MODULES.map((m) => m.id);
  return {
    decoded,
    findings,
    riskScore: scoreFindings(findings),
    modulesRun,
  };
}

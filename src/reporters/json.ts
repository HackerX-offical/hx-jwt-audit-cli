import type { AuditReport } from '../types/report.js';

export function reportJson(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

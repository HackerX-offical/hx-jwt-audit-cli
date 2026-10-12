import type { AuditReport } from '../types/report.js';

export function reportSarif(report: AuditReport): string {
  const sarif = {
    version: '2.1.0',
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: { driver: { name: 'hx-jwt-audit-cli', version: '1.0.0' } },
        results: report.findings.map((f) => ({
          ruleId: f.id,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          message: { text: `${f.title}: ${f.detail}` },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

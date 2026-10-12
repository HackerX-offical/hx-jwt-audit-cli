import type { AuditReport } from '../types/report.js';

export function reportMarkdown(report: AuditReport): string {
  const lines = [
    '# JWT audit report',
    '',
    `**Risk score:** ${report.riskScore}/100`,
    `**Modules:** ${report.modulesRun.length}`,
    '',
    '## Header',
    '```json',
    JSON.stringify(report.decoded.header, null, 2),
    '```',
    '',
    '## Payload',
    '```json',
    JSON.stringify(report.decoded.payload, null, 2),
    '```',
    '',
    '## Findings',
    '',
  ];
  for (const f of report.findings) {
    lines.push(`- **[${f.severity}]** ${f.title} — ${f.detail}`);
    if (f.attack) lines.push(`  - attack: \`${f.attack}\``);
  }
  return lines.join('\n');
}

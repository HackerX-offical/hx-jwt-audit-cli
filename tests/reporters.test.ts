import { reportJson } from '../src/reporters/json.js';
import { reportMarkdown } from '../src/reporters/markdown.js';
import { reportSarif } from '../src/reporters/sarif.js';
import type { AuditReport } from '../src/types/report.js';

const sample: AuditReport = {
  decoded: {
    raw: 'a.b.c',
    header: { alg: 'HS256' },
    payload: { sub: '1' },
    signature: 'c',
    signingInput: 'a.b',
  },
  findings: [
    {
      id: 'test-finding',
      severity: 'high',
      title: 'Test',
      detail: 'detail',
      attack: 'demo',
    },
  ],
  riskScore: 75,
  modulesRun: ['alg-missing'],
};

describe('reporters', () => {
  it('reportJson serializes report', () => {
    const parsed = JSON.parse(reportJson(sample)) as AuditReport;
    expect(parsed.riskScore).toBe(75);
    expect(parsed.findings[0].id).toBe('test-finding');
  });

  it('reportMarkdown includes score and findings', () => {
    const md = reportMarkdown(sample);
    expect(md).toContain('75/100');
    expect(md).toContain('Test');
    expect(md).toContain('demo');
  });

  it('reportSarif maps severities to levels', () => {
    const sarif = JSON.parse(reportSarif(sample)) as {
      runs: Array<{ results: Array<{ level: string; ruleId: string }> }>;
    };
    expect(sarif.runs[0].results[0].ruleId).toBe('test-finding');
    expect(sarif.runs[0].results[0].level).toBe('error');
  });
});

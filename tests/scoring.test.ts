import { scoreFindings } from '../src/analysis/scoring.js';
import type { Finding } from '../src/types/finding.js';

describe('scoreFindings', () => {
  it('returns 100 with no findings', () => {
    expect(scoreFindings([])).toBe(100);
  });

  it('never goes below zero', () => {
    const many: Finding[] = Array.from({ length: 10 }, (_, i) => ({
      id: `f-${i}`,
      severity: 'critical',
      title: 't',
      detail: 'd',
    }));
    expect(scoreFindings(many)).toBe(0);
  });

  it('applies severity weights', () => {
    const low: Finding = { id: 'a', severity: 'low', title: 't', detail: 'd' };
    const high: Finding = { id: 'b', severity: 'high', title: 't', detail: 'd' };
    expect(scoreFindings([low])).toBe(95);
    expect(scoreFindings([high])).toBe(75);
  });
});

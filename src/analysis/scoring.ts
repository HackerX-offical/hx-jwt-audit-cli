import type { Finding } from '../types/finding.js';

const WEIGHTS: Record<Finding['severity'], number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
  info: 0,
};

export function scoreFindings(findings: Finding[]): number {
  const penalty = findings.reduce((s, f) => s + WEIGHTS[f.severity], 0);
  return Math.max(0, 100 - penalty);
}

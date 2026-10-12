export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  cwe?: string;
  attack?: string;
  references?: string[];
}

export interface JwtContext {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  raw: string;
  signingInput: string;
  signature: string;
  nowSec: number;
}

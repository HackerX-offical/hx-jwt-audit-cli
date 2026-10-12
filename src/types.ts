export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  cwe?: string;
  attack?: string;
}

export interface DecodedJwt {
  raw: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  signingInput: string;
}

export interface AuditReport {
  decoded: DecodedJwt;
  findings: Finding[];
  riskScore: number;
}

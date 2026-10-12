import chalk from 'chalk';
import type { AuditReport } from '../types/report.js';

export function printTable(report: AuditReport): void {
  console.log(chalk.bold('Header'), JSON.stringify(report.decoded.header, null, 2));
  console.log(chalk.bold('\nPayload'), JSON.stringify(report.decoded.payload, null, 2));
  console.log(
    chalk.bold(`\nRisk score: ${report.riskScore}/100 (${report.modulesRun.length} modules)\n`),
  );
  for (const f of report.findings) {
    const color =
      f.severity === 'critical' || f.severity === 'high'
        ? chalk.red
        : f.severity === 'medium'
          ? chalk.yellow
          : chalk.dim;
    console.log(color(`[${f.severity}] ${f.title}`));
    console.log(`  ${f.detail}`);
  }
}

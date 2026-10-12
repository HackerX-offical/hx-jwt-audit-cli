#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { analyzeJwt } from './analyze.js';
import { decodeJwt, decodeJwtUnsafeBatch } from './decode.js';
import { probeHs256WithPublicKeyPem, verifyHs256 } from './verify.js';

const program = new Command();
program.name('hx-jwt').description('Advanced JWT/JWS security audit CLI').version('1.0.0');

program
  .command('audit')
  .description('Decode and run full security finding engine on a JWT')
  .argument('<token>', 'JWT string or @file path')
  .option('--json', 'JSON report')
  .action((tokenArg: string, opts: { json?: boolean }) => {
    const token = tokenArg.startsWith('@')
      ? readFileSync(tokenArg.slice(1), 'utf8').trim()
      : tokenArg;
    const decoded = decodeJwt(token);
    const report = analyzeJwt(decoded);
    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    console.log(chalk.bold('Header'), JSON.stringify(report.decoded.header, null, 2));
    console.log(chalk.bold('\nPayload'), JSON.stringify(report.decoded.payload, null, 2));
    console.log(chalk.bold(`\nRisk score: ${report.riskScore}/100\n`));
    for (const f of report.findings) {
      const color =
        f.severity === 'critical' || f.severity === 'high'
          ? chalk.red
          : f.severity === 'medium'
            ? chalk.yellow
            : chalk.dim;
      console.log(color(`[${f.severity}] ${f.title}`));
      console.log(`  ${f.detail}`);
      if (f.attack) console.log(chalk.dim(`  attack: ${f.attack}`));
    }
    process.exit(report.riskScore < 50 ? 2 : 0);
  });

program
  .command('batch')
  .description('Audit multiple tokens (one per line) from a file')
  .argument('<path>', 'token list file')
  .option('--json', 'JSON array output')
  .action((path: string, opts: { json?: boolean }) => {
    const content = readFileSync(path, 'utf8');
    const tokens = decodeJwtUnsafeBatch(content);
    const reports = tokens.map((t) => analyzeJwt(t));
    if (opts.json) {
      console.log(JSON.stringify(reports, null, 2));
      return;
    }
    reports.forEach((r, i) => {
      console.log(chalk.bold(`--- Token ${i + 1} risk ${r.riskScore} ---`));
      r.findings
        .filter((f) => f.severity !== 'info')
        .forEach((f) => console.log(`[${f.severity}] ${f.title}`));
    });
  });

program
  .command('verify-hmac')
  .description('Verify HS* signature with a shared secret')
  .argument('<token>', 'JWT')
  .requiredOption('-s, --secret <secret>', 'HMAC secret')
  .action(async (token: string, opts: { secret: string }) => {
    const r = await verifyHs256(token, opts.secret);
    console.log(r.valid ? chalk.green('VALID') : chalk.red('INVALID'));
    if (r.error) console.log(r.error);
    process.exit(r.valid ? 0 : 2);
  });

program
  .command('confusion-test')
  .description('Test RS/ES token verified as HS256 using PEM public key as HMAC secret (auth bypass class)')
  .argument('<token>', 'JWT')
  .requiredOption('-k, --public-key <path>', 'PEM public key file')
  .action(async (token: string, opts: { publicKey: string }) => {
    const pem = readFileSync(opts.publicKey, 'utf8');
    const r = await probeHs256WithPublicKeyPem(token, pem);
    if (r.valid) {
      console.log(chalk.red.bold('VULNERABLE: token verifies with HMAC using public key bytes'));
      process.exit(2);
    }
    console.log(chalk.green('Not vulnerable to this confusion probe'));
    if (r.error) console.log(chalk.dim(r.error));
  });

program.parse();

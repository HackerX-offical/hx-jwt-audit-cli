#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { decodeJwt, decodeJwtBatch } from './core/decode.js';
import { analyzeJwt } from './analysis/engine.js';
import { reportJson } from './reporters/json.js';
import { reportMarkdown } from './reporters/markdown.js';
import { reportSarif } from './reporters/sarif.js';
import { printTable } from './reporters/table.js';
import { verifyHmac } from './verify/hmac.js';
import { probeRsToHs } from './verify/confusion/rs-to-hs.js';
import { crackHmacWeakList, loadWeakSecrets } from './verify/wordlist.js';
import { readPemFile } from './utils/pem.js';

const program = new Command();
program.name('hx-jwt').description('Advanced modular JWT/JWS security audit CLI').version('1.1.0');

function loadToken(arg: string): string {
  return arg.startsWith('@') ? readFileSync(arg.slice(1), 'utf8').trim() : arg;
}

program
  .command('audit')
  .argument('<token>', 'JWT or @file')
  .option('--format <fmt>', 'json|markdown|sarif|table', 'table')
  .action((tokenArg: string, opts: { format: string }) => {
    const report = analyzeJwt(decodeJwt(loadToken(tokenArg)));
    switch (opts.format) {
      case 'json':
        console.log(reportJson(report));
        break;
      case 'markdown':
        console.log(reportMarkdown(report));
        break;
      case 'sarif':
        console.log(reportSarif(report));
        break;
      default:
        printTable(report);
    }
    process.exit(report.riskScore < 50 ? 2 : 0);
  });

program
  .command('batch')
  .argument('<path>', 'token list')
  .option('--format <fmt>', 'json|markdown', 'json')
  .action((path: string, opts: { format: string }) => {
    const tokens = decodeJwtBatch(readFileSync(path, 'utf8'));
    const reports = tokens.map((t) => analyzeJwt(t));
    console.log(
      opts.format === 'markdown'
        ? reports.map(reportMarkdown).join('\n---\n')
        : JSON.stringify(reports, null, 2),
    );
  });

program
  .command('verify-hmac')
  .argument('<token>', 'JWT')
  .requiredOption('-s, --secret <secret>', 'HMAC secret')
  .action(async (token: string, opts: { secret: string }) => {
    const r = await verifyHmac(token, opts.secret);
    console.log(r.valid ? chalk.green('VALID') : chalk.red('INVALID'));
    if (r.error) console.log(r.error);
    process.exit(r.valid ? 0 : 2);
  });

program
  .command('crack-weak')
  .description('Try built-in weak HMAC secret wordlist (authorized testing only)')
  .argument('<token>', 'JWT')
  .action(async (token: string) => {
    const hit = await crackHmacWeakList(token, loadWeakSecrets());
    if (hit) {
      console.log(chalk.red(`Weak secret found: ${hit}`));
      process.exit(2);
    }
    console.log(chalk.green('No match in weak list'));
  });

program
  .command('confusion-test')
  .argument('<token>', 'JWT')
  .requiredOption('-k, --public-key <path>', 'PEM public key')
  .action(async (token: string, opts: { publicKey: string }) => {
    const r = await probeRsToHs(token, readPemFile(opts.publicKey));
    if (r.valid) {
      console.log(chalk.red.bold('VULNERABLE: RS/ES verified as HMAC with public key'));
      process.exit(2);
    }
    console.log(chalk.green('Not vulnerable to RS→HS probe'));
    if (r.error) console.log(chalk.dim(r.error));
  });

program.parse();

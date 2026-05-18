'use strict';

/** Regenerate docs/ABLATION_STUDY.md from test/ablation/results/*.json without re-running scenarios. */
const fs = require('fs');
const path = require('path');
const { CONFIGS } = require('./configs');

const ROOT = path.resolve(__dirname, '../..');
const RESULTS_DIR = path.join(__dirname, 'results');
const REPORT_PATH = path.join(ROOT, 'docs', 'ABLATION_STUDY.md');

// Reuse report builder from ablation-study.js
const { buildReport } = require('../ablation-study');

const results = CONFIGS.map((cfg) => {
  const p = path.join(RESULTS_DIR, `${cfg.id}.json`);
  if (!fs.existsSync(p)) throw new Error(`Missing ${p}`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
});

for (const r of results) {
  if (r.skipped || !r.scenarios) continue;
  for (const s of r.scenarios) {
    s.securityRegression =
      s.category === 'attack'
      && s.baselineExpected === 'DENY'
      && (s.decision === 'ALLOW' || s.decision === 'MFA_REQUIRED');
  }
  r.summary.securityRegressions = r.scenarios.filter((s) => s.securityRegression).length;
}

const baseline = results.find((r) => r.configId === 'baseline');
const report = buildReport(results, baseline);
fs.writeFileSync(REPORT_PATH, report);
console.log('Updated', REPORT_PATH);

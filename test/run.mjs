#!/usr/bin/env node
/**
 * Regression suite. Run: node test/run.mjs
 *
 * The assertion that matters is the conformant fixture: a repository that has
 * done the work must come back with exactly one finding, and it must be the
 * one no tool can answer. A checker that still complains at a repository which
 * has answered every obligation is worse than no checker, because the person
 * reading it has no way to tell which of its findings are real.
 *
 * Every run pins --today, so a date-sensitive rule cannot start failing in
 * eight months for reasons that have nothing to do with the code.
 */

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const detector = join(here, '..', 'skills', 'cra-ready', 'scripts', 'detect.mjs');
const TODAY = '2026-09-19';

function scan(fixture, args = []) {
  const out = execFileSync(
    process.execPath,
    [detector, join(here, 'fixtures', fixture), '--json', '--today', TODAY, ...args],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  return JSON.parse(out);
}

const failures = [];
const check = (label, actual, expected) => {
  const ok = actual === expected;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}: ${actual}${ok ? '' : ` (expected ${expected})`}`);
  if (!ok) failures.push(label);
};
const has = (result, rule) => result.findings.some((f) => f.rule === rule);

console.log('\ncra-ready regression suite\n');

const conformant = scan('conformant');
const bare = scan('bare');
const partial = scan('partial');

// --- a repository that has done the work must come back quiet ---------------
console.log('a conformant repository must produce only what no tool can decide:');
check('conformant findings', conformant.total, 1);
check('conformant remaining rule', conformant.findings[0]?.rule, 'scope-undetermined');
check('conformant missing', conformant.counts.missing, 0);
check('conformant incomplete', conformant.counts.incomplete, 0);
check('conformant stale', conformant.counts.stale, 0);

// --- absences must all be caught -------------------------------------------
console.log('\nevery absence rule must fire on a repository with nothing:');
for (const rule of [
  'sbom-missing', 'cvd-policy-missing', 'reporting-procedure-missing',
  'support-period-missing', 'manufacturer-contact-missing',
  'conformity-declaration-missing', 'update-instructions-missing',
  'advisory-channel-undeclared', 'scope-undetermined',
]) check(rule, has(bare, rule) ? 1 : 0, 1);

// --- artefacts that exist but are wrong ------------------------------------
console.log('\nan artefact that exists but is wrong must not read as answered:');
for (const rule of [
  'sbom-missing-dependencies', 'sbom-no-supplier', 'cvd-no-contact',
  'cvd-no-timeline', 'security-txt-expired', 'support-period-short',
]) check(rule, has(partial, rule) ? 1 : 0, 1);

// The partial fixture documents the Article 14 clock in docs/, not SECURITY.md.
// If this ever fails, the user-documentation union stopped reading docs/.
console.log('\nevidence is read wherever it legitimately lives:');
check('Article 14 procedure found outside SECURITY.md', has(partial, 'reporting-procedure-missing') ? 1 : 0, 0);

// --- the two false positives found during validation, locked shut -----------
// Both came out of running against real repositories, and both would have made
// the tool wrong rather than merely noisy.
console.log('\nfalse positives found in validation must stay fixed:');
// cosign: test/testdata/bom-go-mod.cyclonedx.json was judged as the project SBOM.
check('an SBOM under test/ is not the project SBOM', has(bare, 'sbom-missing') ? 1 : 0, 1);
check('...and is not audited as one', has(bare, 'sbom-missing-dependencies') ? 1 : 0, 0);
// cosign: a securityscorecards.dev badge URL was read as a reporting channel.
check('a scorecard badge is not a reporting contact', has(partial, 'cvd-no-contact') ? 1 : 0, 1);

// --- every finding must be traceable to the regulation ----------------------
console.log('\nevery finding must carry its citation and its phase-in date:');
const all = [...conformant.findings, ...bare.findings, ...partial.findings];
check('findings with no legal reference', all.filter((f) => !f.ref).length, 0);
check('findings with no obligation name', all.filter((f) => !f.obligation).length, 0);
const PHASE_IN = new Set(['2026-09-11', '2027-12-11']);
check('findings with an invented phase-in date', all.filter((f) => !PHASE_IN.has(f.applies_from)).length, 0);

// The Article 14 reporting obligation is the only one already in force. If a
// rule ever claims more than that is enforceable today, the claim is wrong.
console.log('\nonly the Article 14 obligation is in force today:');
check('rules enforceable today, bare repository', bare.enforceable_now, 1);
check('...and it is the reporting one',
  bare.findings.filter((f) => f.applies_from <= TODAY).every((f) => f.rule === 'reporting-procedure-missing') ? 1 : 0, 1);

// --- the tool must never tell anyone they are compliant ---------------------
// Same rule as its sibling eaa-audit: no automated check can establish
// conformity, and writing that it does is a liability in someone's repository.
console.log('\nthe tool must never assert conformity:');
const prose = JSON.stringify(all.map((f) => [f.message, f.fix])) + conformant.coverage;
check('claims of compliance in the output', (prose.match(/\b(is|are|fully|now|becomes?)\s+(compliant|conformant)\b/gi) ?? []).length, 0);

// --- determinism ------------------------------------------------------------
console.log('\nthe same repository must produce the same report:');
check('two runs agree', JSON.stringify(scan('partial')) === JSON.stringify(partial) ? 1 : 0, 1);

// --- the README must not overstate what ships -------------------------------
console.log('\nthe README rule count must match the rules that exist:');
const detectorSrc = readFileSync(detector, 'utf8');
const ruleCount = new Set([...detectorSrc.matchAll(/rule: '([a-z0-9-]+)'/g)].map((m) => m[1])).size;
const readme = readFileSync(join(here, '..', 'README.md'), 'utf8');
const claimed = readme.match(/(\d+)\*{0,2} checks\*{0,2} across/);
check('rules defined in detect.mjs', ruleCount, 20);
check('rule count claimed in README', claimed ? Number(claimed[1]) : -1, ruleCount);

// --- a call to action must lead somewhere that takes money ------------------
// Traffic sent to a page with no working checkout is traffic thrown away. The
// sibling product shipped a README whose Pro section existed before the
// checkout did; the rule that came out of it is that the button goes in when
// the checkout exists, not before. This asserts it instead of remembering it.
console.log('\na purchase link must be a working checkout:');
const cta = /\[Get cra-ready Pro/.test(readme);
const checkout = /https:\/\/(buy\.polar\.sh|polar\.sh\/[^)\s]*\/)/.test(readme);
check('no call to action without a checkout URL', cta && !checkout ? 1 : 0, 0);

// --- the npm package must be coherent with the repo -------------------------
console.log('\nthe npm package must be coherent with the repo:');
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
const plugin = JSON.parse(readFileSync(join(here, '..', '.claude-plugin', 'plugin.json'), 'utf8'));
const binPath = join(here, '..', pkg.bin['cra-ready'] ?? '');
check('bin target exists', existsSync(binPath) ? 1 : 0, 1);
check('bin target is the detector', binPath === detector ? 1 : 0, 1);
check('package version matches plugin manifest', pkg.version === plugin.version ? 1 : 0, 1);
check('package license matches plugin manifest', pkg.license === plugin.license ? 1 : 0, 1);

// --- a missing directory must be an error, not an empty clean report --------
console.log('\na missing directory must fail loudly:');
let exitCode = 0;
try {
  execFileSync(process.execPath, [detector, join(here, 'fixtures', 'does-not-exist'), '--json'],
    { encoding: 'utf8', stdio: 'pipe' });
} catch (err) { exitCode = err.status; }
check('exit code on a missing directory', exitCode, 2);

console.log(failures.length ? `\n${failures.length} FAILED\n` : '\nall green\n');
process.exit(failures.length ? 1 : 0);

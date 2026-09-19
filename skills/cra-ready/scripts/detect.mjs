#!/usr/bin/env node
/**
 * cra-ready - EU Cyber Resilience Act (Regulation (EU) 2024/2847) evidence check
 *
 * Zero dependencies. Node 18+.
 *   node detect.mjs [dir] [--json] [--today YYYY-MM-DD] [--max N]
 *
 * Checks the obligations that leave EVIDENCE IN A REPOSITORY: the vulnerability
 * handling requirements of Annex I Part II, the user information of Annex II,
 * and readiness for the Article 14 reporting clock. It does not assess the
 * product properties of Annex I Part I: those are a risk assessment, and no
 * repository scan can stand in for one.
 *
 * Built for PRECISION over coverage, same as its sibling eaa-audit: in a
 * compliance report a false positive costs more than a missed finding earns.
 * Where the repository cannot decide, the finding is "review", never "missing".
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, sep, basename, extname } from 'node:path';

// ---------------------------------------------------------------- config

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit',
  'coverage', 'vendor', '.cache', '.output', 'target', '__pycache__', '.venv',
  'venv', '.tox', '.gradle', '.idea', '.vscode', 'bower_components', '.pnpm-store',
]);

// A repository index is cheap but not free. These caps keep a monorepo honest.
const MAX_FILES = 40_000;
const MAX_DEPTH = 12;
const MAX_READ_BYTES = 4_000_000;

const SEVERITY = { missing: 0, incomplete: 1, stale: 2, review: 3 };
const LABEL = {
  missing: 'MISSING', incomplete: 'INCOMPLETE', stale: 'STALE', review: 'NEEDS REVIEW',
};

// Phase-in dates, Article 71. Only these two matter to a manufacturer:
// Chapter IV (11 June 2026) binds conformity assessment bodies, not products.
const FROM_REPORTING = '2026-09-11';   // Article 14 reporting obligations
const FROM_FULL = '2027-12-11';        // everything else

/**
 * Domains that mean "I have not filled this in yet". Two separate cases: the
 * TLDs RFC 2606 reserves for documentation, which are never a real contact
 * whatever the label in front of them, and the handful of second-level names
 * every template ships with.
 */
const RESERVED_TLD = /\.(invalid|test|localhost|example)$/i;
const PLACEHOLDER_DOMAINS = /^(example|yourdomain|yourcompany|your-company|domain|mydomain|company|email|acme|foo|bar|baz|changeme|placeholder|todo)\.(com|org|net|io|eu|dev|co|local)$/i;

const isPlaceholderDomain = (d) => RESERVED_TLD.test(d) || PLACEHOLDER_DOMAINS.test(d);

/**
 * A URL counts as a reporting channel only if its path says so. Matching any
 * URL containing "security" reads a securityscorecards.dev badge as a place to
 * report a vulnerability, which would suppress a true `cvd-no-contact` finding
 * on a repository whose only security-shaped link is a status badge.
 */
const CONTACT_URL = new RegExp(
  'https?://(?:' +
    '(?:www\\.)?(?:hackerone|bugcrowd|intigriti|yeswehack|openbugbounty)\\.com/[^\\s<>()\\]]+' +
    '|[^\\s<>()\\]]*/security/(?:advisories|policy)[^\\s<>()\\]]*' +
    '|[^\\s<>()\\]]*/(?:\\.well-known/security\\.txt|SECURITY\\.md)' +
    '|[^\\s<>()\\]]*/(?:report[-_ ]?a[-_ ]?vulnerability|responsible[-_ ]?disclosure|vulnerability[-_ ]?disclosure|security[-_ ]?policy|report[-_ ]?vulnerability)[^\\s<>()\\]]*' +
  ')', 'i');
const BADGE_HOST = /(shields\.io|badgen\.net|badge\.fury|securityscorecards\.dev\/[^\s]*badge|img\.)/i;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

/**
 * Paths that are not part of the shipped product: test data, fixtures, demos,
 * example applications. Nothing here is evidence about the product, and reading
 * it as evidence is the sharpest false-positive class this tool has. It cost
 * two real findings during validation: cosign's `test/testdata/bom-go-mod.
 * cyclonedx.json` was judged as the project's SBOM and declared empty, and
 * express was reported as shipping a website because of an index.html under
 * `test/fixtures/`.
 */
const NOT_SHIPPED = /(^|\/)(tests?|testdata|__tests__|__fixtures__|fixtures?|spec|specs|e2e|demos?|examples?|samples?|benchmarks?|playground|sandbox|mocks?)(\/|$)/i;

const isShipped = (rel) => !NOT_SHIPPED.test(rel);

// ------------------------------------------------------------- repo index

function indexRepo(root) {
  const files = [];
  const walk = (dir, depth) => {
    if (depth > MAX_DEPTH || files.length >= MAX_FILES) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        files.push(relative(root, full).split(sep).join('/'));
      }
    }
  };
  walk(root, 0);
  return files;
}

function read(root, rel) {
  try {
    const full = join(root, rel.split('/').join(sep));
    const st = statSync(full);
    if (!st.isFile() || st.size > MAX_READ_BYTES) return null;
    return readFileSync(full, 'utf8');
  } catch { return null; }
}

/** First indexed path matching a predicate, preferring the shallowest. */
function locate(index, pred) {
  let best = null;
  let bestDepth = Infinity;
  for (const rel of index) {
    if (!pred(rel)) continue;
    const depth = rel.split('/').length;
    if (depth < bestDepth) { best = rel; bestDepth = depth; }
  }
  return best;
}

function lineOf(src, needle) {
  const idx = src.indexOf(needle);
  if (idx === -1) return null;
  return src.slice(0, idx).split('\n').length;
}

// --------------------------------------------------------------- helpers

function realContacts(text) {
  const out = [];
  for (const m of text.matchAll(EMAIL)) {
    const addr = m[0];
    const domain = addr.slice(addr.indexOf('@') + 1);
    if (isPlaceholderDomain(domain)) continue;
    // "@example" style handles inside code fences are still emails; the
    // placeholder filter above is the only thing standing between a real
    // contact and a template nobody edited.
    out.push(addr);
  }
  const url = text.match(CONTACT_URL);
  if (url && !BADGE_HOST.test(url[0])) out.push(url[0]);
  return out;
}

/** A stated duration: "within 72 hours", "5 business days", "90 days". */
const DURATION = /\b\d{1,3}\s*(?:business\s+|working\s+|calendar\s+)?(hours?|hrs?|days?|weeks?|months?)\b/i;

/** Dates we can read out of prose without guessing. */
function extractDate(text) {
  const iso = text.match(/\b(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b/);
  if (iso) return iso[0];
  const MONTHS = {
    january: '01', february: '02', march: '03', april: '04', may: '05', june: '06',
    july: '07', august: '08', september: '09', october: '10', november: '11', december: '12',
  };
  const named = text.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20\d{2})\b/i);
  if (named) return `${named[2]}-${MONTHS[named[1].toLowerCase()]}-01`;
  return null;
}

function addYears(isoDate, years) {
  const [y, m, d] = isoDate.split('-').map(Number);
  return `${String(y + years).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

function prettyDate(iso) {
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const [y, m, d] = iso.split('-');
  return `${Number(d)} ${MONTHS[Number(m) - 1]} ${y}`;
}

// ------------------------------------------------------- manifest parsing

/**
 * Top-level dependencies, per ecosystem. Deliberately NOT dev dependencies:
 * Annex I Part II(1) is about the components contained in the product, and a
 * test runner is not shipped to the user. Including them would produce a large
 * class of findings that are wrong on the law, not merely noisy.
 */
function topLevelDependencies(root, index) {
  const deps = [];
  const add = (name, ecosystem, source) => {
    const clean = String(name).trim();
    if (clean) deps.push({ name: clean, ecosystem, source });
  };

  const pkgPath = index.includes('package.json') ? 'package.json' : null;
  if (pkgPath) {
    const raw = read(root, pkgPath);
    try {
      const pkg = JSON.parse(raw);
      for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
        for (const name of Object.keys(pkg[field] ?? {})) add(name, 'npm', pkgPath);
      }
    } catch { /* an unparseable manifest is not our finding to make */ }
  }

  const pyproject = index.includes('pyproject.toml') ? 'pyproject.toml' : null;
  if (pyproject) {
    const raw = read(root, pyproject) ?? '';
    // PEP 621: dependencies = ["requests>=2", ...]
    const pep621 = raw.match(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m);
    if (pep621) {
      for (const m of pep621[1].matchAll(/["']\s*([A-Za-z0-9._-]+)/g)) add(m[1], 'pypi', pyproject);
    }
    // Poetry: [tool.poetry.dependencies] followed by name = "^1.0"
    const poetry = raw.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?=\n\[|$)/);
    if (poetry) {
      for (const m of poetry[1].matchAll(/^\s*([A-Za-z0-9._-]+)\s*=/gm)) {
        if (m[1].toLowerCase() !== 'python') add(m[1], 'pypi', pyproject);
      }
    }
  }

  const reqs = index.includes('requirements.txt') ? 'requirements.txt' : null;
  if (reqs) {
    const raw = read(root, reqs) ?? '';
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#') || t.startsWith('-')) continue;
      const m = t.match(/^([A-Za-z0-9._-]+)/);
      if (m) add(m[1], 'pypi', reqs);
    }
  }

  const cargo = index.includes('Cargo.toml') ? 'Cargo.toml' : null;
  if (cargo) {
    const raw = read(root, cargo) ?? '';
    const block = raw.match(/^\[dependencies\]([\s\S]*?)(?=\n\[|$)/m);
    if (block) {
      for (const m of block[1].matchAll(/^\s*([A-Za-z0-9._-]+)\s*=/gm)) add(m[1], 'cargo', cargo);
    }
  }

  const gomod = index.includes('go.mod') ? 'go.mod' : null;
  if (gomod) {
    const raw = read(root, gomod) ?? '';
    for (const line of raw.split('\n')) {
      if (/\/\/\s*indirect/.test(line)) continue;           // transitive, not top-level
      const m = line.match(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+v/i);
      if (m) add(m[1], 'golang', gomod);
    }
  }

  const composer = index.includes('composer.json') ? 'composer.json' : null;
  if (composer) {
    const raw = read(root, composer);
    try {
      const json = JSON.parse(raw);
      for (const name of Object.keys(json.require ?? {})) {
        if (name === 'php' || name.startsWith('ext-')) continue;
        add(name, 'composer', composer);
      }
    } catch { /* ignore */ }
  }

  // Deduplicate on ecosystem+name: a name can legitimately repeat across files.
  const seen = new Set();
  return deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ----------------------------------------------------------- SBOM parsing

const SBOM_NAME = /(^|\/)(sbom|bom)([._-].*)?\.(json|xml|spdx)$|\.(cdx|spdx)\.(json|xml)$|\.spdx$/i;

function looksLikeSbom(rel) {
  const base = basename(rel).toLowerCase();
  if (SKIP_DIRS.has(rel.split('/')[0])) return false;
  return SBOM_NAME.test(rel) || base === 'sbom.json' || base === 'bom.json' ||
    base === 'sbom.spdx.json' || base.endsWith('.cdx.json') || base.endsWith('.spdx.json');
}

/**
 * Returns { format, components: [names], supplier: bool } or null when the file
 * is not a machine-readable SBOM we recognise.
 */
function parseSbom(text) {
  const trimmed = text.trimStart();

  if (trimmed.startsWith('{')) {
    let json;
    try { json = JSON.parse(text); } catch { return null; }

    if (json.bomFormat === 'CycloneDX' || Array.isArray(json.components)) {
      const components = (json.components ?? []).flatMap(flattenCycloneDX);
      const meta = json.metadata ?? {};
      const supplier = Boolean(
        meta.supplier?.name || (Array.isArray(meta.authors) && meta.authors.length) ||
        meta.manufacture?.name || meta.manufacturer?.name || meta.component?.supplier?.name,
      );
      return { format: `CycloneDX ${json.specVersion ?? '?'}`, components, supplier };
    }

    if (json.spdxVersion || Array.isArray(json.packages)) {
      const components = (json.packages ?? []).map((p) => ({
        name: p.name ?? '', purl: (p.externalRefs ?? []).find((r) => r.referenceType === 'purl')?.referenceLocator ?? '',
      }));
      const supplier = (json.packages ?? []).some((p) => p.supplier && p.supplier !== 'NOASSERTION') ||
        Boolean(json.creationInfo?.creators?.some((c) => /^(Organization|Person):/i.test(c)));
      return { format: `SPDX ${json.spdxVersion ?? '?'}`, components, supplier };
    }
    return null;
  }

  if (/^\s*<\?xml|^\s*<bom/i.test(text)) {
    const components = [...text.matchAll(/<component\b[\s\S]*?<\/component>/gi)].map((block) => ({
      name: (block[0].match(/<name>([^<]*)<\/name>/i) ?? [, ''])[1],
      purl: (block[0].match(/<purl>([^<]*)<\/purl>/i) ?? [, ''])[1],
    }));
    if (!components.length && !/<bom/i.test(text)) return null;
    const supplier = /<supplier>|<manufacture>|<author>/i.test(text);
    return { format: 'CycloneDX XML', components, supplier };
  }

  if (/^SPDXVersion:/m.test(text)) {
    const components = [...text.matchAll(/^PackageName:\s*(.+)$/gm)].map((m) => ({ name: m[1].trim(), purl: '' }));
    const supplier = /^PackageSupplier:\s*(?!NOASSERTION)/m.test(text) || /^Creator:\s*(Organization|Person):/m.test(text);
    return { format: 'SPDX tag-value', components, supplier };
  }

  return null;
}

function flattenCycloneDX(component) {
  const self = {
    name: component.group ? `${component.group}/${component.name ?? ''}` : (component.name ?? ''),
    bare: component.name ?? '',
    purl: component.purl ?? '',
  };
  const nested = (component.components ?? []).flatMap(flattenCycloneDX);
  return [self, ...nested];
}

/** Does the SBOM cover this dependency? Name or purl, scope-aware. */
function sbomCovers(sbom, dep) {
  const want = dep.name.toLowerCase();
  const bare = want.includes('/') ? want.slice(want.lastIndexOf('/') + 1) : want;
  return sbom.components.some((c) => {
    const name = (c.name ?? '').toLowerCase();
    const cbare = (c.bare ?? '').toLowerCase();
    const purl = (c.purl ?? '').toLowerCase();
    if (name === want || cbare === want) return true;
    // "@scope/pkg" in a manifest, "pkg" with group "@scope" in CycloneDX
    if (name.replace(/^@/, '') === want.replace(/^@/, '')) return true;
    if (purl) {
      const decoded = decodeURIComponent(purl);
      if (decoded.includes(`/${want}@`) || decoded.endsWith(`/${want}`)) return true;
      if (decoded.includes(`/${bare}@`) && want.includes('/')) {
        const scope = want.slice(0, want.indexOf('/'));
        if (decoded.includes(scope)) return true;
      }
    }
    return false;
  });
}

// ------------------------------------------------------------ rule engine

function audit(root, index, today) {
  const findings = [];
  const add = (f) => findings.push(f);

  // ---- documents we may need more than once ------------------------------
  const securityPath = locate(index, (p) =>
    /^(\.github\/|docs\/|\.gitlab\/)?security(\.md|\.rst|\.txt)?$/i.test(p));
  const securityText = securityPath ? (read(root, securityPath) ?? '') : '';

  const readmePath = locate(index, (p) => /^readme(\.md|\.rst|\.txt)?$/i.test(p));
  const readmeText = readmePath ? (read(root, readmePath) ?? '') : '';

  const supportPath = locate(index, (p) => /^(docs\/)?support(\.md)?$/i.test(p));
  const supportText = supportPath ? (read(root, supportPath) ?? '') : '';

  const docPaths = index.filter((p) => /^docs?\//i.test(p) && /\.(md|rst|txt|adoc)$/i.test(p)).slice(0, 60);
  const docsText = docPaths.map((p) => read(root, p) ?? '').join('\n');

  // A changelog is where most projects actually announce a fixed vulnerability,
  // so it counts as evidence for Annex I Part II(4) even though it is not a
  // place a user would look for the Annex II information.
  const changelogPath = locate(index, (p) => /^changelog(\.md|\.rst|\.txt)?$/i.test(p));
  const changelogText = changelogPath ? (read(root, changelogPath) ?? '') : '';

  // The union we search for user-facing statements. Annex II information may
  // legitimately live in any of them.
  const userDocs = [readmeText, securityText, supportText, docsText].join('\n');
  const userDocLabel = readmePath ?? securityPath ?? supportPath ?? 'README.md';

  auditSbom(root, index, findings, add);
  auditCvd(root, index, securityPath, securityText, userDocs, today, add);
  auditReporting(securityPath, securityText, userDocs, add);
  auditAdvisories(userDocs, changelogText, userDocLabel, readmePath, add);
  auditUserInformation(index, userDocs, userDocLabel, readmePath, today, add);
  auditScope(index, add);

  return findings;
}

// ---- Annex I Part II(1): software bill of materials ----------------------

function auditSbom(root, index, findings, add) {
  // A demo output or a test fixture is not the product's SBOM. Where every
  // candidate sits in such a path, the project genuinely has no SBOM of its
  // own and the "missing" branch below is the correct answer.
  const sbomPaths = index.filter((p) => looksLikeSbom(p) && isShipped(p));
  const deps = topLevelDependencies(root, index);

  if (sbomPaths.length === 0) {
    add({
      artifact: 'software bill of materials', file: null, line: null,
      rule: 'sbom-missing', ref: 'Annex I Part II(1)', obligation: 'Software bill of materials',
      applies_from: FROM_FULL, severity: 'missing',
      message: deps.length
        ? `No machine-readable SBOM in the repository, and ${deps.length} top-level dependencies are declared.`
        : 'No machine-readable SBOM in the repository.',
      fix: 'Generate one in CycloneDX or SPDX and commit it. Annex I Part II(1) requires a "commonly used and machine-readable format" covering at the very least the top-level dependencies.',
    });
    return;
  }

  let parsed = null;
  let parsedPath = null;
  for (const path of sbomPaths) {
    const text = read(root, path);
    if (text === null) continue;
    const result = parseSbom(text);
    if (result) { parsed = result; parsedPath = path; break; }
  }

  if (!parsed) {
    add({
      artifact: sbomPaths[0], file: sbomPaths[0], line: null,
      rule: 'sbom-unreadable', ref: 'Annex I Part II(1)', obligation: 'Software bill of materials',
      applies_from: FROM_FULL, severity: 'incomplete',
      message: 'A file is named like an SBOM but does not parse as CycloneDX or SPDX.',
      fix: 'Regenerate it with a tool that emits valid CycloneDX JSON/XML or SPDX. "Machine-readable" in Annex I Part II(1) means a parser must be able to read it, not that it is a text file.',
    });
    return;
  }

  if (parsed.components.length === 0) {
    add({
      artifact: parsedPath, file: parsedPath, line: null,
      rule: 'sbom-no-components', ref: 'Annex I Part II(1)', obligation: 'Software bill of materials',
      applies_from: FROM_FULL, severity: 'incomplete',
      message: `${parsed.format} SBOM with an empty component list.`,
      fix: 'Regenerate it from the resolved dependency tree. An SBOM listing nothing documents nothing.',
    });
  } else if (deps.length) {
    const uncovered = deps.filter((d) => !sbomCovers(parsed, d));
    if (uncovered.length) {
      const shown = uncovered.slice(0, 6).map((d) => d.name).join(', ');
      const rest = uncovered.length > 6 ? `, and ${uncovered.length - 6} more` : '';
      add({
        artifact: parsedPath, file: parsedPath, line: null,
        rule: 'sbom-missing-dependencies', ref: 'Annex I Part II(1)', obligation: 'Software bill of materials',
        applies_from: FROM_FULL, severity: 'incomplete',
        message: `${uncovered.length} of ${deps.length} declared top-level dependencies are absent from the SBOM: ${shown}${rest}.`,
        fix: 'Regenerate the SBOM from the current manifest. Annex I Part II(1) sets top-level dependencies as the floor, so a top-level dependency missing from it is a gap in the one thing the article names explicitly.',
      });
    }
  }

  if (!parsed.supplier) {
    add({
      artifact: parsedPath, file: parsedPath, line: null,
      rule: 'sbom-no-supplier', ref: 'Annex II(1)', obligation: 'Manufacturer identification',
      applies_from: FROM_FULL, severity: 'incomplete',
      message: `${parsed.format} SBOM carries no supplier, manufacturer or author metadata.`,
      fix: 'Set metadata.supplier (CycloneDX) or PackageSupplier / an Organization creator (SPDX). An SBOM that does not say who made the product cannot support the Annex II(1) identification of the manufacturer.',
    });
  }
}

// ---- Annex I Part II(5)(6): coordinated vulnerability disclosure ---------

function auditCvd(root, index, securityPath, securityText, userDocs, today, add) {
  if (!securityPath) {
    add({
      artifact: 'SECURITY.md', file: null, line: null,
      rule: 'cvd-policy-missing', ref: 'Annex I Part II(5)', obligation: 'Coordinated vulnerability disclosure policy',
      applies_from: FROM_FULL, severity: 'missing',
      message: 'No coordinated vulnerability disclosure policy found (looked for SECURITY.md in the root, .github/ and docs/).',
      fix: 'Add SECURITY.md stating where to report, what a reporter can expect and on what timeline. Annex I Part II(5) requires the policy to be in place and enforced, not merely an address to write to. An organisation-wide policy in your .github repository satisfies GitHub\'s interface but not this check, and for a reason: a user who receives the source of one product cannot see it.',
    });
  } else {
    const contacts = realContacts(securityText);
    if (contacts.length === 0) {
      add({
        artifact: securityPath, file: securityPath, line: null,
        rule: 'cvd-no-contact', ref: 'Annex I Part II(6)', obligation: 'Contact address for reporting',
        applies_from: FROM_FULL, severity: 'incomplete',
        message: 'The disclosure policy names no reachable contact: no address outside placeholder domains, and no reporting URL.',
        fix: 'Publish an address you monitor, or a reporting form. Annex I Part II(6) requires a contact address for reporting vulnerabilities; a policy nobody can act on does not satisfy it.',
      });
    }
    if (!DURATION.test(securityText)) {
      add({
        artifact: securityPath, file: securityPath, line: null,
        rule: 'cvd-no-timeline', ref: 'Annex I Part II(5)', obligation: 'Coordinated vulnerability disclosure policy',
        applies_from: FROM_FULL, severity: 'incomplete',
        message: 'The disclosure policy states no timeframe: no acknowledgement, triage or disclosure window is given.',
        fix: 'State the windows you commit to, for example acknowledgement within 72 hours and disclosure within 90 days. A policy without a clock is the part a reporter cannot rely on and an auditor cannot check.',
      });
    }
  }

  // security.txt is not named in the CRA. It is the machine-readable convention
  // that answers Annex I Part II(6) for a web-facing product, which is why it
  // fires only where the repository actually ships a website. A `docs/` folder
  // is not one: it is the single most common directory in any repository, and
  // treating it as a web root made this rule fire on libraries that serve
  // nothing at all.
  const servesWeb = index.some((p) => /(^|\/)index\.html$/i.test(p) && isShipped(p)) ||
    topLevelDependencies(root, index).some((d) =>
      /^(next|nuxt|astro|gatsby|@remix-run\/|vite|@sveltejs\/kit|express|fastify|koa|@angular\/core|@nestjs\/core)/.test(d.name));
  const webRoot = ['public', 'static', 'www'].find((d) => index.some((p) => p.startsWith(`${d}/`)));
  const securityTxtPath = locate(index, (p) => /(^|\/)\.well-known\/security\.txt$/.test(p));

  if (!securityTxtPath) {
    if (servesWeb) {
      const where = webRoot ? `${webRoot}/.well-known/security.txt` : '.well-known/security.txt';
      add({
        artifact: where, file: null, line: null,
        rule: 'security-txt-missing', ref: 'Annex I Part II(6)', obligation: 'Contact address for reporting',
        applies_from: FROM_FULL, severity: 'incomplete',
        message: 'This project ships a website and serves no .well-known/security.txt.',
        fix: 'Add one per RFC 9116. The CRA does not name security.txt; it requires a contact address a reporter can find, and for a web-facing product this is the location a researcher and a market surveillance authority check first.',
      });
    }
    return;
  }

  const txt = read(root, securityTxtPath) ?? '';
  const contact = txt.match(/^Contact:\s*(.+)$/im);
  const expires = txt.match(/^Expires:\s*(.+)$/im);

  if (!contact) {
    add({
      artifact: securityTxtPath, file: securityTxtPath, line: null,
      rule: 'security-txt-no-contact', ref: 'RFC 9116 §2.5.3', obligation: 'Contact address for reporting',
      applies_from: FROM_FULL, severity: 'incomplete',
      message: 'security.txt has no Contact field, which RFC 9116 makes mandatory.',
      fix: 'Add "Contact: mailto:security@yourdomain" or a reporting URL. A security.txt without Contact conveys nothing.',
    });
  }

  if (!expires) {
    add({
      artifact: securityTxtPath, file: securityTxtPath, line: null,
      rule: 'security-txt-no-expires', ref: 'RFC 9116 §2.5.5', obligation: 'Contact address for reporting',
      applies_from: FROM_FULL, severity: 'incomplete',
      message: 'security.txt has no Expires field, which RFC 9116 makes mandatory.',
      fix: 'Add "Expires:" with a date under a year out, and renew it. The field exists so a reader can tell a maintained contact from an abandoned one.',
    });
    return;
  }

  // An expired security.txt is worse than none: RFC 9116 §2.5.5 says a reader
  // SHOULD treat the file as stale, so the contact it publishes is one a
  // researcher is entitled to ignore.
  const expiryDate = (expires[1].match(/\d{4}-\d{2}-\d{2}/) ?? [])[0];
  if (expiryDate && expiryDate < today) {
    add({
      artifact: securityTxtPath, file: securityTxtPath,
      line: lineOf(txt, expires[0]),
      rule: 'security-txt-expired', ref: 'RFC 9116 §2.5.5', obligation: 'Contact address for reporting',
      applies_from: FROM_FULL, severity: 'stale',
      message: `security.txt expired on ${prettyDate(expiryDate)}.`,
      fix: 'Renew the Expires date and keep renewing it. RFC 9116 says a reader should consider an expired file stale, so the reporting channel it advertises is one a researcher may disregard — which leaves Annex I Part II(6) unmet while the file still sits there looking answered.',
    });
  }
}

// ---- Article 14: the reporting clock, live since 11 September 2026 -------

function auditReporting(securityPath, securityText, userDocs, add) {
  const namesChannel = /\bENISA\b|\bCSIRT\b|single reporting platform/i.test(userDocs);
  const namesClock = /\b24\s*(hours?|h)\b/i.test(userDocs) && /\b72\s*(hours?|h)\b/i.test(userDocs);

  if (!namesChannel || !namesClock) {
    add({
      artifact: 'Article 14 reporting procedure', file: securityPath, line: null,
      rule: 'reporting-procedure-missing', ref: 'Art. 14(1)-(4)', obligation: 'Reporting of actively exploited vulnerabilities',
      applies_from: FROM_REPORTING, severity: 'missing',
      message: 'No documented procedure for the Article 14 reporting deadlines: the repository names neither the channel (ENISA Single Reporting Platform / national CSIRT) nor the 24-hour and 72-hour windows.',
      fix: 'Write the procedure down before you need it: early warning to the CSIRT and ENISA within 24 hours of becoming aware of an actively exploited vulnerability, notification within 72 hours, final report within 14 days. This obligation is already in force; the 24-hour clock is not a deadline anyone meets by improvising.',
    });
  }
}

// ---- Annex II: information and instructions to the user -----------------

function auditUserInformation(index, userDocs, docLabel, readmePath, today, add) {
  // (7) end-date of the support period, read together with Art. 13(8).
  //
  // The date is rarely on the same line as the phrase that introduces it: a
  // "## Support period" heading followed by the date underneath is the normal
  // shape, and matching a single line found the heading, read no date, and
  // silently skipped the five-year check. Every occurrence is tried, against a
  // window that runs past the end of its line.
  const SUPPORT_PHRASE = /\b(support period|end[- ]of[- ]support|end of life|supported until|security updates until|maintained until|EOL)\b/gi;
  const occurrences = [...userDocs.matchAll(SUPPORT_PHRASE)];
  const supportClaim = occurrences.length ? occurrences[0] : null;
  const declared = occurrences
    .map((m) => extractDate(userDocs.slice(m.index, m.index + 300)))
    .find(Boolean) ?? null;

  if (!supportClaim) {
    add({
      artifact: docLabel, file: readmePath, line: null,
      rule: 'support-period-missing', ref: 'Annex II(7)', obligation: 'Support period',
      applies_from: FROM_FULL, severity: 'missing',
      message: 'Nothing in the user-facing documentation states the end-date of the support period.',
      fix: 'State the date until which you will handle vulnerabilities. Article 13(8) sets a floor of five years from placing on the market, or the expected use time where that is shorter, and Annex II(7) requires the end-date to reach the user.',
    });
  } else {
    if (declared && declared < addYears(today, 5)) {
      add({
        artifact: docLabel, file: readmePath, line: null,
        rule: 'support-period-short', ref: 'Art. 13(8)', obligation: 'Support period',
        applies_from: FROM_FULL, severity: 'review',
        message: `A support period ending ${prettyDate(declared)} is less than five years from today.`,
        fix: 'Check it against the date the product was placed on the market, not today: the five-year floor runs from there, and a repository cannot know that date. If the expected use time is genuinely shorter than five years, record the justification — Annex VII(4) asks for it.',
      });
    }
  }

  // (1)(2) manufacturer identity and the single point of contact
  const contacts = realContacts(userDocs);
  if (contacts.length === 0) {
    add({
      artifact: docLabel, file: readmePath, line: null,
      rule: 'manufacturer-contact-missing', ref: 'Annex II(1)(2)', obligation: 'Manufacturer identification',
      applies_from: FROM_FULL, severity: 'missing',
      message: 'No contact channel for the manufacturer anywhere in the user-facing documentation.',
      fix: 'Publish the single point of contact required by Article 13(17), and the electronic address required by Annex II(1). Both must be reachable by a user, not only by a contributor who opens an issue.',
    });
  }

  // Annex II(1) also requires a postal address. There is deliberately no rule
  // for it: recognising one in prose needs a dictionary of street words in
  // every EU language, and during validation "Keizersgracht 241, 1016 EA
  // Amsterdam" was reported as a missing address. Claiming an absence on a
  // document that has it is the one error this tool refuses to make, so the
  // postal address is listed in the ruleset as human-verified instead.

  // (8) instructions covering the installation of security updates
  const updateDocs = /\b(security update|security patch|install (the )?updates?|upgrade instructions|how to (update|upgrade)|automatic updates)\b/i.test(userDocs);
  if (!updateDocs) {
    add({
      artifact: docLabel, file: readmePath, line: null,
      rule: 'update-instructions-missing', ref: 'Annex II(8)', obligation: 'Instructions to the user',
      applies_from: FROM_FULL, severity: 'incomplete',
      message: 'The documentation does not explain how a user installs security updates.',
      fix: 'Document how updates reach the user and how they are applied, including how to turn automatic updates off where they exist. Annex I Part I(2)(c) expects security updates to be distributed automatically by default; Annex II(8) expects the user to be told how.',
    });
  }

  // (6) the internet address at which the EU declaration of conformity is accessible
  const hasDoC = /\b(EU )?declaration of conformity\b|\bdichiarazione di conformit/i.test(userDocs) ||
    index.some((p) => /declaration[-_ ]?of[-_ ]?conformity|(^|\/)doc\.(pdf|md)$/i.test(p));
  if (!hasDoC) {
    add({
      artifact: 'EU declaration of conformity', file: null, line: null,
      rule: 'conformity-declaration-missing', ref: 'Art. 28 · Annex V',
      obligation: 'EU declaration of conformity',
      applies_from: FROM_FULL, severity: 'missing',
      message: 'No EU declaration of conformity, and no internet address where one could be found.',
      fix: 'Draw up the declaration on the Annex V model and publish the address where a user can reach it, as Annex II(6) requires. It is the document that carries the CE marking; without it the marking cannot be affixed.',
    });
  }

}

// ---- Annex I Part II(4): public disclosure of fixed vulnerabilities ------

function auditAdvisories(userDocs, changelogText, docLabel, readmePath, add) {
  const ADVISORY = /\b(advisor(y|ies)|CVE-\d|GHSA-|security release|security bulletin|security fix)\b/i;
  if (ADVISORY.test(userDocs) || ADVISORY.test(changelogText)) return;
  add({
    artifact: docLabel, file: readmePath, line: null,
    rule: 'advisory-channel-undeclared', ref: 'Annex I Part II(4)', obligation: 'Public disclosure of fixed vulnerabilities',
    applies_from: FROM_FULL, severity: 'review',
    message: 'Nothing says where fixed vulnerabilities are publicly disclosed. A repository cannot tell an unused channel from an undocumented one.',
    fix: 'Name the channel — GitHub Security Advisories, a CVE feed, a mailing list — and say that each fixed vulnerability gets an entry with its severity and the information a user needs to act. If you already publish advisories, this finding costs you one sentence.',
  });
}

// ---- scope: the question no scan can answer ------------------------------

function auditScope(index, add) {
  const hasLicence = index.some((p) => /^licen[cs]e(\.|$)/i.test(p));
  add({
    artifact: 'scope determination', file: null, line: null,
    rule: 'scope-undetermined', ref: 'Art. 2 · Art. 3(14) · Annex III/IV',
    obligation: 'Scope and product class',
    applies_from: FROM_FULL, severity: 'review',
    message: hasLicence
      ? 'Whether the CRA applies here, and under which class, cannot be read from a repository.'
      : 'Whether the CRA applies here cannot be read from a repository, and there is no licence file to indicate how this is distributed.',
    fix: 'Three questions decide it, and all three are commercial rather than technical: is this made available on the market in the course of a commercial activity (free and open-source software outside commercial activity is out of scope, and a legal entity supporting it may instead be an open-source software steward under Article 24); is it listed in Annex III as an important product or Annex IV as a critical one, which changes the conformity assessment route; and are you the manufacturer, the importer or the distributor. Record the answers in the technical documentation.',
  });
}

// ------------------------------------------------------------------- main

function main() {
  const args = process.argv.slice(2);
  const flags = new Set(args.filter((a) => a.startsWith('--')));
  const positional = args.filter((a) => !a.startsWith('--'));
  const root = positional[0] || process.cwd();

  const valueOf = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };
  const todayArg = valueOf('--today');
  const today = /^\d{4}-\d{2}-\d{2}$/.test(todayArg ?? '')
    ? todayArg
    : new Date().toISOString().slice(0, 10);
  const max = flags.has('--max') ? parseInt(valueOf('--max'), 10) : Infinity;

  if (!existsSync(root)) {
    process.stderr.write(`cra-ready: no such directory: ${root}\n`);
    process.exit(2);
  }

  const index = indexRepo(root);
  let findings;
  try {
    findings = audit(root, index, today);
  } catch (err) {
    process.stderr.write(`cra-ready: analysis failed: ${err.message}\n`);
    process.exit(2);
  }

  findings.sort((a, b) =>
    SEVERITY[a.severity] - SEVERITY[b.severity] ||
    a.applies_from.localeCompare(b.applies_from) ||
    a.rule.localeCompare(b.rule));

  const counts = { missing: 0, incomplete: 0, stale: 0, review: 0 };
  for (const f of findings) counts[f.severity]++;
  const enforceableNow = findings.filter((f) => f.applies_from <= today).length;

  const limited = Number.isFinite(max) ? findings.slice(0, max) : findings;

  const result = {
    tool: 'cra-ready',
    regulation: 'Regulation (EU) 2024/2847 (Cyber Resilience Act)',
    root,
    today,
    indexed: index.length,
    counts,
    enforceable_now: enforceableNow,
    total: findings.length,
    truncated: findings.length > limited.length,
    coverage: 'Repository evidence for Annex I Part II, Annex II and Article 14 readiness. The product properties of Annex I Part I are a risk assessment and are not checked. This does not establish conformity.',
    findings: limited,
  };

  if (flags.has('--json')) {
    process.stdout.write(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`\ncra-ready - EU Cyber Resilience Act (EU) 2024/2847, repository evidence`);
  console.log(`${index.length} files indexed in ${root}\n`);
  console.log(`  MISSING ${counts.missing}   INCOMPLETE ${counts.incomplete}   STALE ${counts.stale}   NEEDS REVIEW ${counts.review}`);
  console.log(`  enforceable today ${enforceableNow}   ·   from ${prettyDate(FROM_FULL)} ${findings.length - enforceableNow}\n`);

  let lastSev = null;
  for (const f of limited) {
    if (f.severity !== lastSev) { console.log(`\n── ${LABEL[f.severity]} ──`); lastSev = f.severity; }
    const where = f.file
      ? `${f.file}${f.line ? `:${f.line}` : ''}`
      : (f.severity === 'review' ? f.artifact : `${f.artifact} — absent`);
    const when = f.applies_from <= today ? 'in force' : `from ${prettyDate(f.applies_from)}`;
    console.log(`  ${where}  [${f.ref} · ${when}]  ${f.rule}`);
    console.log(`     ${f.message}`);
    console.log(`     → ${f.fix}`);
  }
  if (result.truncated) {
    console.log(`\n  ... and ${findings.length - limited.length} more findings (use --max to raise the limit)`);
  }
  console.log(`\n${result.coverage}\n`);
}

main();

# cra-ready

**The Cyber Resilience Act obligations your repository cannot currently
evidence, each with the article it comes from and the date it bites.**

A Claude Code skill and a standalone CLI that checks a codebase against
**Regulation (EU) 2024/2847** — the European Cyber Resilience Act. Zero
dependencies, nothing leaves your machine.

A real run, not a mock-up — this is `expressjs/express` at its current `main`,
trimmed to the first four findings, and you can reproduce it in the two
commands below the block:

```
cra-ready - EU Cyber Resilience Act (EU) 2024/2847, repository evidence
214 files indexed in ./express

  MISSING 5   INCOMPLETE 1   STALE 0   NEEDS REVIEW 2
  enforceable today 1   ·   from 11 Dec 2027 7


── MISSING ──
  Article 14 reporting procedure — absent  [Art. 14(1)-(4) · in force]  reporting-procedure-missing
     No documented procedure for the Article 14 reporting deadlines: the repository names neither the channel (ENISA Single Reporting Platform / national CSIRT) nor the 24-hour and 72-hour windows.
     → Write the procedure down before you need it: early warning to the CSIRT and ENISA within 24 hours of becoming aware of an actively exploited vulnerability, notification within 72 hours, final report within 14 days. This obligation is already in force; the 24-hour clock is not a deadline anyone meets by improvising.
  EU declaration of conformity — absent  [Art. 28 · Annex V · from 11 Dec 2027]  conformity-declaration-missing
     No EU declaration of conformity, and no internet address where one could be found.
     → Draw up the declaration on the Annex V model and publish the address where a user can reach it, as Annex II(6) requires. It is the document that carries the CE marking; without it the marking cannot be affixed.
  SECURITY.md — absent  [Annex I Part II(5) · from 11 Dec 2027]  cvd-policy-missing
     No coordinated vulnerability disclosure policy found (looked for SECURITY.md in the root, .github/ and docs/).
     → Add SECURITY.md stating where to report, what a reporter can expect and on what timeline. Annex I Part II(5) requires the policy to be in place and enforced, not merely an address to write to. An organisation-wide policy in your .github repository satisfies GitHub's interface but not this check, and for a reason: a user who receives the source of one product cannot see it.
  software bill of materials — absent  [Annex I Part II(1) · from 11 Dec 2027]  sbom-missing
     No machine-readable SBOM in the repository, and 28 top-level dependencies are declared.
     → Generate one in CycloneDX or SPDX and commit it. Annex I Part II(1) requires a "commonly used and machine-readable format" covering at the very least the top-level dependencies.

Static subset of the CRA. The product properties of Annex I Part I are a risk assessment and are not checked. This does not establish conformity.
```

```bash
git clone --depth 1 https://github.com/expressjs/express.git
node skills/cra-ready/scripts/detect.mjs ./express --max 4
```

## Why this exists

Most CRA writing gives one date, 11 December 2027, and most teams have filed it
under "next year's problem". That is the wrong half of the timeline:

```
  11 Sep 2026  ──────────────────────────────▶  11 Dec 2027
  Article 14 reporting                          essential requirements,
  IN FORCE NOW                                  CE marking, technical
                                                documentation
  24h early warning                             the 15-month runway
  72h notification                              that is already running
  14d final report
```

Since **11 September 2026**, a manufacturer who becomes aware that a
vulnerability in a product on the EU market is being **actively exploited** has
24 hours to file an early warning with their national CSIRT and ENISA through
the Single Reporting Platform, 72 hours for the notification, 14 days for the
final report. It applies to products placed on the market *before* the
regulation fully applies, so "we shipped it in 2024" is not an exemption.

Penalties under Article 64 run to **€15 million or 2.5% of worldwide annual
turnover**, whichever is higher, for the essential requirements and the
Article 13 and 14 obligations.

## What it checks, and what it refuses to check

Vulnerability scanners already answer "does this code contain a known
vulnerability", and they answer it better than anything here could, because the
answer changes daily. That is not the gap:

```
   known vulns      →   [ CAN YOU EVIDENCE IT? ]   →   the dossier
  OSV, Dependabot        SBOM, disclosure policy,       Annex V + VII
    Trivy, Grype         reporting procedure,           nobody does this
     (solved)            support period
```

**20 checks** across the obligations that leave a trace in source control: the
vulnerability handling requirements of Annex I Part II, the user information of
Annex II, and readiness for the Article 14 clock.

It deliberately does **not** check Annex I Part I — the thirteen product
properties, from secure defaults to attack surface minimisation. Those are a
cybersecurity risk assessment under Annex VII(3), not a file that is present or
absent, and a tool that graded them would be inventing a result.

So it will never tell you that you are compliant, because it cannot know. It
tells you which obligations you cannot currently evidence, and when each one
becomes enforceable. The full rule list — including an explicit account of
**what is not covered and why** — is in
[`skills/cra-ready/references/ruleset.md`](skills/cra-ready/references/ruleset.md).

No legal advice. Whether the CRA applies to your product at all, which class it
falls in, and how to answer an authority are questions for a professional.

If you want the regulation itself explained before the tool: [what applies and
when](https://plainform.github.io/cra/), [the Article 14 reporting
deadlines](https://plainform.github.io/cra/article-14-reporting/), and [what
the SBOM requirement actually asks for](https://plainform.github.io/cra/sbom/).

## Install

```
/plugin marketplace add plainform/cra-ready
/plugin install cra-ready
```

Then just ask:

> check this project against the Cyber Resilience Act

### Without Claude Code

Standalone CLI, zero dependencies:

```bash
npx cra-ready ./my-project
npx cra-ready ./my-project --json          # for CI, or to feed another tool
npx cra-ready ./my-project --today 2026-09-11   # pin the date
```

Or straight from a clone, without npm at all:

```bash
node skills/cra-ready/scripts/detect.mjs ./my-project
```

Requires Node 18+. Reads manifests for npm, PyPI, Cargo, Go and Composer, and
SBOMs in CycloneDX (JSON and XML) and SPDX (JSON and tag-value).

## How accurate is it

Precision was the whole design constraint, same as its sibling
[`eaa-audit`](https://github.com/plainform/eaa-audit): in a compliance report a
false positive costs more credibility than a missed finding earns. Where the
repository is genuinely ambiguous, a finding is emitted as `NEEDS REVIEW`,
never `MISSING`.

Validated against real repositories, every finding checked by hand:

| Repository | Findings | Verified true |
|---|---|---|
| `expressjs/express` | 8 | 8 |
| `fastify/fastify` | 5 | 5 |
| `sigstore/cosign` | 7 | 7 |
| `CycloneDX/cyclonedx-node-npm` | 9 | 9 |

Three classes of false positive were found during that process and fixed before
release. All three are now asserted by the test suite, so they cannot come back:

- **A test fixture was read as the project's SBOM.** `cosign` has
  `test/testdata/bom-go-mod.cyclonedx.json`; it was audited as though it were
  the product's bill of materials and reported as having an empty component
  list. SBOM selection now ignores test, fixture, demo and example paths — and
  where every candidate sits in one, the project genuinely has no SBOM, which
  is what gets reported.
- **`express` was reported as shipping a website**, because of an `index.html`
  under `test/fixtures/`. Same fix, same reason: what is not shipped is not
  evidence about the product.
- **An OpenSSF Scorecard badge was read as a vulnerability reporting channel**,
  because its URL contains the word "security". On a repository whose only
  security-shaped link is a status badge, that would have suppressed a true
  finding. A URL now counts only if its *path* says it is a reporting
  destination.

A fourth rule was **removed** rather than fixed. Annex II(1) requires a postal
address, and detecting one in prose needs a dictionary of street words in every
EU language — a draft reported `Keizersgracht 241, 1016 EA Amsterdam` as a
missing address. Claiming an absence on a document that has it is the one error
this tool refuses to make, so the postal address is listed in the ruleset as
human-verified instead.

Run it yourself:

```bash
node test/run.mjs
```

`test/fixtures/conformant` is the assertion that matters: a repository that has
answered every obligation must come back with **exactly one finding**, and it
must be `scope-undetermined` — the question no tool can answer. A checker that
still complains at a repository which has done the work is worse than no
checker, because the reader has no way to tell which findings are real.

## Pro

Detection is the part that is free, and it stays free. What it does not do is
write anything for you: the SBOM, the disclosure policy, the reporting
procedure, or the dossier an auditor reads.

**cra-ready Pro** adds those, all built on the JSON this checker already emits:

| | |
|---|---|
| `sbom.mjs` | CycloneDX 1.6 SBOM generated from your lockfiles, with supplier metadata and licences — zero dependencies, no network |
| `cvd-policy.mjs` | `SECURITY.md` and RFC 9116 `security.txt`, including the Article 14 procedure with the 24h/72h/14d clock written down |
| `dossier.mjs` | Draft EU declaration of conformity (Annex V) and technical documentation skeleton (Annex VII), every unknown as `[TO COMPLETE]` |
| `guard.mjs` | CI guard that fails the build when a closed obligation reopens, with a baseline keyed on the obligation rather than the file |

€59 once, perpetual licence for one organisation. Delivery is access to a
private GitHub repository, granted automatically on purchase — no licence key,
no telemetry, no network calls. Runs entirely on your machine, like the free
tier.

**[Get cra-ready Pro →](https://buy.polar.sh/polar_cl_WUMBvOIUaondwQEhkTgzS9IbwYgvG2g79nIjB0BWVhZ)**

The same limit stated above applies to Pro: it is repository evidence, not a
conformity assessment, and every document it drafts is marked as a draft
requiring human review and signature. No tool can establish legal conformity,
and this one does not claim to.

## License

MIT. See [LICENSE](LICENSE).

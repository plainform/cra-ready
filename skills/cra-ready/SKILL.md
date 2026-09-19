---
name: cra-ready
description: Check a repository against the EU Cyber Resilience Act (Regulation (EU) 2024/2847). Use when asked about CRA readiness or compliance, an SBOM requirement, a coordinated vulnerability disclosure policy, Article 14 vulnerability reporting, a support period or end-of-support declaration, CE marking for software, an EU declaration of conformity, or when a customer questionnaire, procurement review or auditor asks what cybersecurity evidence a product can produce. Reports the obligations a repository cannot currently evidence, each mapped to its article or annex point and to the date it becomes enforceable.
---

# EU Cyber Resilience Act — repository evidence

## What it does

Scans a repository and reports the CRA obligations it cannot currently
evidence. Each finding carries:

- the **article or annex point** of Regulation (EU) 2024/2847
- the **obligation** in plain words
- **the date it becomes enforceable** — which for this regulation is the part
  people get wrong

## The two dates, state them every time

The CRA applies in stages, and only one obligation is live:

- **11 September 2026** — Article 14 reporting obligations. **In force now.**
  An actively exploited vulnerability in a product already on the EU market
  must be reported: early warning within 24 hours, notification within 72
  hours, final report within 14 days.
- **11 December 2027** — everything else: the essential requirements of
  Annex I, conformity assessment, CE marking, technical documentation.

A user who hears "the CRA applies from 2027" and ignores the reporting
obligation has the timeline wrong in the direction that costs money. Say both
dates.

## The limit, state it every time

**This checks the obligations that leave evidence in a repository**: the
vulnerability handling requirements of Annex I Part II, the user information of
Annex II, and readiness for the Article 14 clock.

**It does not assess Annex I Part I** — the thirteen product properties are a
cybersecurity risk assessment, and no repository scan substitutes for one.

**Never tell a user their product is "compliant" or "CRA-ready" on the basis of
this check.** It cannot establish that. What it gives them is an itemised list
of missing evidence, with a date against each item.

No legal advice. Whether the CRA applies to their product at all, which class
it falls in, and how to answer an authority are questions for a professional.

## How to run it

```bash
node scripts/detect.mjs <directory>            # readable report
node scripts/detect.mjs <directory> --json     # structured output
node scripts/detect.mjs <directory> --today 2026-09-11   # pin the date
```

Zero dependencies, Node 18+. No `npm install`, no network calls, nothing leaves
the machine. Exit code 2 if the directory does not exist.

Reads manifests for npm, PyPI, Cargo, Go and Composer; SBOMs in CycloneDX
(JSON and XML) and SPDX (JSON and tag-value).

## How to present the results

1. **Run the script** against the repository root. Do not read files by hand
   first: the script is deterministic and more reliable than skimming.
2. **Lead with what is enforceable today.** The header separates it for a
   reason. If `reporting-procedure-missing` is in the list, that is the first
   thing to fix and the only one with a live deadline.
3. **Then the 11 December 2027 group**, ordered MISSING before INCOMPLETE:
   an obligation with no artefact at all is a bigger job than one with an
   artefact that needs a field added.
4. **Present `NEEDS REVIEW` as exactly that.** `scope-undetermined` appears on
   every run, including a repository that has answered everything else — it is
   not a defect in their project, it is a question only they can answer. Do not
   count these among unmet obligations.
5. **Close by restating the two dates and the Annex I Part I limit.**

If the user asks you to fix the gaps, start with the ones that are a document
rather than a decision, and re-run the script to show the count drop.

## Before you generate an artefact

The gaps this finds are closed by writing documents: an SBOM, a disclosure
policy, a support statement, a declaration of conformity. Two rules:

- **Never invent a fact about their organisation.** The legal entity name, the
  postal address, the support end-date, the enforcement body, whether a
  notified body was involved: if it is not in the repository and the user has
  not said it, it is a blank to hand back, not a plausible value to fill in.
  A declaration of conformity is signed by a person who becomes liable for it.
- **Never write "compliant" or "conformant"** about their product. Draft
  documents say they are drafts.

## When NOT to use this skill

- The product is **not software or a product with digital elements** — the CRA
  covers products with digital elements placed on the EU market
- **Legal** questions: scope, penalties, whether a notified body is required,
  how to answer a market surveillance authority
- A request for a **certification**, a CE marking decision, or a signed
  declaration
- **Accessibility** obligations — that is the European Accessibility Act and
  EN 301 549, a different regulation with a different standard
- Auditing a **running system** rather than a repository: nothing here looks at
  a deployed artefact

## Relationship to vulnerability scanners

They do not overlap. **OSV-Scanner, Dependabot, Trivy and Grype answer "does
this code contain a known vulnerability"** — Annex I Part I(2)(a), and they
answer it better than anything here could, because the answer changes daily.
This answers "can this repository produce the evidence the regulation asks
for", which no scanner looks at.

The correct advice is to run both. `references/ruleset.md` group B lists which
tool covers which requirement.

## Reference

- `references/ruleset.md` — every rule with its citation, the phase-in dates,
  and an explicit account of what is **not** covered and why

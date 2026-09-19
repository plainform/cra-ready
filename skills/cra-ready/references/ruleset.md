# Ruleset — Cyber Resilience Act obligations detectable from a repository

Every rule carries three references:

- the **article or annex point** of Regulation (EU) 2024/2847 it comes from
- the **obligation** in plain words, because an annex number alone tells a
  developer nothing
- the **date it becomes enforceable**, which for this regulation is not one
  date but two

---

## The two dates

The CRA entered into force on **10 December 2024** and applies in stages
(Article 71):

| Date | What starts | Status here |
|---|---|---|
| 11 June 2026 | Chapter IV, notification of conformity assessment bodies | binds notified bodies, not products — no rule |
| **11 September 2026** | **Article 14 reporting obligations** | **in force** |
| 11 December 2027 | everything else: essential requirements, conformity assessment, CE marking, technical documentation | 20 rules |

This is why the report separates *enforceable today* from the rest. One
obligation is live; the others are a dated runway, and a tool that flattens
them into a single pile of red is not telling you what to do first.

---

## Inclusion criterion

A rule ships **only if a repository can decide it**. The CRA is largely about
process and product design; only part of it leaves a trace in source control,
and that part is what this checks.

Three groups:

| Group | Where it lives | What we do |
|---|---|---|
| **A** — repository evidence | an artefact is present, absent, or incomplete | we check it |
| **B** — runtime and supply chain | needs the built artefact or a vulnerability feed | we declare it, defer to the tools that do it |
| **C** — judgement | needs a person, a lawyer, or a risk assessment | we list it as to-verify |

The severity vocabulary follows from the domain: an obligation is not *more or
less* violated, it is unanswered, half answered, or answered with something out
of date.

| Level | Meaning |
|---|---|
| `MISSING` | the obligation has no artefact at all. An auditor asking for it gets nothing |
| `INCOMPLETE` | the artefact exists and lacks something the regulation names |
| `STALE` | the artefact exists and has expired |
| `NEEDS REVIEW` | the repository cannot decide it, and says so rather than guessing |

---

## Group A — implemented rules

### Annex I Part II — vulnerability handling requirements

The part of the CRA that is genuinely mechanical, and the part almost no
repository has done.

| ID | Reference | Severity | What it catches |
|---|---|---|---|
| `sbom-missing` | Annex I Part II(1) | MISSING | no machine-readable SBOM anywhere in the repository |
| `sbom-unreadable` | Annex I Part II(1) | INCOMPLETE | a file named like an SBOM that parses as neither CycloneDX nor SPDX |
| `sbom-no-components` | Annex I Part II(1) | INCOMPLETE | a valid SBOM with an empty component list |
| `sbom-missing-dependencies` | Annex I Part II(1) | INCOMPLETE | top-level dependencies declared in the manifest and absent from the SBOM |
| `sbom-no-supplier` | Annex II(1) | INCOMPLETE | SBOM with no supplier, manufacturer or author metadata |
| `cvd-policy-missing` | Annex I Part II(5) | MISSING | no coordinated vulnerability disclosure policy |
| `cvd-no-contact` | Annex I Part II(6) | INCOMPLETE | a policy naming no address or reporting URL |
| `cvd-no-timeline` | Annex I Part II(5) | INCOMPLETE | a policy stating no acknowledgement or disclosure window |
| `security-txt-missing` | Annex I Part II(6) | INCOMPLETE | a project that ships a website and serves no `.well-known/security.txt` ⁽¹⁾ |
| `security-txt-no-contact` | RFC 9116 §2.5.3 | INCOMPLETE | `security.txt` without its mandatory `Contact` |
| `security-txt-no-expires` | RFC 9116 §2.5.5 | INCOMPLETE | `security.txt` without its mandatory `Expires` |
| `security-txt-expired` | RFC 9116 §2.5.5 | STALE | `Expires` in the past: a channel a researcher may disregard |
| `advisory-channel-undeclared` | Annex I Part II(4) | NEEDS REVIEW | nothing says where fixed vulnerabilities are published ⁽²⁾ |

⁽¹⁾ The CRA does not name `security.txt`. It requires a contact address a
reporter can find, and for a web-facing product this is where a researcher and
a market surveillance authority look first. The rule fires only where the
repository actually ships a website — an `index.html` outside test and example
directories, or a web framework in the dependencies.

⁽²⁾ `NEEDS REVIEW`, not `MISSING`: a repository cannot tell a channel that is
used but undocumented from one that does not exist. The changelog counts as
evidence, because that is where most projects actually announce a fix.

### Article 14 — reporting, in force since 11 September 2026

| ID | Reference | Severity | What it catches |
|---|---|---|---|
| `reporting-procedure-missing` | Art. 14(1)–(4) | MISSING | no written procedure naming the reporting channel and the 24-hour and 72-hour windows |

The obligation is to report an actively exploited vulnerability in a product
you have placed on the market: early warning to the national CSIRT and ENISA
through the Single Reporting Platform **within 24 hours** of becoming aware, a
vulnerability notification **within 72 hours**, a final report **within 14
days**. For a severe incident the final report is due within one month.

Nothing in a repository can prove you would meet a 24-hour clock. What it can
show is whether anyone has written down who files, where, and by when — which
is the difference between a procedure and an intention.

### Annex II — information and instructions to the user

| ID | Reference | Severity | What it catches |
|---|---|---|---|
| `support-period-missing` | Annex II(7) | MISSING | no end-date of the support period anywhere in the user documentation |
| `support-period-short` | Art. 13(8) | NEEDS REVIEW | a declared end-date under five years out ⁽³⁾ |
| `manufacturer-contact-missing` | Annex II(1)(2) | MISSING | no contact channel for the manufacturer |
| `update-instructions-missing` | Annex II(8) | INCOMPLETE | nothing explains how a user installs security updates |
| `conformity-declaration-missing` | Art. 28 · Annex V | MISSING | no EU declaration of conformity and no address where one lives |

⁽³⁾ `NEEDS REVIEW` on purpose. Article 13(8) sets five years **from placing on
the market**, or the expected use time where that is shorter. A repository does
not know the date of placing on the market and cannot know whether a shorter
period is justified, so the rule reports the arithmetic and hands back the
judgement.

### Scope

| ID | Reference | Severity | What it catches |
|---|---|---|---|
| `scope-undetermined` | Art. 2 · Art. 3(14) · Annex III/IV | NEEDS REVIEW | always emitted |

Emitted on every run, including a repository that has answered everything else.
Three questions decide whether any of this applies, and all three are
commercial rather than technical:

1. Is the product **made available on the market in the course of a commercial
   activity**? Free and open-source software outside commercial activity is out
   of scope. Paid support, SLA-backed hosting or professional services around
   it are commercial activity. A legal entity that supports a FOSS project
   without monetising it may instead be an **open-source software steward**
   under Article 24, with a much lighter set of obligations.
2. Is it listed in **Annex III** (important products, class I or II) or
   **Annex IV** (critical products)? This changes the conformity assessment
   route, including whether a notified body has to be involved.
3. Are you the **manufacturer**, the importer or the distributor? The
   obligations differ.

A checker that silently assumed the answers would be wrong for most of the
repositories it runs against.

---

## Group B — needs more than the repository

Declared, never guessed. Each has good tools already, and this one does not
duplicate them.

| Requirement | Why we do not check it | What does |
|---|---|---|
| Annex I Part I(2)(a) — released without known exploitable vulnerabilities | needs a vulnerability feed and the resolved tree, and the answer changes daily | OSV-Scanner, Dependabot, Trivy, Grype |
| Annex I Part II(2) — vulnerabilities remediated without delay | needs the history of your advisories against your releases | your own release process |
| Annex I Part II(3) — regular testing and review | needs evidence of tests having been run, not of tests existing | your CI records |
| Annex I Part II(7)(8) — secure distribution of updates | a property of the distribution channel, not of the source | your registry or update server |
| Credentials committed to source | precision here needs entropy analysis and allowlists | gitleaks, trufflehog, GitHub secret scanning |

Running one of these alongside `cra-ready` is the correct setup. They answer
different questions and the answers do not overlap.

---

## Group C — requires human verification

No automated tool covers these. The report names them because that is the part
that makes the paper trail defensible.

- **The entire Annex I Part I** — the thirteen product properties: risk-based
  design, secure default configuration, access control, confidentiality and
  integrity of data, data minimisation, availability under denial of service,
  limited attack surface, exploit mitigation, security logging, secure data
  deletion. These are a **cybersecurity risk assessment** (Annex VII(3)), not a
  file that is present or absent.
- **The postal address** required by Annex II(1). Recognising one in prose
  needs a dictionary of street words in every EU language, and a draft of this
  tool reported *"Keizersgracht 241, 1016 EA Amsterdam"* as a missing address.
  Claiming an absence on a document that has it is the one error this tool
  refuses to make, so there is no rule and the address is listed here instead.
- **Whether the SBOM is true** — that its contents match what actually ships.
  We check coverage of the declared top-level dependencies, which is the floor
  Annex I Part II(1) names, not accuracy.
- **Whether the intended purpose and the foreseeable risks** (Annex II(4)(5))
  are described *adequately*.
- **Whether the support period is justified** (Annex VII(4)).
- **Which harmonised standards apply** (Annex VII(5)) — at the time of writing
  the harmonised standards under the CRA are still being developed, so this is
  a moving target and not something to hard-code.

---

## A note on dev dependencies

`sbom-missing-dependencies` deliberately ignores `devDependencies` and their
equivalents. Annex I Part II(1) is about the components *contained in the
product*, and a test runner is not shipped to the user. Including them would
generate a large class of findings that are wrong on the law rather than merely
noisy.

If your build bundles a dev dependency into the shipped artefact, that
dependency is in the product and belongs in the SBOM — but only your build
knows that, which is why this is stated here rather than guessed at.

---

## The sentence this tool will not write

**This does not establish conformity, and it cannot.** It checks whether a
repository can produce the evidence a market surveillance authority would ask
for. That is a necessary condition, never a sufficient one.

What is promised: fewer hours assembling a technical documentation file, and an
itemised list of what is missing with the date each item becomes enforceable.

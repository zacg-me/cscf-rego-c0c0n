# Layered Compliance Translation (LCT) v2.0
### A regime-, target-, and engine-independent architecture for converting regulatory prose into enforceable policy-as-code

> **Naming.** LCT supersedes the Phase I name *"Translation Framework"*, which named
> the activity rather than the contribution and is unsearchable in the literature.
> The contribution is not that prose is translated; it is that **regulatory
> interpretation is separated from technology binding**, so the expert work is done
> once and survives tooling change. The architecture is the compiler
> front-end / intermediate-representation / back-end split applied to regulation:
> the **Assertion Register is the intermediate representation**, and that split has a
> four-decade track record of surviving language and hardware churn.

**Author:** Zachariah George
**Supersedes:** Translation Framework v1.2.1 (Phase I)
**Basis:** empirical application of v1.2.1 to **10 further CSCF controls** and one
complete **regime version migration (v2026 -> v2027)**.

---

## 0. Why v2.0, the evidence

v1.2.1 was derived from **5 controls**. Phase II applied it to **10 more** and to a
regime version change. Every change below is justified by a measurement from that
application, not by preference.

**Measured across the 10 Phase II translations** (78 exclusions, 74 scoped
assertions, 37 specifications):

| Taxonomy | Observation | Implication |
|---|---|---|
| Exclusion categories | **XREF 33 (42%)**, PROC 18, RUNTIME 10, ADV 8, PLATLIM 4, VENDOR 2, ONPREM 2, ROOT 1, LEGAL 0 | Control **overlap is the most common decomposition outcome**, v1.2.1 buries it as one of ten exclusion codes |
| Scope levels | TAG 50 (68%), ACCT 16, VPC 8, **MODULE 0, XREF-scope 0** | Two of five levels are **dead** |
| Spec variants | **A 26 (70%)**, C 5, B 4, E 1, **D 0** | Variant D unused; Variant **E used once, and that rule (1.4-A6) is the only one that fails open under a real `terraform plan`** |

### 0.1 The structural defect: "seven stages" was never seven

The v1.2.1 pipeline was *Parse -> Decompose -> **Scope (2.5)** -> Map -> Specify ->
**Trace (4.5)** -> Encode*. Two of its seven members are numbered as halves. That is
not cosmetic; it records that the model was fitted to a memorable number rather
than to the work:

- **"Stage 2.5" Scope** was appended after the fact. Scope is not a step between
  Decompose and Map; it is one of the two decisions that *constitute* binding an
  abstract assertion to a technology.
- **"Stage 4.5" Trace is not a stage at all; it is a verification gate.** It
  produces no translation product; it *checks* the products of other stages.
  Modelling a check as a pipeline step is a category error, and it is why
  completeness verification in v1.2.1 reads as an afterthought.
- **Specify is not a distinct cognitive act.** It is the written form of the Scope
  and Map decisions, an artifact, not a stage.

Removing the padding leaves **six genuine stages and three gates**, which then map
exactly onto the three planes below (two stages and one gate each). The structure
gets simpler *and* more honest at the same time.

### 0.2 The longevity defect

v1.2.1 hard-couples the method to **CSCF + Terraform plan JSON + OPA/Rego + AWS**.
Over 20 years all four will change. A methodology with those embedded in its stages
dies with them.

### 0.3 Four gaps with no vocabulary at all

1. **Meta-controls.** CSCF 1.3 ("secure the cloud platform *to the same level as
   physical systems*") and 4.2 mostly re-delegate to other controls. v1.2.1 cannot
   say this, so such controls merely look thin.
2. **Mechanism-presence assertions.** For 2.2 (patching) and 2.7 (scanning) the only
   plan-evaluable fact is *"the automation exists."* That is far weaker than
   "the requirement is met," and `Full`/`Partial` cannot express it, inviting
   overclaim in an attestation.
3. **Plan-time unknowns.** Joins on runtime identifiers **fail open** under a real
   `terraform plan` (`known after apply`). Unmentioned in v1.2.1; the single largest
   real-world risk.
4. **Independent falsifiability.** An assertion pair *"resource exists"* +
   *"resource is configured"* cannot both be falsified by one non-compliant fixture.
   Decomposition must respect this; v1.2.1 is silent.

---

## 1. Design goals (the 20-year test)

| Goal | Mechanism |
|---|---|
| **Regime-independent** (CSCF, PCI-DSS, DORA, NIS2, successors) | Regime Profile (§3) |
| **Target-independent** (Terraform/AWS, Bicep/Azure, Crossplane, CDK) | Target Profile (§3) |
| **Engine-independent** (survives OPA/Rego's replacement) | Three planes (§2) |
| **Version-resilient** (absorbs annual revisions cheaply) | Re-baseline loop (§6) |
| **Scalable** (N regimes × M targets without re-deriving requirements) | Author once in Plane 1 |
| **Honest** (never overstates what a static check proves) | Assurance levels (§4.3) |
| **Non-duplicative** (overlapping controls don't duplicate rules) | Delegation (§4.2) |

---

## 2. Architecture, three planes, six stages, three gates

Dependencies run one way, downward. Each plane holds two stages and closes with a
gate.

```
PLANE 1, NORMATIVE  regime-bound, technology-free
1 PARSE      prose -> Requirement Register + Exclusion Register
2 DECOMPOSE  requirements -> Assertion Register (abstract intent)
GATE A, DISPOSITION  every requirement covered, delegated,
excluded, or informational
Contains NO cloud, IaC, or engine vocabulary.
Lifetime: that of the regulation. Survives all tooling change.
============================================================================
                                assertions are reused, not re-derived
PLANE 2: BINDING, target-bound (per Target)
3 SCOPE      which resources an assertion applies to
4 MAP        which resource types + attributes carry the evidence
-> artifact: Binding Specification (GIVEN / WHEN / THEN)
GATE B, BINDABILITY  every assertion bound, or declared
unbindable for this target, with reason;
every attribute read admissible in the
target schema; declared scope implemented
Lifetime: one cloud/IaC generation. Swappable.
============================================================================
PLANE 3: REALIZATION, engine-bound (per Engine)
5 ENCODE     Binding Specification -> executable policy
6 ATTEST     evaluation -> evidence artefact -> assessor attestation
GATE C, CONFORMANCE  executable suite: no false positives,
coverage symmetry, scope, metrics, perf
Lifetime: shortest. Fully replaceable.
============================================================================

LOOPS   RE-BASELINE (regime version delta) -> re-enters Plane 1
        OPERATE     (pipeline enforcement, drift, runtime) -> informs Plane 2/3
```

**Why the separation pays.** The assertion *"secrets at rest are encrypted under a
key the institution controls"* is authored **once** in Plane 1. Binding it to
AWS/Terraform yields `aws_secretsmanager_secret.kms_key_id`; to Azure/Bicep, a Key
Vault CMK property. Encoding yields Rego now and something else later. **The
expensive, expert act (reading the regulation) happens once and is never
repeated.** Only the cheap, mechanical lower planes churn.

**Why gates, not stages.** A gate consumes the artifacts of its plane and answers
one yes/no question. Gate A is v1.2.1's completeness check, restored to its proper
role. Gate C is executable (§7), because prose validation criteria are never run
and therefore decay.

**Gate B is executable too, and cheaply.** Bindability alone proved insufficient:
a binding can be *admissible-looking* and impossible. Two mechanical checks close
that gap, both reading the target's published schema rather than anyone's
judgement:

| Check | Catches | Why a fixture corpus cannot |
|---|---|---|
| **Admissibility** | a rule reads an attribute the resource type does not define | the fixture author supplies the impossible attribute |
| **Scope conformance** | a rule declares a scope it does not apply | every fixture resource is in scope, so both behave identically |

Between them they found four defects in a library that passed a 42-test
conformance suite. Any instantiation of LCT should run both; for a Terraform
Target Profile the schema comes from `terraform providers schema -json`.

---

## 3. Profiles, the extensibility mechanism

Rather than embedding CSCF/AWS/Terraform/OPA in the stages, v2.0 declares them as
swappable **profiles**. A project instantiates one of each.

- **Regime Profile**: regulation name, version, control-identifier scheme,
  mandatory/advisory semantics, applicability dimensions (CSCF: architecture types
  A1-A4/B), update cadence.
- **Target Profile**: IaC format and serialisation (Terraform `plan -json`),
  resource vocabulary, attribute-path convention, module/nesting model, tagging
  model, the **resolvability model** (§4.5) (which values are known before
  deployment) and the **completeness model** (§4.9): whether an evaluated plan
  describes the whole environment or only a change to it.
- **Engine Profile**: policy language and rule idiom, violation-message format,
  evidence schema, pipeline integration point.

*Current instantiation:* CSCF v2026 (+v2027 delta), Terraform plan JSON / AWS
provider 5.x, OPA Rego v1 + `swift-cscf-evidence/v1` (with the additive
`undetermined`, `plan_scope`, `module_normalisation` and `signature` fields).
Evidence is signed with Ed25519 by a key held only in CI, so the ATTEST stage's
artefact is verifiable by an assessor holding nothing but the published public
key.

*Target Profile normalisation.* A generated plan differs from the model a policy
library is written against in ways that silently suppress findings, so the
Terraform Target Profile normalises it before evaluation: R2 unknowns resolved by
reference, `null` attributes treated as absent, environment bindings the plan does
not carry (`swift_account_id`, `swift_vpc_id`) derived from it, and resources
nested deeper than the engine-side traversal reaches lifted into the root module
with their addresses intact. Every normalisation is recorded in the evidence.

---

## 4. Core concepts

### 4.1 Control archetypes *(new, fixes gap 1)*

Classify a control **before** decomposing it; the archetype sets the realistic
assertion yield and prevents mistaking a structural property for poor work.

| Archetype | Definition | Expected yield | Observed |
|---|---|---|---|
| **Configuration** | Requirements are resource properties | High | 1.1, 2.1, 4.1, 1.4, 2.3 |
| **Meta** | Text re-applies *other* controls to a new surface | Low; high delegation | **1.3, 4.2** |
| **Process** | Human/organisational activity | ~zero; exclusions | 7.1, 7.2, 2.8 |
| **Mechanism-presence** | Runtime process whose *enablement* is declarable | 1-2 proxy assertions | **2.2, 2.7** |
| **Shared-responsibility** | Owned by the provider | Zero; CSP exclusion | 3.1 |

A Meta or Mechanism-presence control with few assertions is a **correct** result.

### 4.2 Delegation and the Ownership Register *(new, fixes the 42% finding)*

Overlap is the norm once a library exceeds a handful of controls. v2.0 promotes it
from an exclusion code to a first-class artifact.

Each distinct security requirement has exactly **one owning control**; every other
control stating it records a **Delegation**.

```
requirement:   "administrative network ports are not exposed to the internet"
owner:         1.1-A3
delegated-by:  1.2 (§ admin access), 2.3 (§ unnecessary ports)
```

1. **Single-owner rule**: a requirement is encoded **once**. Delegating controls
   never re-encode it. *This is the primary scalability mechanism.*
2. Delegation is **bidirectional in the register** (owners list dependants), so the
   blast radius of changing a rule is visible.
3. Delegations count as **covered**, not excluded (§5), correcting v1.2.1, which
   conflated "handled elsewhere" with "not handled."

### 4.3 Assurance levels *(new, replaces Full/Partial)*

| Level | Meaning | Example |
|---|---|---|
| **A1 Direct** | The check *is* the requirement | 5.4-A1 secret under a customer-managed key |
| **A2 Partial** | Covers part; remainder documented | 1.4-A3 (network egress; proxy allowlisting excluded) |
| **A3 Proxy** | Proves a *mechanism exists*, not the outcome | 2.2-A1 patch baseline; 2.7-A1 Inspector |
| **A4 Delegated** | Owned by another control | any delegation |
| **A5 Excluded** | Not evaluable; categorised rationale | 3.1 physical |

**Rule.** Attestations report the assurance mix. A control whose assertions are all
**A3 must never be presented as "compliant"** - only as "mechanism configured."

### 4.4 Scope: a resolution ladder *(revised; two dead levels retired)*

Measured: TAG 68%, ACCT 22%, VPC 11%, MODULE 0%, XREF-scope 0%. The flat five-level
taxonomy becomes an **ordered ladder**, take the first that applies, record why:

1. **Resource-identity**: the resource carries the in-scope marker (tag). *Preferred.*
2. **Containment**: it lives inside an in-scope container (VPC/subscription/project).
3. **Association**: reachable from an in-scope resource by a **declared reference**
   (never a runtime id, §4.5).
4. **Account/tenant**: the type is **untaggable or inherently account-global**;
   record the untaggability justification. *(Observed with
   `aws_s3_bucket_public_access_block`, `aws_ssm_document`, `aws_inspector2_enabler`.)*

**Reinforced rule (v1.2.1's most valuable lesson):** *scope must be **enforced in the
rule**, not merely declared in the matrix.* 16 of 19 Phase I false positives were
scope errors, not logic errors.

### 4.5 Plan-time resolvability *(new, fixes gap 3, the largest real-world risk)*

| Class | Depends on | Pre-deployment behaviour |
|---|---|---|
| **R1 Declared** | Literal attributes in the plan | Always evaluable yes |
| **R2 Reference-resolvable** | Links expressed as IaC references/addresses | Evaluable once resolved yes, presence verified, value not |
| **R3 Apply-time** | Values `known after apply` with no in-plan reference, or an embedded document whose text is unknown | **Undetermined**, reported, never passed |

1. Prefer **R1**; where a join is needed use **R2** (join on resource *address* or
   configuration reference), never **R3**.
2. An R2 value is resolved before evaluation by a deterministic stand-in derived
   from the reference, so every consumer of the same reference agrees. The
   substitution is recorded, not silent.
3. An **R3** verdict is **undetermined**, and the attestation says so. It is never
   counted as a pass; the check belongs to the post-deployment enforcement point.

**Resolvability is one cause of silent passing, not all of them.** Evaluating the
library against generated rather than hand-written plans found three distinct
mechanisms, of which this table models only the first:

| Mechanism | What happens | Remedy in the instantiation |
|---|---|---|
| **Unresolved value or key** | A rule filters or joins on a value the plan does not know; the body never completes | Resolve R2 by reference; report R3 as undetermined |
| **`null` versus absent** | Terraform writes `null` for an unset optional attribute; rules written against absence read it as present-and-satisfied | Normalise `null` to absent before evaluation |
| **Unparseable embedded document** | A policy document interpolating an unknown ARN cannot be parsed, so every rule parsing it passes | R3; undetermined, detected by witness differential |

**Which assertions are undetermined is measured, not declared.** For each R3
attribute the gate substitutes admissible witness values, an empty document and
a permissive one for a document; `false`, `true`, an arbitrary string and zero for
a scalar, since a single witness only exposes the rules it happens to move,
re-evaluates, and treats any verdict that moves as undetermined. No per-rule
annotation is maintained, so the classification cannot rot as the library grows.

**A value the author never set can still be R3.** Terraform reports many
attributes as "known after apply" without the author assigning them. Most are
outputs no rule reads, and the first resolvability pass treated all of them so.
Some are not: a root volume's `encrypted`, left unset, takes the account's EBS
encryption-by-default setting at apply time (state outside the plan) and rule
1.3-A3 reads it. Discarding it made the rule read nothing and pass silently; the
case study's change, re-run as real Terraform, exposed it. The Target Profile now
classifies every provider-computed attribute a rule reads, in one of two tables:

| Table | Meaning | Examples |
|---|---|---|
| **Apply-time defaults** | the value comes from state outside the plan -> **R3, undetermined** (resolved instead if the plan itself declares that state) | EBS `encrypted` (account default) |
| **Unset defaults** | leaving it unset has a fixed meaning, which is how the rule reads its absence | `key_name` (no key pair), `tenancy` (default), default security-group rules (removed) |

The classification is enforced mechanically: the conformance suite extracts every
attribute the library reads, intersects it with the provider-computed attributes
in each generated plan, and fails on any that neither table lists. A new rule
cannot quietly depend on an apply-time value.

*Evidence (`terraform/README.md`): on the generated non-compliant plan, 121 of the
127 v2026 assertions fire, four are undetermined by this procedure, and two are
mutually exclusive with assertions that do fire, none passes silently.*

### 4.6 Decomposition rules *(revised)*

Retained: atomicity, compound splitting, declarative compliant-state wording,
multi-service enumeration, source linkage.

**New: Independent falsifiability.** Two assertions must not stand in a
precondition relationship such that one cannot be falsified while the other is. If
A2 presupposes the resource whose existence A1 asserts, either merge them or
validate them with **separate** non-compliant fixtures.
*Evidence: "Inspector exists" + "Inspector covers EC2" was unvalidatable in one
fixture; merged into 2.7-A1.*

**New: Archetype-aware yield.** Never inflate assertion counts. Coverage is measured
by **requirement disposition** (§5), never by assertion count.

### 4.7 Assertion identity and lifecycle *(revised, critical over 20 years)*

v1.2.1 required **new assertion IDs at every regime version**. Applied literally that
renumbers the register annually, destroying traceability continuity, invalidating
prior attestation references, and making longitudinal analysis impossible. It is the
least durable rule in v1.2.1 and is replaced.

**Stable identity, versioned lifecycle:**

```
id:          4.1-A20
introduced:  v2027           # first regime version requiring it
status:      active          # active | superseded | retired
rationale:   "v2027 added failed-authentication logging and alerting"
```

Regime versions are **deltas over a persistent register**, not parallel copies.
Status changes; identity never churns.

### 4.8 Exclusion taxonomy *(revised)*

Retained: PROC, RUNTIME, PLATLIM, VENDOR, ONPREM, LEGAL, ADV, ROOT, DRIFT.
**Removed:** `XREF` - overlap is now **Delegation** (§4.2), a form of *coverage*.
**Added:** **`CSP`** - cloud-service-provider responsibility under the
shared-responsibility model (CSCF 3.1). Permanent for as long as public cloud
exists; v1.2.1 forced it to be mis-filed as PROC/ONPREM.

### 4.9 Plan completeness *(new, the second undecidability axis)*

Resolvability (§4.5) asks whether a *value* is known. Completeness asks whether
the *plan* is. They are independent, and both produce silent passes or false
alarms when ignored.

An assertion is one of two shapes:

| Shape | Finding | Sound over |
|---|---|---|
| **Resource-attributed** | "*this* resource is misconfigured" | any plan |
| **Absence** | "nothing here provides X" | a **complete** plan only |

An absence assertion (no multi-region CloudTrail, no GuardDuty detector, no
patch baseline) draws a conclusion from what the plan does *not* contain. A
plan for a change contains only what changes, so on an incremental plan the
conclusion is unsupported: the account's CloudTrail is absent from the document,
not from the account.

The consequence is severe in practice and in the wrong direction from §4.5:
where an unresolved value produces a silent *pass*, an incomplete plan produces
a confident *false alarm* on every pull request, which is how a gate gets
switched off.

**The discipline.** A Target Profile declares whether a plan is `full` or
`incremental`. Absence assertions are evaluated only under `full`; under
`incremental` they return **undetermined**, and the account-level posture is
verified separately by a scheduled full-environment evaluation; which is the
correct enforcement point for an account-level control in any case.

**Detection needs no registry.** An absence finding *cannot name a resource*,
because the resource is what is missing. The message shape is therefore the
classifier: a finding without a resource attribution is asserting an absence.
This holds by construction rather than by convention, and it distinguishes
absence from its opposite, "this resource must not exist" names the offending
resource, is present in the change itself, and stays decidable.

---

## 5. Coverage metrics, defined once, reported consistently

The project's own "95 / 88 / 108" ambiguity shows why these need normative
definitions.

| Metric | Definition |
|---|---|
| **Requirements identified** | Verifiable/obligation items extracted in Parse |
| **Requirement disposition** | Each is exactly one of *covered*, *delegated*, *excluded*, *informational* |
| **Assertions defined** | Atomic assertions in the register |
| **Rules defined** | Executable rules encoded, may exceed assertions (one assertion -> several rules, e.g. IPv4 + IPv6) |
| **Assertions exercised** | Distinct assertions fired by the non-compliant corpus |
| **Violation instances** | Individual findings (one assertion may match many resources) |

**Gate A (Disposition):**
```
covered + delegated + excluded == requirements identified − informational
```
**Exercise ratio** = assertions exercised ÷ assertions defined, a measure of
**fixture-corpus** quality, explicitly *not* of library quality.

*Phase I restated: 95 rules defined, 88 assertions exercised, 108 violation
instances, three distinct quantities, now unambiguous by definition.*

---

## 6. The Re-baseline loop (regime version change)

v1.2.1 said only "re-execute Stages 1-4.5" - prohibitively expensive annually. The
v2026 -> v2027 migration proved a cheaper, rigorous procedure, now codified.

1. **Structural diff**, control inventories: added / removed / renamed /
   re-classified (mandatory <-> advisory) / applicability changed.
2. **Textual diff per control**: normalised, noise-filtered (strip headers,
   pagination, footnote renumbering, hyphenation).
3. **Classify each change:**

| Impact | Meaning | Action |
|---|---|---|
| **I0 Editorial** | Wording only ("should"->"must") | Note only |
| **I1 Terminology** | Defined-term rename | Update message text |
| **I2 Scope-shift** | In-scope components / applicability changed | Re-run Scope |
| **I3 New requirement** | New obligation | Full Parse->Attest for it |
| **I4 Retired** | Obligation removed | Set status `retired` |

4. **Emit a delta report**: impact class and library action per control.

*Applied to v2026 -> v2027 (32 controls): 0 added/removed/reclassified; 12 of 15
implemented controls I0; 2 I2; **1 I3**. The migration cost one new assertion, the
empirical demonstration that the framework is version-resilient.*

---

## 7. Gate C, conformance made executable

v1.2.1 listed nine validation criteria as prose. Prose criteria are not run, so they
decay. Gate C is executable:

| Criterion | Executable form |
|---|---|
| No false positives | Every compliant fixture (and the compliant *generated* environment, across every control) yields zero findings |
| **Coverage symmetry** | Every non-compliant fixture fires **exactly** its expected assertion set |
| **Whole-library accounting** | On the generated non-compliant plan, fired + undetermined + explained assertions equal the library, nothing passes silently |
| Scope correctness | Moved out of the Swift zone, a non-compliant corpus trips no resource-scoped assertion; only account-scoped ones may fire |
| Defect pins | Each known defect still reproduces under the archived version that had it, so the claim that it was broken is itself under test |
| Metric integrity | Defined counts asserted against fixed values |
| Performance | Evaluation within a stated budget |

*Realised as the conformance suite (`tests/`), alongside the two Gate B audits.* **Rule:**
an assertion is not "done" until it has an expected-set entry in the conformance
suite.

**The scope criterion was listed before it was implemented.** For most of Phase II
this table claimed an out-of-scope test that no test performed, and that is
precisely why 39 rules declaring a resource scope and applying none went
unnoticed. A criterion written in a gate definition is a claim; only an
executable one is a check.

---

## 8. Scalability and longevity

| Dimension | Growth cost | Mechanism |
|---|---|---|
| More controls | Sub-linear in practice | Delegation prevents re-encoding shared requirements (42% of outcomes) |
| More clouds / IaC | Plane 2 only | Same Assertion Register, new Target Profile |
| New policy engine | Plane 3 only | Re-encode from unchanged Binding Specifications |
| New regime | Plane 1 addition | New Regime Profile; lower-plane patterns reused |
| Regime version | Delta only | Re-baseline loop |

**What will change in 20 years, and where it lands:**

| Change | Absorbed by |
|---|---|
| CSCF v2028 ... v2045 | Re-baseline loop |
| Terraform superseded (Pulumi / Crossplane / CDK) | New Target Profile; Plane 1 untouched |
| OPA/Rego superseded | New Engine Profile; specifications unchanged |
| New services / attribute churn | Re-run Map for affected assertions |
| Multi-cloud mandate | Additional Target Profiles over one register |
| New regulations (DORA, NIS2, successors) | Additional Regime Profiles; cross-regime delegation |
| Shift-left -> continuous/runtime | R3 assertions migrate to a runtime enforcement point |

**Residual limitations, stated plainly.**
- The framework governs *static, declarative* evaluation. Irreducibly procedural,
  physical, or runtime requirements (PROC/RUNTIME/CSP, 36% of observed exclusions)
  will never be automatable by it. Its contribution is to make that boundary
  **explicit, categorised and auditable** rather than invisible.
- Cross-regime delegation is designed but **not yet empirically exercised**, stated
  future work, not a claim.

---

## 9. Migration from v1.2.1

| v1.2.1 | v2.0 | Action |
|---|---|---|
| 7 stages (incl. "2.5" and "4.5") | **6 stages + 3 gates over 3 planes** | Scope joins Binding; Trace becomes Gate A; Specify becomes an artifact |
| `XREF` exclusion | **Delegation** (a form of coverage) | Reclassify 33 entries |
| `Full` / `Partial` | **A1-A5 assurance levels** | A3 for the 2.2 / 2.7 proxies |
| 5 flat scope levels | **4-step resolution ladder** | Retire MODULE and XREF-scope (0 uses) |
| Spec variants A-F | Retained; **D under review** (0 uses) | Note Variant E's R3 fragility |
| "New IDs each version" | **Stable IDs + lifecycle** | 4.1-A20 `introduced: v2027` |
| Prose validation criteria | **Executable Gate C** | Already realised (`tests/`) |
| - | Control archetypes | Classify the 15 implemented controls |
| - | Plan-time resolvability | Label 1.4-A6 as R3 |
| - | `CSP` exclusion category | Reclassify 3.1 |

**Backwards compatibility.** No encoded rule changes behaviour. v2.0 is a
*methodological* revision (restructuring, re-labelling, added metadata) so the
existing library, the conformance suite as it stood at the migration (28 tests; 95 today), and every committed attestation
remain valid. The frozen Phase I code is untouched; only the narrative around it is
unified. (The Phase I code was later corrected by a separate, visible re-issue
(policy library 2.0.0, `../policies/CHANGELOG.md`) with 1.0.0 archived and
still executable.)

---

## 10. Contribution statement

> The Translation Framework v2.0 separates regulatory interpretation (normative
> plane) from technology binding (binding plane) and enforcement realization
> (realization plane), so that the expensive expert act of reading a regulation is
> performed **once** and survives changes of cloud, IaC tool and policy engine. It
> introduces requirement **Delegation** (empirically the outcome of 42% of
> decomposition) as the mechanism that keeps a growing library non-duplicative;
> **assurance levels** that prevent a static check being reported as proof of a
> runtime property; **plan-time resolvability** classes that expose checks which
> would otherwise fail open before deployment; and a formal **re-baselining** loop
> whose application to CSCF v2026 -> v2027 cost a single new assertion across 32
> controls.

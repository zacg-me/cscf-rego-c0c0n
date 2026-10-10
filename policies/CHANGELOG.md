# Policy library: changelog

The CSCF policy library has four versions. The gate records the version and a
digest of the library source in every evidence artefact (`library` block), and
the attestation report shows both.

| Version | Where | What it is |
|---|---|---|
| **2.1.2** | `policies` | The current library: 15 controls, 130 assertions, 147 rules. |
| 2.1.1 | `policies` (history) | 1.1-A15 corrections: 130 assertions, 147 rules. |
| 2.1.0 | `policies` (history) | Adds 1.1-A15: 130 assertions, 145 rules. |
| 2.0.0 | `policies` (history) | 15 controls, 129 assertions, 144 rules. |
| 1.0.0 | not published here | The first research library, 5 controls, 95 rules. Its defects and their corrections: `../docs/failure-modes.md`. |

Rego merges a package across files, so two policy roots that define the same
file would be evaluated together silently; the gate refuses them
(`check_policy_roots`).

---

## 2.1.2: plain punctuation (October 2026)

No rule changes: the same 147 rules over the same 130 assertions, and the same
findings on both reference estates. Comments, finding messages and the gate's
summary use plain punctuation (no em-dashes, emoji or box drawing), so the
library digest changes and the version moves with it.

## 2.1.1: 1.1-A15 corrections from the final review (October 2026)

Three paths let an out-of-boundary grant go unreported, with nothing
undetermined. Each is now a test (`tests/test_trust_boundary.py`).

- **A guessed account widened the boundary.** With no `account_id` variable,
  `resolve_plan.py` took the Swift account from the first ARN in the plan
  (often the partner principal in the very policy under review) and put it
  inside the boundary. Only an explicitly stated account joins the boundary
  now; without a declaration or an explicit account, the boundary is unbound
  and 1.1-A15 is undetermined.
- **Two missing inputs added up to a pass.** A policy on a bucket outside the
  plan, or with a document unknown at plan time, on a plan with no boundary
  bound: each witness supplied only its own input. A missing boundary is now
  supplied to every witness and to its baseline (`gate._with_missing_bindings`).
- **Principal forms passed silently.** `Federated` identity-provider ARNs now
  yield their account; `CanonicalUser` grants and `Allow` + `NotPrincipal`
  fire (two new rules under 1.1-A15; 147 rules).

Also: the binding witness keeps a hand-written plan's stated Swift account
inside the boundary, so a grant to that account alone is no longer reported
undetermined. The generated environments' verdicts are unchanged.

---

## 2.1.0: trust-boundary assertion 1.1-A15 (October 2026)

**Added:** 1.1-A15, a Swift-zone bucket policy granting an account outside the
declared trust boundary (`translations/1_1_a15_trust_boundary.md`). The first
relational rule over a *declared environment boundary*: neither the bucket nor
the policy is wrong on its own.

**New binding:** `input.swift_trust_boundary_accounts` (`resolve_plan.py`),
from the `swift_trust_boundary_accounts` Terraform variable; the Swift account
is always inside.

**New undetermined cause:** `unbound-environment`. When no boundary is bound
the rule cannot decide; the gate supplies an empty boundary as a witness and
reports what fires only then.

**Witness change:** the permissive witness document now also names an account
outside any boundary (`999999999999`), so R3 bucket policies are reported
undetermined for 1.1-A15 rather than passing it. On the generated reference
environments no other assertion moved; on an estate whose policy documents are
unknown at plan time, the extra principal can also, correctly, expose other
cross-account assertions as undetermined.

**Generated environments:** the non-compliant one gains `partner_share` (one
1.1-A15 instance: 151 findings, 122 assertions); 1.1-A15 is undetermined on
its three R3 bucket policies. The compliant one gains `swift_dr_exchange`, a
grant to the DR account inside the declared boundary, and still passes with 0
findings; 1.1-A15 is undetermined on its two R3 bucket policies.

**Unchanged:** every existing assertion id, finding message and verdict.

---

## 2.0.0: re-issue of the Phase I library (September 2026)

### Why a re-issue

The September 2026 library review found
defects of two kinds in the Phase I library. A rule that **misses** findings
can be corrected by adding a rule: Rego merges a package across files, so a
Phase II file declaring the same package adds to the same `deny` set. Phase II
did that for every such defect. A rule that **over-reports** cannot be
corrected that way (an added rule can add findings but never withdraw one)
and 42 rules were in that state. Correcting them meant changing the library
itself, which is done here as a new version rather than an edit to the
submitted one.

The re-issue also merges the Phase I controls and the Phase II corrections into
one library: the seven Phase II files that joined the 1.0.0 packages are folded
into the controls they corrected, and the rules they superseded are gone.

**Unchanged:** every assertion id, every finding message, every assertion title
and source reference; the ten Phase II controls (1.2-5.4) apart from comments;
the v2027 delta. A finding from either version resolves to the same regulatory
requirement.

### Results, before and after

| | 1.0.0 + Phase II additions | 2.0.0 |
|---|---|---|
| Rules, assertions | 153 (150 active, 3 superseded), 129 | **144**, 129 |
| Generated compliant environment | PASS, 0 findings | PASS, 0 findings |
| Generated non-compliant environment | 150 findings, 121 of 127 assertions | 150 findings, 121 of 127, **identical** |
| Rules declaring a resource scope and not applying it | 39 (over 35 assertions) | **0** of 87 |
| Inadmissible attribute reads (Gate B) | 3, allowlisted | **0** of 383, nothing allowlisted |
| Resource three modules deep (R8 plan) | invisible without gate normalisation | found as supplied |
| Phase I mock plan, non-compliant | 111 findings | 102 findings + 8 undetermined (see below) |
| Conformance tests | 69 | 91 |

The generated environments are unchanged finding for finding. That is the
expected outcome: both carry every zone signal (tags, the Swift VPC binding, a
parent for every attachment), so correct scoping costs no detection there. The
difference shows where those signals are absent (a shared account, a change
plan, a hand-written plan) and the tests demonstrate each case.

### The 42 over-reporting rules

**Declared scope implemented: 39 rules over 35 assertions.** Each rule's
`# Scope:` header named the population it applied to; 1.0.0 applied none and
evaluated account-wide, so a non-Swift resource in the same account was
reported as a CSCF violation.

| File | Rules | Assertions | Scope now applied |
|---|---:|---|---|
| `ctrl_1_1.rego` | 15 | A1-A11 | VPC: `zone_scope.in_swift_zone` (Swift VPC binding, or the zone tag). A6 through the route table; A10 TAG; A11 through the VPN endpoint. A9 counts only a flow log in the Swift zone. |
| `ctrl_2_1.rego` | 15 | A1-A15 | TAG: `helpers.is_swift_tagged`. A12 through the EFS file system. |
| `ctrl_4_1.rego` | 6 | A11-A13, A16-A18 | TAG. A16 through the secret it rotates. |
| `ctrl_5_1.rego` | 2 | A16, A17 | TAG, on the Lambda function / ECS task definition that uses the role. |
| `ctrl_6_4.rego` | 1 | A5 | VPC: counts only a flow log in the Swift zone. |

A sub-resource that cannot carry a tag or a `vpc_id` - a route, a VPN
authorisation rule, a file-system policy, a secret rotation, a standalone
security-group or ACL rule, takes the scope of the resource it belongs to,
through `parent_scope.parent_swift_tagged` / `parent_in_swift_zone`.

**2.1-A12: condition value compared as a string only (R7).** `Bool =
{ "aws:SecureTransport" = false }` emits a JSON boolean, and 1.0.0 compared
against the string `"false"`, so a correct TLS-only EFS policy was reported as
violating. Both spellings are accepted (`helpers.is_false`).

**1.1-A13: service role flagged when its trust policy is unreadable (R9.2).**
`not is_service_only_role(role)` also holds when the trust policy is unknown at
plan time or not valid JSON. The rule now requires `helpers.is_human_assumable`,
which holds only for a trust policy that parses and admits a non-service
principal. 1.1-A12 and 1.1-A14 use the same predicate.

**1.1-A6: `contains(gateway_id, "")` matches every route (R9.4).** An internet
gateway with an empty id matched every route in the plan. The id must be
non-empty.

### Corrections folded in from Phase II

These were already in effect as Phase II files joining the 1.0.0 packages; they
now live in the controls they correct. Behaviour is unchanged except where
noted.

| Was | Now | Review |
|---|---|---|
| `ctrl_1_1_rescoped.rego`, `ctrl_2_1_rescoped.rego`, `ctrl_5_1_rescoped.rego` | 1.1-A14, 2.1-A16, 5.1-A11 scoped through the parent role / bucket; the three inert 1.0.0 rules (a tag test on an untaggable type) are removed | generated plans |
| `ctrl_1_1_conditions.rego` | 1.1-A12 checks the MFA condition's value; the two rules are one | R6 |
| `ctrl_1_1_network_coverage.rego` | standalone security-group rules, custom ACLs and `protocol = "-1"` under 1.1-A2/A3/A4/A7/A8, **now also VPC-scoped** through the parent group or ACL | R5 |
| `ctrl_2_1_empty_blocks.rego` | superseded by `helpers.block`, below; the three rules are removed | R9.3 |
| `ctrl_5_1_inline_policies.rego` | user and group inline policies, **now for 5.1-A1, A2, A10, A12-A15**, not only A1/A2 | R9.5 |

### Corrections that were deferred because the library was frozen

| Defect | Correction | Review |
|---|---|---|
| Resources more than two module levels deep were invisible | `helpers.all_resources` traverses every depth | R8 |
| `Statement` given as a single object was read as its fields | `helpers.statements` normalises it; used by every rule that reads a policy document in the five controls | R9.1 |
| An explicitly empty nested block (`[]`) made the rule pass silently | `helpers.block` returns `{}` for an absent or empty block, 2.1-A7-A11, 4.1-A11-A13 and A16-A18, 6.4-A14, A16, A18 | R9.3 |
| `contains(x, "")` in 5.1-A16/A17 matched every role; an empty `swift_account_id` in 5.1-A18 counted every root ARN as same-account | both sides of each join must be non-empty | R9.4 (same pattern) |
| An inline ACL rule and an `aws_network_acl_rule` were read through one helper that read `rule_action` on both | one helper per shape; found by the widened admissibility check | - |

### A new undetermined cause: the parent is not in the plan

Scoping a sub-resource through its parent raises a question 1.0.0 never had to
answer: what if the parent is not in the plan? A change plan references
existing resources by id all the time, and the Phase I mock plan references
parents it never defines (`rtb-bad`, `fs-bad`, `cvpn-bad`...). Treating that as
out of scope would be a silent pass; treating it as in scope would bring back
the over-reporting. The honest answer is the third verdict.

The gate supplies each missing parent inside the Swift zone in a witness plan
(`find_scope_undetermined`, the same differential as for values unknown until
apply). A finding on the sub-resource that appears only then is reported as
**undetermined**, kind `unresolved-scope`, naming the missing parent. On the
Phase I mock plan that accounts for all 9 findings 2.0.0 no longer attributes
(`test_missing_parent_is_undetermined_not_silent`).

### Tooling

- **gate.py**: defaults to the 2.0.0 library and all fifteen controls; records
  `library: {version, digest, files}` in the evidence; refuses to load two
  roots that define the same file; reports missing-parent undetermined checks.
- **Audits**: both run on the library alone, with empty allowlists. The
  admissibility check now follows `helpers.block`, parent lookups and reads
  through an alias (383 reads, from 308).
- **Traceability matrix**: built from 2.0.0; the superseded and correction
  columns are gone, and each assertion's `defect` field records what was
  corrected and in which version.
- **Attestation report**: shows the library version and digest, and the cause
  of each undetermined check.

### Rule count, 153 -> 144

| | Rules |
|---|---:|
| 1.0.0 (95) + Phase II controls and additions | 153 |
| inert 1.0.0 rules superseded by the re-scoped ones | −3 |
| empty-block rules, now covered by `helpers.block` | −3 |
| 1.1-A12 value correction, merged into the 1.1-A12 rule | −1 |
| inline-policy rules, merged into 5.1-A1 and A2 by resource type | −2 |
| **2.0.0** | **144** |

### 1.0.0 in this repository

The 1.0.0 library is not published here. What it got wrong, and how 2.0.0
corrected each defect, is in `../docs/failure-modes.md`; the record of the 39
unapplied scopes is kept as data in `pipeline/audit/scope_audit.py`
(`PHASE1_MISMATCHES`).

---

## 1.0.0: first research library

Five controls (1.1, 2.1, 4.1, 5.1, 6.4), 91 assertions, 95 deny rules, validated
on hand-written mock plans (now `fixtures/phase1_mock/`). Not published in this
repository; see `docs/failure-modes.md`.

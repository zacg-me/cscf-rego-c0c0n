# Real Terraform plans driving the gate

Phase I validated the policy library against **hand-written mock plan JSON**.
That is a circular test: the same author shaped both the rule and the document
it reads, so a rule could only fail if the mock disagreed with itself. This
deliverable replaces the mock with a genuine `terraform plan -json` and reports
what changed, including the five assertions that turn out to be unable to fire
against any real plan.

---

## What is here

```
terraform/compliant/main.tf        75 resources, expected to pass the gate
terraform/non_compliant/main.tf    deliberately insecure fixture
../plans/*_live_plan.json          terraform show -json output (committed)
../plans/*_resolved_plan.json      after the resolvability pass
../plans/*_resolvability.json      what the resolver had to assume
../plans/*_resolved_evidence.json  gate evidence for the live plans
../pipeline/resolve_plan.py        the resolvability pass
../pipeline/plan_and_gate.sh       one command: plan -> resolve -> gate
```

The `.tf` files are repaired copies of the first-phase fixtures, which were
invalid HCL and never ran. The environments are gated by the current policy
library (`../policies/CHANGELOG.md`).

## Provider version

Both environments pin `hashicorp/aws ~> 5.0`, with `.terraform.lock.hcl`
committed at 5.100.0. This is a deliberate decision, not drift: the argument
rests on what the provider schema says a resource type has, so the schema the
Gate B admissibility check reads must be the schema the plans were generated
against. Moving to 6.x is a re-baseline of the Target Profile, re-run both
audits and the conformance suite as part of it.

## Running it

```bash
pipeline/plan_and_gate.sh            # both fixtures
pipeline/plan_and_gate.sh compliant  # just one
```

No AWS account is needed. The provider is configured with mock credentials and
every credential, account and metadata lookup is skipped, so `terraform plan`
runs offline; the two `data` sources Phase I used (`aws_caller_identity`,
`aws_region`) were replaced by a `region` variable for the same reason.

## Result

Both environments are gated against **all fifteen implemented controls**, not
just the five of Phase I:

| Fixture | Live gate result | Instances | Distinct assertions | Controls | Undetermined |
|---|---|---:|---:|---:|---:|
| compliant | **PASS** | 0 | 0 | 15 | 8 |
| non-compliant | **FAIL** | 150 | 121 | 15 | 8 |
| non-compliant (Phase I mock, five controls) | FAIL | 108 | 88 | 5 | - |

**121 of the 127 v2026 assertions fire on the generated non-compliant plan, and
the other six are accounted for, none passes silently:**

| Not fired | Why |
|---|---|
| 2.1-A12, 2.1-A16, 5.1-A11, 6.4-A17 | **undetermined**, each parses a policy document whose text interpolates an ARN Terraform resolves only at apply |
| 4.1-A1 | mutually exclusive with 4.1-A2...A10: a weak password policy exists, so "no policy at all" cannot also hold |
| 4.1-A18 | mutually exclusive with 4.1-A17: fine-grained access control is off, so the internal-user-database branch is unreachable |

The re-issue to 2.0.0 left both environments' results unchanged finding for
finding; 2.1.0 adds one (1.1-A15 on `partner_share`).

---

## Stage 1: the HCL was never valid

The Phase I `.tf` files had never been run through Terraform. They were written
as compressed one-liners using `;` as a separator:

```hcl
parameter { name = "rds.force_ssl"; value = "1" }                    # invalid
encryption_in_transit { client_broker = "TLS"; in_cluster = true }   # invalid
```

HCL accepts a one-line block body only when it holds a single attribute, and
never accepts `;`. 148 semicolons across the two files were expanded, into
newlines at a block's top level, into commas inside an object constructor. One
further defect was a genuine provider conflict: `manage_master_user_password =
false` alongside `password`, which the AWS provider rejects outright.

Both configurations now pass `terraform validate` and produce a plan.

## Stage 2: a real plan does not look like the mock

Running the gate on the *unmodified* live plan produced **11 violations against
the compliant fixture**. Two were genuine misconfigurations (Stage 3 below); the
other nine were not compliance failures at all. Three differences between real
and mock plan JSON account for those nine.

**1. Unknown values.** An attribute assigned from another resource is not
computed until apply:

```hcl
kms_key_id = aws_kms_key.swift_logs.arn
```

Terraform writes `null` into `change.after` and records the attribute under
`change.after_unknown`. A rule that reads only `after` sees an absent attribute
and denies a correctly configured plan. The mock plans carried resolved values
that no real plan can know at this point.

**2. `null` versus absent.** Terraform writes `null` for an optional attribute
the author left unset; the mock plans omitted the key. Rules are written
against absence, `object.get(values, "access_group_id", "") == ""` - and
`null` is not `""`, so an unset attribute reads as *present and fine*. This
direction is worse than a false positive: it is a **silent pass**.

**3. Environment bindings that Terraform does not carry.** The library reads
`input.swift_account_id` and `input.swift_vpc_id`. Neither exists in a
`terraform show -json` document; they were fields the mock plans supplied out
of band. Without them, `5.1-A18` cannot tell same-account trust from
cross-account (false positive), and every VPC-scoped rule (which filters on
`vpc_id == input.swift_vpc_id`) matches nothing at all and passes silently.

### The resolvability pass

`pipeline/resolve_plan.py` closes these gaps before the gate runs, and records
every assumption it made. Each unknown attribute is classified:

| Class | Meaning | Treatment |
|---|---|---|
| **R1** | resolved in the plan | nothing to do |
| **R2** | unknown, but the configuration shows it is assigned from a resource this same plan creates | filled with a deterministic stand-in derived from the reference; **presence** is verified, the value is not |
| **R3** | unknown with no in-plan reference, or an embedded JSON document whose text is unknown | left unset and reported: no static check can decide it |
| **C** | provider-computed output nobody assigned (`arn`, `id`, `owner_id`) | counted only; not a policy input |

The stand-in is a pure function of the reference, so every consumer of the same
reference receives the identical value (which is what makes a scope filter
such as `vpc_id == input.swift_vpc_id` work again) and it is built around the
target's own known name where the plan has one, so a join like *does this
Lambda's role ARN contain that attachment's role name* still matches.

On the two fixtures:

| | compliant | non-compliant |
|---|---:|---:|
| R2 resolved by reference | 46 | 30 |
| R2 self-identity (`id` / `arn` filled so cross-resource joins work) | 131 | 109 |
| R3 unresolvable | 4 | 4 |
| provider-computed | 502 | 496 |
| `null` attributes dropped | 178 | 158 |

Every R3 in both fixtures is the same thing: an IAM or bucket **policy document
whose text interpolates an unknown ARN**, so the whole JSON string is unknown.
Nothing can be substituted, and the assertions that parse those documents
cannot be evaluated at all.

## Stage 3: what the live plan found

### Three real defects in the "compliant" fixture

The gate caught three genuine misconfigurations that the mock plan had hidden,
each fixed in `compliant/main.tf`:

| Assertion | Defect | Fix |
|---|---|---|
| 5.1-A14 | `swift-security-officer` granted `iam:CreatePolicy` **and** `iam:AttachGroupPolicy` in one document, a separation-of-duties violation | split into `swift-policy-author` and `swift-policy-attacher` |
| 1.1-A12 | the cross-account audit role carried an ExternalId but no MFA condition | added `aws:MultiFactorAuthPresent` |
| 1.1-A13 | the same role had no permissions boundary | added `SwiftZoneBoundary` |

### Five assertions that could not fire on a real plan

83 of the 88 assertions the mock exercises fired on the first live run. The
remaining five were not fixture gaps; they were defects in the library, and
only a live plan could reveal them.

| Assertion | Cause | Now |
|---|---|---|
| 1.1-A14 | TAG-scoped on `aws_iam_role_policy` | re-scoped; **fires** |
| 2.1-A16 | TAG-scoped on `aws_s3_bucket_policy` | re-scoped; **undetermined** |
| 5.1-A11 | TAG-scoped on `aws_s3_bucket_policy` | re-scoped; **undetermined** |
| 2.1-A12 | parses the `policy` document of `aws_efs_file_system_policy` | **undetermined** |
| 6.4-A17 | parses the `policy` document of `aws_s3_bucket_policy` | **undetermined** |

**The first three were unsatisfiable.** Neither `aws_iam_role_policy` nor
`aws_s3_bucket_policy` accepts a `tags` argument, the AWS provider rejects the
configuration outright:

```
Error: Unsupported argument
  An argument named "tags" is not expected here.
```

So `helpers.is_swift_tagged(resource)` could never hold for those types. The
mock plans gave those resources tags anyway, and the assertions passed
validation that way. On real infrastructure they were dead rules.

They are fixed: scope now comes from the parent bucket or role, first in
Phase II files that joined the Phase I packages without editing them, and since
library 2.0.0 in the controls themselves, with the dead rules removed. The
record is `../translations/binding_corrections.md`. Only 1.1-A14 gains a real verdict,
the other two read a bucket policy whose text is unknown at plan time, so once
in scope they are undetermined rather than passing.

**The last two are undecidable at plan time**, not wrong. They belong to the R3
class above: the document they need to parse does not exist yet. The gate
reports them as *undetermined* rather than as passes, see below.

## The third verdict

`gate.py --resolvability <report.json>` adds **UNDETERMINED** alongside pass and
fail, the three-valued result the translation framework argues policy engines should expose
(`framework/translation_framework_v2.md` §R1-R3).

Which assertions are undetermined is **measured, not declared**. The gate builds
a *witness plan*, the resolved plan with every R3 attribute given an admissible
value (an empty but syntactically valid policy document), evaluates it, and
diffs the two runs per (assertion, resource). Any verdict that moves between the
two was never determined by the plan. No hand-maintained map of which rule reads
which attribute is needed, and the method stays correct as the library grows.

Two witness documents are used, because one only exposes the rules it happens to
move: an assertion demanding a restriction ("the policy must deny non-TLS
access") is exposed by an **empty** document, while one forbidding a permission
("the policy must not allow any principal") is exposed by a **permissive** one.
An assertion is undetermined if either witness moves it.

On the compliant fixture the diff isolates:

```
UNDETERMINED (7) -- not evaluated, not passed:
       ? CSCF 2.1 [2.1-A12] aws_efs_file_system_policy.swift.policy unknown at plan time
       ? CSCF 2.1 [2.1-A16] aws_s3_bucket_policy.swift_data_tls.policy unknown at plan time
       ? CSCF 2.1 [2.1-A16] aws_s3_bucket_policy.trail.policy unknown at plan time
       ? CSCF 5.1 [5.1-A1]  aws_iam_policy.swift_deploy.policy unknown at plan time
       ? CSCF 5.1 [5.1-A11] aws_s3_bucket_policy.swift_data_tls.policy unknown at plan time
       ? CSCF 5.1 [5.1-A11] aws_s3_bucket_policy.trail.policy unknown at plan time
       ? CSCF 6.4 [6.4-A17] aws_s3_bucket_policy.trail.policy unknown at plan time
```

Every one is a policy document whose text interpolates an ARN that Terraform
resolves only at apply.

The evidence JSON gains an `undetermined` array and two summary counts, and the
attestation report renders a dedicated **Undetermined Checks** section; a plan
with no violations but undetermined checks is attested as *"COMPLIANT, WITH
UNDETERMINED CHECKS"*, never as a clean pass. Both fields are additive, so
evidence consumers written against schema v1 are unaffected.

Undetermined checks do not block by default, `plan_and_gate.sh` reports them.
`--fail-on-undetermined` exits non-zero instead, which is the posture a
production SWIFT zone should run: what the gate could not evaluate must not
silently ship.

## Whole-library coverage (review findings R3, R4)

This check originally covered the five Phase I controls. Gated against all fifteen, the
"compliant" environment failed seven of them, and the ten Phase II controls had
never been evaluated against a generated plan at all, the circularity this check exists
to remove still applied to two thirds of the library.

Both environments were extended. The compliant one gained the jump server,
patching, vulnerability scanning, VPC endpoints, Session Manager preferences,
back-office connectivity and secret storage that the Phase II controls check;
the non-compliant one gained the corresponding violations. Two further defects
surfaced in the process, both of the kind only a real plan exposes:

**Nested unknowns were not resolved.** The resolvability pass handled top-level
attributes only, so `vpc_options { subnet_ids = aws_subnet.swift[*].id }` (the
unknown one level inside a block) still read as absent and produced a false
positive. `resolve_plan.py` now walks nested `after_unknown` structures against
the configuration's nested expressions.

**A second unsatisfiable assertion.** 4.2-A4 tested
`advanced_security_options[_].saml_options[_].enabled`, but the AWS provider has
no `saml_options` block there, SAML federation is a separate resource. That
branch could never hold. It was found by extending the Gate B admissibility
check to follow nested blocks and private helpers, and is fixed to read
`aws_opensearch_domain_saml_options`.

The check runs in CI over the whole library. On library 2.0.0 it validates
**383 attribute reads against the provider schema with nothing allowlisted**:
the three Phase I defects were removed by the re-issue, so any inadmissible
read fails the build.

## Module depth (review finding R8)

`nested_modules/` is a third, deliberately small environment: root -> `zone` ->
`network` -> `edge`, with a single security group open to SSH from the internet
three modules down. The library's resource traversal walks the root and two
levels of child modules, so on the plan as Terraform emits it the gate reported
**PASS**.

`gate.py` now lifts any resource nested deeper than the traversal reaches into
the root module before evaluation, keeping its full address, and records that it
did so in the evidence. The same plan fails on 1.1-A2 and 1.1-A3, each naming
`module.zone.module.network.module.edge.aws_security_group.edge`. The plan is
committed as `plans/nested_modules_live_plan.json`; the tests read it from there.

## Consequences

1. Validation is no longer self-referential. The compliant fixture passes and
   the non-compliant fixture is blocked on plans Terraform actually produced,
   from HCL Terraform actually accepts.
2. The honest coverage number against live plans is **83 of 88 assertions**,
   with a stated reason for each of the five.
3. The fail-open claim is now an empirical result rather than an argument: it
   was measured in three distinct forms, unknown scope keys, `null`-versus-
   absent, and unparseable policy documents.
4. The gate no longer overstates what a pre-deployment check can attest.
   Undecidable assertions are reported as undetermined instead of counted as
   passes, and an assessor is told to verify them post-deployment.
5. **No assertion passes silently, across the whole library.** Of the 128 v2026
   assertions (library 2.1.0), 122 fire on the generated non-compliant plan, 4
   are undetermined, and 2 are mutually exclusive with assertions that do fire. The unsatisfiable
   ones are re-scoped onto the resource that actually carries the tag
   (`../translations/binding_corrections.md`), and that correction immediately
   found a real defect in the Phase I compliant mock plan.
6. LCT Gate B should gain a mechanical check that every attribute a rule reads
   (scope attributes included) exists on that resource type in the provider
   schema. It is a one-command check, and it would have caught all three at
   authoring time.

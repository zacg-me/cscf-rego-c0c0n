# Binding corrections: 1.1-A14, 2.1-A16, 5.1-A11

An LCT record of a Phase II correction that touches only the **Binding plane**.
The normative reading of all three assertions is unchanged; what was wrong was
the Target Profile fact each one relied on.

## The defect

All three assertions scoped themselves with `helpers.is_swift_tagged` applied to
an *attachment* resource:

| Assertion | Resource type | Requirement |
|---|---|---|
| 1.1-A14 | `aws_iam_role_policy` | inline role policy must deny non-MFA sessions |
| 2.1-A16 | `aws_s3_bucket_policy` | bucket policy must enforce TLS-only access |
| 5.1-A11 | `aws_s3_bucket_policy` | bucket policy must not allow any principal |

Neither resource type accepts a `tags` argument. The AWS provider rejects the
configuration outright:

```
Error: Unsupported argument
  An argument named "tags" is not expected here.
```

So `is_swift_tagged` could never hold and the three assertions were
**unsatisfiable against any real Terraform plan**; they passed silently on
every input. The hand-written Phase I mock plans gave those resources tags
anyway, which is how the defect survived validation. It surfaced only when the gate
was given a genuine `terraform plan -json` through the gate.

## The correction

An attachment inherits the scope of the resource it attaches to. Scope now
resolves through the parent:

- `aws_s3_bucket_policy` -> the `aws_s3_bucket` it names in `bucket`
- `aws_iam_role_policy` -> the `aws_iam_role` it names in `role`

`policies/swift_cscf/v2026/parent_scope.rego` performs that lookup, matching on
`name`, `bucket` or `id` so the join survives either spelling. 1.1-A14 already
resolved the parent role in order to test whether it is human-assumable; the
correction reuses that role for the scope test too.

> **Since library 2.0.0** the corrected rules live in the controls themselves
> and the three dead Phase I rules are removed (`../policies/CHANGELOG.md`). The
> paragraph below describes how the correction was first made, while the Phase I
> library was frozen.

**Phase I is not edited.** Rego merges a package across files, so each corrected
rule lives in a Phase II file declaring the frozen Phase I package
(`ctrl_1_1_rescoped.rego`, `ctrl_2_1_rescoped.rego`, `ctrl_5_1_rescoped.rego`)
and joins the same `deny` set under the same assertion id. Loading only the
Phase I root reproduces the original behaviour exactly; loading both applies the
correction. The superseded Phase I rules stay in place and remain inert (their
tag test cannot hold for those resource types) and because `deny` is a set of
strings, a rule that did fire under both scopings would produce one identical
message, not two.

## Effect

| | before | after |
|---|---|---|
| assertions firing on the live non-compliant plan | 83 of 88 | **84 of 88** |
| assertions silently passing | 3 | **0** |
| assertions reported as undetermined | 2 | **4** |

Only 1.1-A14 gains a real verdict: it reads an inline document the plan already
knows. 2.1-A16 and 5.1-A11 read a bucket policy whose text interpolates an ARN
Terraform does not resolve until apply, so once in scope they are **undetermined**
rather than passing; which is the honest answer, and the one the gate now
reports (`terraform/README.md`, "The third verdict").

## What the correction found

The corrected scope immediately caught a real defect in the **Phase I compliant
mock plan**, which is frozen and therefore stands as evidence: it tags its
CloudTrail log bucket but not the bucket policy attached to it, and that policy
carries no `aws:SecureTransport` deny. Scoped on the policy, 2.1-A16 never
looked; scoped on the bucket, it is a genuine 2.1 violation. The same omission
was present in the Terraform compliant fixture and is fixed there
(`terraform/compliant/main.tf`, `aws_s3_bucket_policy.trail`).

A regression test pins this: `test_rescope_finds_a_real_defect_in_the_phase1_compliant_mock`.

## Lesson for the framework

The Phase I framework validated a binding by checking that the rule fired on a
non-compliant fixture, a test the mock could satisfy for a rule that can never
fire on real input. LCT's Gate B (binding admissibility) should therefore
include an explicit check that **every attribute a rule reads, scope attributes
included, exists on that resource type in the Target Profile's schema**. That
check is mechanical (`terraform providers schema -json`) and would have caught
all three at authoring time.

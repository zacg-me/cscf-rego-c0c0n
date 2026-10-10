# Failure modes found while building the library

The first version of this library (1.0.0, five controls, 95 rules) was validated
on hand-written mock plans, and passed. Running it on plans Terraform actually
produced, and reviewing every rule against the provider schema, showed that
"passed" had hidden a set of defects. They are worth knowing because each one is
a way that *any* compliance-as-code library can be wrong while looking right.
The current library corrects all of them; `../policies/CHANGELOG.md` lists every
change by assertion id.

## 1. A rule that can never fire, and so always "passes"

Three assertions (1.1-A14, 2.1-A16, 5.1-A11) scoped themselves by a tag on
`aws_iam_role_policy` or `aws_s3_bucket_policy`. The AWS provider does not accept
tags on those types, so on any real plan the rules matched nothing and reported
no violation, forever.

**Correction:** a sub-resource takes the scope of the resource it belongs to
(`policies/swift_cscf/v2026/parent_scope.rego`). **Guard:** the Gate B check
(`pipeline/audit/gate_b_admissibility.py`) fails the build if any rule reads an
attribute the provider schema does not define, 384 reads, none allowlisted.

## 2. A scope declared but not applied, reporting things that are not Swift

39 rules said, in their `# Scope:` header, that they applied to Swift-zone
resources, and then evaluated the whole account. A bucket or security group
belonging to another system in the same account was reported as a CSCF
violation.

**Correction:** every declared scope is implemented (`zone_scope.rego`,
`parent_scope.rego`). **Guard:** `pipeline/audit/scope_audit.py` compares each
rule's declared scope with what it actually tests, and fails the build on any
mismatch; the record of the original 39 is kept as `PHASE1_MISMATCHES`.

## 3. Over-broad role assertions

1.1-A13 flagged any role that was not provably service-only, which also held
when the role's trust policy was simply unreadable at plan time. Service roles
were reported as human-assumable roles missing controls.

**Correction:** a `helpers.is_human_assumable` predicate that holds only for a
trust policy that parses *and* admits a non-service principal, used by 1.1-A12,
A13 and A14.

## 4. Missing relational data: the parent is not in the plan

Once a sub-resource is scoped through its parent, a new question appears: what
if the parent is not in the plan? A change plan routinely references a bucket
or route table created long ago. Treating it as out of scope would be a silent
pass; treating it as in scope would bring the over-reporting back.

**Correction:** a third verdict. The gate supplies the missing parent inside the
Swift zone in a witness plan, and any finding that appears only then is reported
**undetermined** (`unresolved-scope`), naming the parent.
Test: `test_missing_parent_is_undetermined_not_silent`.

## 5. Values Terraform only knows after apply

A policy document that interpolates a resource's ARN is unknown at plan time.
Read naively, it is absent, so a rule that parses it matches nothing and passes.
A real change request (CR-2041, `case_study/`) found a quieter version: EBS
encryption left to the account default passed silently, because the plan does
not say what the default is.

**Correction:** `pipeline/resolve_plan.py` classifies every unknown (resolvable
by reference, or unresolvable), the gate substitutes witness values and reports
any assertion whose verdict moves as **undetermined** (`unresolved-value`), and
values AWS decides at apply time are listed explicitly so none is read as a pass.

## 6. Values that look like strings but are not

`Bool = { "aws:SecureTransport" = false }` is a JSON boolean. 2.1-A12 compared it
with the string `"false"`, so a correct TLS-only policy was reported as
violating. 1.1-A12 had the mirror image: a condition that *disabled* MFA was
accepted as long as the key was present.

**Correction:** `helpers.is_false` accepts both spellings; 1.1-A12 checks the
value, not just the key. Tests: `test_boolean_conditions_are_accepted`,
`test_mfa_condition_set_to_false_is_a_violation`.

## 7. Resources the traversal never reached

The resource walker descended two module levels while its comment claimed
recursion. An SSH-open security group three modules deep
(`root -> zone -> network -> edge`) could violate anything and the plan still
passed. **Correction:** `helpers.all_resources` walks every depth.
Test: `test_library_traverses_every_module_depth`.

## 8. Matching everything by matching nothing

`contains(gateway_id, "")` is true for every string. An internet gateway with an
empty id matched every route in the plan (1.1-A6); the same pattern in 5.1-A16/A17
matched every role. **Correction:** both sides of every join must be non-empty.

## A note on `max_password_age = 0`

Not a defect of the library but a trap for every implementation: in the AWS
password policy, `0` means *passwords never expire*, not "compliant". A rule
that checks `max_password_age <= 90` passes it. 4.1-A7 treats 0 (and an unset
value) as a violation.

---

The pattern across all eight: **a rule that does not fire looks exactly like a
rule that checked and found nothing.** The library's answer is to make the
difference visible (fired, passed, or undetermined) and to check the rules
themselves (schema admissibility, scope conformance, coverage symmetry) as
strictly as the infrastructure.

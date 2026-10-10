# 1.1-A15: Bucket policy principal outside the Swift trust boundary

Added in library 2.1.0. Control 1.1, Swift Environment Protection; source
§ c) Boundary Protection.

## Normative plane
The secure zone is a boundary: what is inside may be reached only from inside
it, or through controlled, justified paths. Data held in the zone is inside the
boundary, so granting an account outside it direct access to that data is a
path across the boundary that no firewall rule describes.

## Binding plane
- **Target:** `aws_s3_bucket_policy`. It takes no tags, so its scope comes from
  the bucket it attaches to (`parent_scope.in_swift_zone_via_bucket`).
- **Boundary:** `input.swift_trust_boundary_accounts`, bound by
  `resolve_plan.py` from the `swift_trust_boundary_accounts` Terraform
  variable; the Swift account is always inside when it is stated explicitly
  (`--account-id` or the `account_id` variable). An account guessed from an
  ARN in the plan never joins the boundary, the first ARN may be the very
  partner the boundary excludes (2.1.1). The boundary is *declared*: the plan
  runs offline and cannot see AWS Organizations membership. The declaration is
  the institution's scoping decision and is itself reviewable evidence.
- **Principals:** `AWS` and `Federated` principals, IAM and STS ARNs and
  identity-provider ARNs in any partition, and bare account ids, string or
  number. `CanonicalUser` and `Allow` + `NotPrincipal` fire on their own
  (2.1.1). `*` is 5.1-A11's; service principals and web-identity services name
  no account.

## Realization plane
Relational (Variant E): the verdict needs the principal, the bucket's zone and
the boundary together. Each resource can pass every per-resource check while
the grant still crosses the boundary.

## Verdicts
- **Fires:** an `Allow` statement names an account outside the boundary; grants
  a canonical user (not provably inside, so treated as outside); or allows
  everyone except a `NotPrincipal` list. A condition (source VPC endpoint, IP
  range) narrows a grant but does not bring the account inside, so it still
  fires.
- **Undetermined:** the policy document is unknown at plan time (R3), the
  parent bucket is not in the plan, or no boundary is bound
  (`unbound-environment`), and any combination of these: a missing boundary
  is supplied to every other witness too, so two missing inputs never add up
  to a pass (2.1.1).

## Limits (stated, not silent)
- Wildcard principals restricted by `aws:PrincipalOrgID` or
  `aws:SourceAccount` conditions are not evaluated against the boundary.
- S3 access points and KMS key policies are not covered.
- A hand-written plan that states `swift_trust_boundary_accounts` directly is
  taken as the complete boundary; only `resolve_plan.py` adds the Swift
  account to it.
- Whether the declared boundary matches the real account estate is an
  assessor question (XREF to the institution's account inventory).

## Validation
- Unit: `tests/test_trust_boundary.py` (principal forms, partitions, single
  statement object, conditions, scope, unbound and unknown-document verdicts).
- Fixtures: `fixtures/ctrl_1_1_a15_compliant.json` / `_non_compliant.json`.
- Generated plans: `aws_s3_bucket_policy.partner_share` fires in the
  non-compliant environment; `aws_s3_bucket_policy.swift_dr_exchange` (DR
  account, inside the declared boundary) passes in the compliant one.

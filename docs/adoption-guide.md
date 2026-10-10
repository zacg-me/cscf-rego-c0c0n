# Adoption guide

## Run it on your estate

1. Plan and export the plan as JSON:
   `terraform plan -out tfplan.binary && terraform show -json tfplan.binary > plan.json`
2. Declare the bindings the library compares against:
   - tag Swift-zone resources `swift:zone = secure`;
   - set the `account_id` Terraform variable to the Swift account;
   - set `swift_trust_boundary_accounts` to the accounts inside the Swift trust
     boundary (the Swift account is always included).
3. Resolve plan-time unknowns and bindings:
   `python pipeline/resolve_plan.py --plan plan.json --out resolved.json --report resolvability.json`
4. Gate:
   `python pipeline/gate.py --plan resolved.json --resolvability resolvability.json --evidence evidence.json`
   Exit 0 = pass, 1 = violations. Add `--fail-on-undetermined` for a production
   Swift zone: what the gate could not evaluate must not ship silently. For a plan
   that changes only part of the estate, add `--plan-scope incremental`.
5. Render the attestation:
   `python evidence/report.py --evidence evidence.json --out attestation.html`
6. In CI, sign the evidence: set an Ed25519 private key in the
   `CSCF_EVIDENCE_SIGNING_KEY` secret (`pipeline/evidence_signing.py keygen`),
   commit the public key, and verify with
   `python pipeline/evidence_signing.py verify --require --evidence evidence.json`.

## Accept a risk (exceptions)

Sometimes a finding is understood and accepted for a while: a partner feed that
moves to the DR account next quarter, say. Record it as an exception instead of
weakening a rule.

1. Copy the record in `exceptions/exceptions.example.toml` into
   `exceptions/exceptions.toml` (or a file you pass with `--exceptions`) and
   fill it in:
   - `assertion` and `resource` - the assertion id and the **exact** Terraform
     address from the finding. No wildcards; one record per finding.
   - `reason`, `ticket` - why, and where the risk acceptance is recorded.
   - `risk_owner`, `approved_by` - **roles**, not names: the evidence is signed
     and kept.
   - `approved_on`, `expires_on` - TOML dates. `expires_on` is at most six
     calendar months after `approved_on`, and `approved_on` cannot be in the
     future.
2. Open a pull request. `.github/CODEOWNERS` names who must approve changes to
   `exceptions/`; in an institution that is the risk or compliance function,
   with branch protection requiring their review.
3. The gate then reports the finding as **EXCEPTED, accepted risk, not
   passed**:
   - the run passes if nothing else is wrong (exit 0);
   - the console, the attestation ("PASS WITH N ACCEPTED RISK(S)") and the
     step summary list the finding with its exception id, owner and expiry;
   - the evidence carries each excepted finding with its full record, and the
     exceptions file's SHA-256, inside the signature.
4. On the day after `expires_on` the exception stops applying and the finding
   fails the run again. Expired and unused exceptions are listed in every run.

**Scope.** A record matches by assertion and Terraform address only, so it
covers that address in every plan the gate evaluates with this file. If dev,
stage and production are built from the same configuration, keep one
exceptions file per environment (pass it with `--exceptions`), so a risk
accepted for one environment is not accepted for the others. Dates are UTC:
`approved_on` is checked against today's UTC date.

Anything wrong with the file (a missing or unknown field, a wildcard, a date
out of range, two records for the same finding) is a configuration error
(exit 2), reported before any rule is evaluated. Undetermined checks and
findings with no resource address (an absence, such as no CloudTrail) cannot
be excepted: dispositions for those belong in the exclusion register.

## Add an assertion to an existing control

1. Write the translation (`translations/`): the normative intent, the binding
   (resource types, scope), the realization (variant), the verdicts (fires and
   undetermined) and the stated limits.
2. Add a `deny` rule to `policies/swift_cscf/v2026/ctrl_<a>_<b>.rego` with the
   header lines `# <id>: <title>`, `# Source: ...` and
   `# Scope: <TAG|VPC|MODULE|ACCT> ...`. Read only attributes the provider schema
   defines; scope sub-resources that take no tags through `parent_scope`.
3. Add a compliant and a non-compliant fixture in `fixtures/` and tests that the
   non-compliant one fires exactly your assertion and the compliant one fires
   nothing. Include the inputs the rule cannot decide.
4. Seed the reference estates in `terraform/`, run `pipeline/plan_and_gate.sh`,
   and compare the evidence before and after: the new findings must be exactly
   the ones you intended.
5. Run the audits: `pipeline/audit/scope_audit.py` and
   `pipeline/audit/gate_b_admissibility.py` (against
   `terraform providers schema -json`), rebuild the matrix with
   `python traceability/build_matrix.py --xlsx`, bump
   `policies/swift_cscf/library.rego`, and write the `policies/CHANGELOG.md` entry.

## Adapt the method to another framework

The Rego packages are namespaced (`swift_cscf.v2026.*`). A new framework, PCI
DSS, RBI's Master Direction on IT governance, DORA, HIPAA, ISO 27001, an internal
standard, gets its own namespace and reuses `helpers`, `zone_scope`,
`parent_scope`, the gate, the resolver and the exclusion taxonomy unchanged.

Work clause by clause: decompose each requirement into testable assertions, or
disposition it in one of the seven exclusion categories with a reason. Keep the
matrix bidirectional (every rule traces to a clause, every clause to an
assertion or an exclusion) and report what the plan cannot decide as
undetermined. That last step is what makes the output defensible to an assessor.

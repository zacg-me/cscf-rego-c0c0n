# cscf-rego

Compliance-as-Code for SWIFT CSCF v2026: an OPA/Rego policy library and a CI
gate that evaluates a Terraform plan **before** deployment, blocks a change that
breaks a mandatory control, and emits signed evidence an assessor can verify.

Presented at c0c0n 2026, *Compliance-as-Code for SWIFT (and Beyond)*.

## Why

Institutions on the Swift network demonstrate CSCF compliance once a year, with
screenshots and hand-assembled evidence, while the infrastructure-as-code
pipeline keeps changing the environment underneath the evidence. This library
moves the check to where the change happens: every `terraform plan` is gated
against the framework, and every verdict is traceable to a clause.

Some of what the framework requires is relational. A bucket can be encrypted,
logged and free of wildcard principals, and still let an account outside the
Swift trust boundary read it. Neither the bucket nor its policy is wrong on its
own; the relationship is. Rego is built for exactly that shape of rule
(assertion 1.1-A15, `translations/1_1_a15_trust_boundary.md`).

## What is in it

*Phase I* and *Phase II*, in the changelog and the matrix, are the two phases of
the research that built the library: the first five controls, then the other ten
and the re-issue.


- `policies/` - policy library **2.1.2**: the 15 mandatory CSCF v2026 controls
  that infrastructure-as-code can evidence, enforced in Rego; the other 11
  mandatory controls are dispositioned in the exclusion register. All 26 are
  accounted for.
- `pipeline/gate.py` - the gate, with a three-valued verdict: **fired**,
  **passed**, **undetermined**. What a plan cannot decide is never reported as
  compliant.
- `exceptions/` - risk acceptances: one assertion on one exact resource, an
  owner, an approver, a ticket and an expiry of at most six months, approved
  through code review. A covered finding is reported as **excepted, not
  passed**, and signed into the evidence; an expired exception no longer
  applies. Only an example ships (`exceptions.example.toml`).
- `traceability/` - the matrix: every assertion to its rules, sub-requirements
  and live verdict; exclusions in seven categories (PROC, RUNTIME, PLATLIM,
  ONPREM, VENDOR, XREF, LEGAL).
- `terraform/` - a compliant and a non-compliant reference estate that plan
  **offline** (mock credentials; no AWS account needed).
- `translations/`, `framework/` - the translation method: how a sentence of
  regulation becomes testable assertions, and where that stops.
- `case_study/` - CR-2041, a realistic change blocked at the gate, then
  remediated.
- `docs/failure-modes.md` - what the first version of this library got wrong,
  and how each defect was found and fixed.
- `docs/adoption-guide.md` - running it on your estate, adding assertions,
  adapting the method to another framework.

## Quickstart

Needs OPA 1.17.0, Terraform 1.15.x, Python 3.12+ (`pip install pytest cryptography`).

```bash
bash pipeline/plan_and_gate.sh     # plan -> resolve -> gate, both reference estates
python -m pytest tests -q          # the conformance suite
```

## Results (re-run before quoting)

| | |
|---|---|
| Library | 147 rules, 130 assertions, 15 controls |
| Compliant estate | **PASS**, 0 findings (10 checks over 7 assertions undetermined) |
| Non-compliant estate | **FAIL**, 151 findings: 122 of 128 v2026 assertions fire, 4 undetermined, 2 mutually exclusive, **0 silent** |
| Traceability | 118 sub-requirements, 0 untraced |
| Schema admissibility | 384 attribute reads, 0 inadmissible, nothing allowlisted |
| Scope conformance | every resource-scoped rule applies the scope it declares |
| Conformance suite | 203 tests |

## Limits

Plan-time analysis sees declared configuration, not runtime behaviour.
Procedural, physical, vendor and runtime requirements are dispositioned, not
enforced; the exclusion register says why for each. The Swift trust boundary is
*declared* (`swift_trust_boundary_accounts`), not discovered; it is the
institution's scoping decision, and itself evidence an assessor can challenge.
A PASS here is evidence for an assessor, not an attestation.

## Licence

Apache-2.0. See NOTICE for the Swift trademark statement.

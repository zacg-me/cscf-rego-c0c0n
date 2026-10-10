# Case Study, CR-2041: Blocking a Risky SWIFT-Zone Change at the Gate

**Author:** Zachariah George
**Controls exercised:** 1.2, 1.3, 1.4, 2.3, 4.2, 5.4

This case study demonstrates the pre-deployment gate on a **single, realistic
change** to a SWIFT secure zone, end to end, from a blocked pull request to a
clean re-run after remediation. It shows the value proposition concretely: a
cross-cutting misconfiguration is caught **before** `terraform apply`, with
specific, actionable, control-referenced findings.

---

## The scenario

> **Change request CR-2041, "Add a reporting microservice to the SWIFT secure
> zone."** A developer must ship a reporting service (an EC2 host, an RDS database,
> an S3 export bucket, a Lambda exporter, and a secret) before a deadline. Under
> pressure they cut corners: reuse an SSH key for "quick debugging", skip disk
> encryption, add a NAT route so the host "can download packages", make the
> database publicly reachable "just for testing", and hardcode the DB password in
> the Lambda and Terraform.

The developer opens a pull request. The CI pipeline runs the CSCF gate on the
`terraform plan` **before** any apply.

Plans in this folder:
- `cr2041_change_plan.json` (the risky change as submitted.
- `cr2041_remediated_plan.json`) the same change, corrected.

**Run it on GitHub:** Actions -> **Case study CR-2041** -> **Run workflow** (choose
`both`, `change` or `remediated`). Each plan runs as its own job (the change
blocked in red, the remediation passing in green) with the verdict and findings
on the run page and the signed evidence and attestation attached
(`.github/workflows/case-study.yml`).

Gate command (both plans):
```
python pipeline/gate.py \
  --plan case_study/cr2041_change_plan.json \
  --policies policies \
  --controls ctrl_1_2,ctrl_1_3,ctrl_1_4,ctrl_2_3,ctrl_4_2,ctrl_5_4
```

---

## Result 1: the gate blocks the PR

**RESULT: FAIL, 14 violation instances across 6 controls. Pipeline exit code 1;
deployment blocked.** (Full evidence: `cr2041_change_evidence.json`; human-readable
attestation: `cr2041_change_report.html`.)

| Control | Findings | What the developer did |
|---------|:-------:|------------------------|
| **1.2** OS Privileged Account | A1, A2 | Reused an SSH key pair; no SSM-managed instance profile |
| **1.3** Virtualisation/Cloud | A1, A2, A3, A5 | IMDSv2 not enforced; IMDS hop limit 2; unencrypted root volume; shared (default) tenancy |
| **1.4** Restriction of Internet Access | A1, A4 | Added a `0.0.0.0/0` -> NAT route; no VPC endpoint for AWS-service access |
| **2.3** System Hardening | A1, A2 | RDS publicly accessible; S3 public-access block incomplete |
| **4.2** Multi-Factor Authentication | A3 | RDS IAM database authentication disabled |
| **5.4** Password Repository Protection | A1, A4, A5 | Secret without a customer-managed KMS key; hardcoded RDS master password; hardcoded password in a Lambda env var |

Every finding names the CSCF control, the assertion ID, the reason, and the exact
Terraform resource, so the developer knows precisely what to fix, with the
regulatory justification attached.

**Why this matters:** post-deployment tooling (e.g. AWS Config) would have flagged
these only *after* the publicly-accessible database and the plaintext credentials
were already live. The gate stops them at the pull request.

---

## Result 2: the developer remediates, and the gate passes

The developer corrects each finding:

| Fix | Control satisfied |
|-----|-------------------|
| Drop the SSH key; attach an SSM-managed instance profile | 1.2-A1, 1.2-A2 |
| Enforce IMDSv2, hop limit 1, encrypt the root volume, use dedicated tenancy | 1.3-A1/A2/A3/A5 |
| Remove the NAT internet route; add an S3 **VPC endpoint** | 1.4-A1, 1.4-A4 |
| Make RDS private; complete the S3 public-access block | 2.3-A1, 2.3-A2 |
| Enable RDS IAM database authentication | 4.2-A3 |
| Give the secret a customer-managed KMS key; use `manage_master_user_password`; reference the secret ARN from Lambda | 5.4-A1/A4/A5 |

Re-running the gate on `cr2041_remediated_plan.json`:

**RESULT: PASS, 0 violations across all 6 controls. Exit code 0; the change may
proceed.** (Evidence: `cr2041_remediated_evidence.json`; attestation:
`cr2041_remediated_report.html`.)

---

## What this case study demonstrates

1. **Cross-control coverage on one change.** A single realistic PR tripped **six**
   different CSCF controls spanning network egress, VM hardening, privileged
   access, data exposure, authentication, and secret handling, caught in one gate
   run.
2. **Shift-left value.** The misconfigurations never reached AWS; they were denied
   at plan time with actionable, regulator-traceable messages.
3. **The full pipeline in one story.** Terraform plan -> OPA/Rego gate -> machine
   evidence JSON -> human-readable attestation -> remediation -> clean re-run.
4. **Attestation for assessors.** The `*_report.html` files are the artefacts an
   independent SWIFT CSP assessor would review, tying the verdict to the plan's
   SHA-256 and the OPA version.

### Why six controls, and what happens with more

The change is evaluated against the six controls it touches. That is not
arbitrary trimming: a change plan is an **incremental** plan, and twelve
assertions across the library report the *absence* of account-level
infrastructure, no CloudTrail, no GuardDuty detector, no patch baseline. A plan
that adds a reporting service does not re-declare the account's logging estate,
so those assertions cannot be decided from it.

Adding controls 1.1 and 6.4 to the remediated (clean) plan makes this concrete:

```
--controls ctrl_6_4,ctrl_1_1                        -> 9 violations
--controls ctrl_6_4,ctrl_1_1 --plan-scope incremental -> 1 violation, 8 undetermined
```

Eight of the nine are absence findings that an incremental plan cannot support;
`--plan-scope incremental` reports them as **undetermined**, to be verified
against a full-environment plan. That flag is the right setting for a CI gate on
a pull request, and the account-level posture belongs in a scheduled
full-environment evaluation.

The ninth is real and survives the downgrade: **6.4-A6**, the remediated RDS
instance exports no logs to CloudWatch. It names the resource the change itself
creates, so it is decidable and is a genuine gap in the remediation, recorded
here rather than quietly excluded.

---

## CR-2041 as a real change

The plans above are hand-written. The same change was then made for real: the
reporting service written as Terraform (`cr2041_reporting.tf`), added to the
secure-zone environment in a pull request, and planned by `terraform plan` in
CI, where the gate is a required check on `main`.

| | Result |
|---|---|
| The change as submitted | **blocked**, `live-plan-gate` failed, and GitHub refused the merge. **16 findings across 9 controls** (1.1, 1.2, 1.3, 1.4, 2.3, 4.1, 4.2, 5.4, 6.4) |
| The remediation, pushed to the same pull request | **passed**, 0 findings, evidence signed and verified; the merge was allowed |

The pull request was made in the project's development repository, which is not
published. The plans it generated are committed here as
`cr2041_change_live_plan.json` and `cr2041_remediated_live_plan.json`, and the
suite gates both, so the result can be reproduced from this repository.

**What the real plan found that the hand-written one could not.**

- **More findings, 16 rather than 14.** In the full environment every control
  applies, so the change also trips 1.1-A4 (unrestricted egress), 4.1-A14 (the
  master password not managed by Secrets Manager), 6.4-A13 (the incomplete S3
  public-access block) and 6.4-A6 (no database logs), the gap recorded above.
- **A silent pass.** The hand-written plan said `encrypted = false` for the root
  volume. Real Terraform, where the author simply leaves it unset, says "known
  after apply": AWS applies the account's EBS encryption-by-default setting. The
  plan normaliser discarded values the author never assigned, so 1.3-A3 read
  nothing and passed. It is now **undetermined**, naming
  `root_block_device.0.encrypted` - see the framework, §4.5, for the Target
  Profile classification that fixed it and the test that keeps it fixed.

### Honesty note

The plans in the first half are **hand-written `terraform plan` JSON**; the
real-change plans are generated by Terraform, planning offline with no AWS
account, as everywhere in the project. Either way this is a demonstration of the
enforcement mechanism on a realistic change, not an independent audit of a live
AWS account.

# Applied Translation: CSCF v2026 Control 2.2 (Security Updates)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 2.2, pp. 48-49, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4, B (all)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 2 assertions fire (2 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** **Mechanism-presence**
>, **Assurance mix:** A3 Proxy ×2
>, **Delegations (owning control):**,
>, **Plan-time resolvability:** all R1
>, **Note:** Both assertions prove the patch mechanism exists, not that hosts are current

> **A mechanism-presence control.** Whether software is actually patched and within
> vendor support is an OS-host **runtime** fact, not visible in a Terraform plan.
> 2.2's only plan-evaluable sliver is that the **patch-automation mechanism** is
> configured, AWS SSM Patch Manager (a patch baseline plus a scheduled
> association). The assertions are therefore **presence checks with Partial
> coverage**: they prove the update process is set up, not that every host is
> current. Added for control-coverage completeness; the substantive requirement is
> documented as RUNTIME.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (close paraphrase) | CSCF § |
|----|---------------------------|--------|
| 2.2-S1 | All HW/SW inside the secure zone and on operator PCs are within vendor support, upgraded with mandatory updates, and have had security updates promptly applied. | Control Statement |
| 2.2-S2 | Vendor support: software/hardware within the vendor's supported life-cycle; maintenance/licensing contracts in place. | §guidelines |
| 2.2-S3 | Mandatory software updates are applied. | §guidelines |
| 2.2-S4 | Security updates are promptly applied, aligned to assessed risk. | §guidelines |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 2.2-S2 (vendor support / contracts) | PROC | Support-lifecycle and contractual status are not resource states. | - |
| 2.2-S3 (updates applied) | RUNTIME | Whether a host is patched is an OS-host runtime fact. | Patch-automation mechanism via A1/A2. |
| 2.2-S4 (security updates applied) | RUNTIME / DRIFT | Prompt application is runtime / post-deployment. | Patch-automation mechanism via A1/A2. |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource |
|----|------------------------------|-----|------------|-------------|--------------------|
| 2.2-A1 | An **SSM Patch Manager baseline** is configured (a patch policy exists). | S1 | PRESENCE | ACCT | `aws_ssm_patch_baseline` |
| 2.2-A2 | A **patch-automation association** is scheduled (the baseline is applied on a schedule). | S1 | PRESENCE | ACCT | `aws_ssm_association` |

ACCT-scoped: patch automation is an account-wide capability (mirrors the Phase I
PRESENCE checks for GuardDuty/Config in 6.4).

---

## Stage 4: Specify

**2.2-A1 (Variant B, presence)**, DENY if no `aws_ssm_patch_baseline` exists:
"CSCF 2.2 [2.2-A1]: no SSM Patch Manager baseline is configured; a security-update mechanism must be in place (§ mandatory software updates)."

**2.2-A2 (Variant B, presence)**, DENY if no `aws_ssm_association` exists:
"CSCF 2.2 [2.2-A2]: no SSM patch-automation association is scheduled; security updates must be applied on a defined schedule (§ security updates)."

---

## Stage 4.5: Trace

| Assertion | Src | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----|--------|--------------------|------------|-------------|---------|----------|
| 2.2-A1 | S1 | mandatory updates | `aws_ssm_patch_baseline` | PRESENCE | ACCT | B | Partial (mechanism) |
| 2.2-A2 | S1 | security updates | `aws_ssm_association` | PRESENCE | ACCT | B | Partial (mechanism) |

**Completeness check.** Verifiable items S1-S4 = **4**.
- Covered by ≥ 1 assertion (partial, mechanism): S1 -> **1**
- Excluded: S2 (PROC), S3 (RUNTIME), S4 (RUNTIME/DRIFT) -> **3**

```
covered (1) + excluded (3) == total (4)   ->   PASS
```

**Coverage summary.** 2.2 is a runtime patching control; its plan-evaluable footprint
is only the presence of the SSM Patch Manager mechanism (baseline + association).
Honest limit: these prove the *process is configured*, not that hosts are current,
the substantive requirement is RUNTIME/DRIFT (Phase II continuous-compliance
territory). Included for completeness of the mandatory-control coverage.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_2_2.rego` (package
`swift_cscf.v2026.ctrl_2_2`), importing the shared helpers. Two presence
`deny` rules. Passes `opa check` / `opa fmt`.

**Validation.** Fixtures `ctrl_2_2_{compliant,non_compliant}.json`. Compliant -> **0
violations**; non-compliant (omits both resources) -> **2 assertions fire**. Two CI
steps enforce this. Evidence + attestation samples at `evidence/samples/ctrl_2_2_*`.

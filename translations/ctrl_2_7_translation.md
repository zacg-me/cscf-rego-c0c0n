# Applied Translation: CSCF v2026 Control 2.7 (Vulnerability Scanning)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 2.7, pp. 58-59, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory (Advisory for architecture B), **Architecture:** A1, A2, A3, A4, B
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 1 assertion fires (1 instance).

> **Framework v2.0 classification.**
>, **Control archetype:** **Mechanism-presence**
>, **Assurance mix:** A3 Proxy ×1
>, **Delegations (owning control):** 2.2 (remediation)
>, **Plan-time resolvability:** all R1
>, **Note:** Proves the scanner is enabled, not that scans run on cadence

> **A mechanism-presence control.** Vulnerability *scanning* is a periodic process
> (scan cadence, tool reputability, credentialed scans, remediation), all
> procedural/runtime and invisible to a Terraform plan. 2.7's only plan-evaluable
> sliver is that the **continuous-scanning mechanism** is enabled: AWS Amazon
> Inspector, covering compute (EC2). The single assertion is a **presence check
> with Partial coverage**; it proves scanning is configured, not that scans are
> performed and acted upon. Added for control-coverage completeness.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (close paraphrase) | CSCF § |
|----|---------------------------|--------|
| 2.7-S1 | Secure-zone systems are scanned for vulnerabilities at OS and application level using an up-to-date reputable tool; results are acted upon. | Control Statement |
| 2.7-S2 | Scanning is performed at least annually or after any significant change (quarterly/monthly/real-time recommended). | §guidelines |
| 2.7-S3 | Reputable, updated tools; appropriate scan type (e.g. credentialed); scan credentials protected; safeguards to limit operational impact. | §guidelines |
| 2.7-S4 | Scanning outcomes are documented (restricted access) and analysed for remediation (e.g. applying updates per 2.2). | §guidelines |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 2.7-S2 (cadence) | PROC | Scan frequency is an operational schedule. | Continuous scanning via A1 (Inspector). |
| 2.7-S3 (tool/creds/safeguards) | PROC / RUNTIME | Tool selection and credential handling are operational. | - |
| 2.7-S4 (remediation) | XREF -> 2.2 / PROC | Remediation via updates is Control 2.2; documentation is procedural. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource |
|----|------------------------------|-----|------------|-------------|--------------------|
| 2.7-A1 | **Amazon Inspector** continuous vulnerability scanning is **enabled for EC2** (compute). | S1 | PRESENCE + SINGLE | ACCT | `aws_inspector2_enabler.values.resource_types` (must include `EC2`) |

ACCT-scoped: Inspector is enabled at the account level (mirrors Phase I
GuardDuty/Config PRESENCE checks).

---

## Stage 4: Specify

**2.7-A1 (Variant B, presence + coverage)**, DENY if no `aws_inspector2_enabler`
enables EC2 scanning:
"CSCF 2.7 [2.7-A1]: Amazon Inspector is not enabled for EC2 vulnerability scanning; a continuous scanning mechanism must be in place (§ Control Statement)."

---

## Stage 4.5: Trace

| Assertion | Src | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----|--------|--------------------|------------|-------------|---------|----------|
| 2.7-A1 | S1 | Control Statement | `aws_inspector2_enabler` | PRESENCE+SINGLE | ACCT | B | Partial (mechanism) |

**Completeness check.** Verifiable items S1-S4 = **4**.
- Covered by ≥ 1 assertion (partial, mechanism): S1 -> **1**
- Excluded: S2 (PROC), S3 (PROC/RUNTIME), S4 (XREF 2.2 / PROC) -> **3**

```
covered (1) + excluded (3) == total (4)   ->   PASS
```

**Coverage summary.** 2.7 is a scanning *process* control; its plan-evaluable
footprint is only that Amazon Inspector (continuous scanning) is enabled for
compute. Honest limit: this proves the scanner is on, not that scans run on cadence
and results are remediated, those are PROC/RUNTIME. Included for completeness.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_2_7.rego` (package
`swift_cscf.v2026.ctrl_2_7`), importing the shared helpers. One presence
`deny` rule. Passes `opa check` / `opa fmt`.

**Validation.** Fixtures `ctrl_2_7_{compliant,non_compliant}.json`. Compliant -> **0
violations**; non-compliant (no Inspector EC2 enabler) -> **1 assertion fires**. Two
CI steps enforce this. Evidence + attestation samples at `evidence/samples/ctrl_2_7_*`.

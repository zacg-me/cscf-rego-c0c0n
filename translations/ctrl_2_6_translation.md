# Applied Translation: CSCF v2026 Control 2.6 (Operator Session Confidentiality and Integrity)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 2.6, pp. 56-57, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4, B (all)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 3 assertions fire (3 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** Configuration
>, **Assurance mix:** A1 Direct ×2, A2 Partial ×1
>, **Delegations (owning control):** 2.1 (transport TLS/crypto)
>, **Plan-time resolvability:** all R1
>, **Note:** App-level idle lock-out remains RUNTIME

> **Focus.** 2.6 protects interactive operator sessions into the secure zone; they
> must be **encrypted** and **time-limited**. The transport-crypto half (ssh /
> https / one-way TLS with strong algorithms) is already Control 2.1's job (ALB/GUI
> TLS listeners) and is XREF-excluded; SSH is removed altogether by 1.2's
> SSM-managed-access model. 2.6's net-new plan-evaluable surface is the **session
> lifetime and session-data protection** on the AWS remote-access paths: Client VPN
> session timeout, and SSM Session Manager idle-timeout and KMS encryption.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 2.6-S1 | The confidentiality and integrity of interactive operator sessions into the secure zone / to service-provider Swift applications are safeguarded. | Control Statement |
| 2.6-S2 | All interactive sessions are protected by a cryptographic protocol (e.g. ssh, https with one-way TLS). | §guidelines |
| 2.6-S3 | Protocols use current cryptographic algorithms (AES, ECDHE) with adequate key lengths. | §guidelines |
| 2.6-S4 | Operator/admin/maintenance sessions have an **inactivity lock-out** limiting the session to the minimal necessary time frame. | §guidelines |
| 2.6-S5 | If not implemented at the application level, the inactivity lock-out is implemented at the OS level or on the jump server. | §guidelines |
| 2.6-S6 | Communication between the jump server and Swift components/underlying systems is protected by a secure mechanism (one-way or two-way TLS). | §guidelines |
| 2.6-OE | Apply to all bridging servers. *(Optional Enhancement)* | Optional Enhancement |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 2.6-S2 (transport TLS on ALB/GUI) | XREF -> 2.1 | Interactive-session transport TLS is Control 2.1 (A1/A2/A13). | SSM session encryption via A3. |
| 2.6-S2 (SSH to instances) | RUNTIME | SSH is removed by 1.2's SSM-managed model; any residual SSH is OS runtime. | - |
| 2.6-S3 | XREF -> 2.1 | Cryptographic-algorithm/TLS-policy allowlists are Control 2.1. | - |
| 2.6-S4 (application-level lock-out) | RUNTIME / VENDOR | App-level idle lock-out is a Swift-application setting. | Infra-level via A1 (VPN) / A2 (SSM). |
| 2.6-S6 (jump server <-> component TLS) | XREF -> 2.1 | Transport TLS is Control 2.1. | SSM session encryption via A3. |
| 2.6-OE | ADV | Optional Enhancement. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Net-new surface: session lifetime + session-data protection.** Assertion Register:

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 2.6-A1 | Swift **Client VPN** endpoints enforce a **bounded session timeout** (`session_timeout_hours` ≤ 8, the minimum AWS permits). | S4 | SINGLE | TAG | `aws_ec2_client_vpn_endpoint.values.session_timeout_hours` |
| 2.6-A2 | **SSM Session Manager** enforces an **idle-session timeout** (≤ 20 minutes). | S4, S5 | JSON | ACCT | `aws_ssm_document` (type `Session`) `.content` [JSON] -> `inputs.idleSessionTimeout` |
| 2.6-A3 | **SSM Session Manager** encrypts session data with a **KMS key** (`inputs.kmsKeyId` set). | S1, S6 | JSON | ACCT | `aws_ssm_document` (type `Session`) `.content` [JSON] -> `inputs.kmsKeyId` |

**Scope conventions (Stage 2.5).** A1 TAG-scoped to `swift:zone = "secure"`; A2/A3
ACCT-scoped (the Session-type SSM document governs sessions account-wide). A2/A3
inspect the same SSM document 1.2-A3 uses, but for *different* properties (idle
timeout / encryption vs. logging), distinct CSCF requirements, no rule overlap.

---

## Stage 4: Specify

**2.6-A1: Client VPN session timeout (Variant A)**
```
GIVEN   an aws_ec2_client_vpn_endpoint where tags["swift:zone"]=="secure"
WHEN    session_timeout_hours is unset OR > 8
THEN    DENY "CSCF 2.6 [2.6-A1]: Client VPN session timeout exceeds the minimum (8h);
        operator sessions must be limited to the minimal necessary time frame
        (§ inactivity lock-out). (resource: %s)"
```

**2.6-A2: SSM idle-session timeout (Variant C, JSON)**
```
GIVEN   an aws_ssm_document whose document_type == "Session"
WHEN    content.inputs.idleSessionTimeout is unset OR its numeric value > 20 (minutes)
THEN    DENY "CSCF 2.6 [2.6-A2]: SSM Session Manager does not enforce an idle-session
        timeout ≤ 20 minutes (§ inactivity lock-out). (resource: %s)"
```

**2.6-A3: SSM session KMS encryption (Variant C, JSON)**
```
GIVEN   an aws_ssm_document whose document_type == "Session"
WHEN    content.inputs.kmsKeyId is empty/absent
THEN    DENY "CSCF 2.6 [2.6-A3]: SSM Session Manager does not encrypt session data with a
        KMS key; operator-session confidentiality is not protected (§ Control Statement).
        (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 2.6-A1 | S4 | inactivity lock-out | `aws_ec2_client_vpn_endpoint` | SINGLE | TAG | A | Full (VPN session limit) |
| 2.6-A2 | S4, S5 | inactivity lock-out | `aws_ssm_document` | JSON | ACCT | C | Full (SSM idle timeout) |
| 2.6-A3 | S1, S6 | confidentiality | `aws_ssm_document` | JSON | ACCT | C | Partial (SSM session data) |

### Completeness check

Verifiable/obligation items in § 2.6: S1-S6 = **6** (OE is Advisory).

- **Covered by ≥ 1 assertion**: S1, S4, S5 -> **3**
- **Documented exclusions**: S2 (XREF 2.1 / RUNTIME), S3 (XREF 2.1), S6 (XREF 2.1) -> **3**

```
covered (3) + excluded (3) == total (6)   ->   PASS
```

### Coverage summary

2.6's automatable contribution is **session lifetime and session-data protection**
on the AWS remote-access paths: Client VPN session timeout (A1) and SSM Session
Manager idle-timeout (A2) and KMS encryption (A3). The transport-TLS/crypto half is
Control 2.1's (XREF), and SSH is eliminated by 1.2. Stated limitation: 2.6 is a
Tier-2 control that leans on 2.1 for transport crypto; its own value is the
time-limit / session-encryption checks that 2.1 does not make.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_2_6.rego`
(package `swift_cscf.v2026.ctrl_2_6`), importing the shared helpers. Three
assertions -> three `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **A1** requires `session_timeout_hours == 8` (AWS's minimum; valid values are
  8/10/12/24). An unset value defaults to 24 (violation).
- **A2** parses the SSM document JSON and reads `inputs.idleSessionTimeout` as a
  string of minutes; unset or > 20 is a violation.
- **A2/A3** share the SSM Session document with 1.2-A3 but test different fields.
  Application-level inactivity lock-out (S4) remains RUNTIME/VENDOR, infra-level
  is the plan-evaluable proxy.

**Validation.** Paired fixtures in `fixtures/`
(`ctrl_2_6_compliant.json`, `ctrl_2_6_non_compliant.json`). Compliant -> **0
violations (PASS)**; non-compliant -> **3 instances / 3 assertions (FAIL)**. Two CI
steps in `.github/workflows/cscf-gate.yml` enforce this. Evidence + attestation
samples: `evidence/samples/ctrl_2_6_*`.

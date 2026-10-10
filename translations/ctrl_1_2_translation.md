# Applied Translation: CSCF v2026 Control 1.2 (Operating System Privileged Account Control)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 1.2, pp. 35-37, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory (Advisory for architecture B), **Architecture:** A1, A2, A3, A4, B
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 3 assertions fire (3 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** Configuration (heavy delegation)
>, **Assurance mix:** A1 Direct ×2, A3 Proxy ×1
>, **Delegations (owning control):** 5.1 (IAM admin), 1.1 (admin ports), 4.2 (MFA), 6.4 (log capture)
>, **Plan-time resolvability:** all R1
>, **Note:** 1.2-A2 is a prerequisite signal, not proof of SSM enrolment

> **A largely OS-level control.** 1.2 restricts and controls *operating-system*
> administrator accounts (Windows Administrator, Linux root, network-device admin,
> HSM admin). Most of that lives at the OS/appliance runtime layer, not in a
> Terraform plan, and its logging/IAM aspects belong to controls already
> implemented (admin access logging -> 6.4; broad IAM admin -> 5.1; admin network
> ports -> 1.1; MFA for admin -> 4.2/1.1), all XREF-excluded. 1.2's genuinely
> plan-evaluable, net-new surface is the **controlled and monitored admin-access
> path on the cloud platform**: use of AWS SSM Session Manager (managed,
> auditable) instead of persistent shared SSH key pairs, and session-activity
> logging.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 1.2-S1 | Access to administrator-level OS accounts is restricted to the maximum extent possible; usage is controlled, monitored, and only permitted for relevant activities; least-privilege used otherwise. | Control Statement |
| 1.2-S2 | Logins with built-in administrator accounts are not permitted except when specifically needed; individual accounts / escalation (sudo) are used instead. | §guidelines |
| 1.2-S3 | Break-glass account usage is strictly controlled (safe-stored password, authorisation before retrieval) and monitored; password changed after use. | §guidelines |
| 1.2-S4 | Individual administrator-level account access and usage are logged (in line with / as part of Control 6.4). | §guidelines |
| 1.2-S5 | Administrator-level passwords are tightly controlled with physical access controls when physically recorded. | §guidelines |
| 1.2-OE | Systems disallow built-in admin logins except maintenance mode; apply to bridging servers. *(Optional Enhancements)* | Optional Enhancements |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 1.2-S1 (OS accounts on network devices / HSM) | ONPREM / VENDOR | Network-device and HSM admin accounts are not AWS Terraform resources. | Cloud VM path via A1-A3. |
| 1.2-S2 (built-in OS admin logins) | RUNTIME | Whether a login uses the built-in account is an OS-runtime fact. | SSM-managed path (A1, A2) removes the need for shared SSH login. |
| 1.2-S3 (break-glass) | PROC / RUNTIME | Safe storage, authorisation-before-retrieval, post-use password change are operational. | Repository storage -> 5.4. |
| 1.2-S4 (admin access logging) | XREF -> 6.4 | Log capture/retention is Control 6.4. | Session logging enforced by A3. |
| 1.2-S5 (physical password control) | PROC / ONPREM | Physical media controls. | Logical repository -> 5.4. |
| Broad IAM admin (AdministratorAccess to humans) | XREF -> 5.1 | Wildcard / admin IAM is Control 5.1. | - |
| Admin network ports (22/3389) | XREF -> 1.1 | Admin-port exposure is 1.1-A3. | - |
| MFA for admin access | XREF -> 4.2 / 1.1 | MFA is 4.2 / 1.1-A12/A14. | - |
| AWS root account controls | ROOT | The AWS account root user is not a Terraform-manageable resource. | - |
| 1.2-OE | ADV | Optional Enhancement. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Net-new surface: controlled/monitored admin-access path.** Assertion Register:

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 1.2-A1 | Swift VMs use **no static SSH key pair** (`key_name` empty), admin access via SSM Session Manager, not a persistent shared credential. | S1, S2 | SINGLE | TAG | `aws_instance.values.key_name` |
| 1.2-A2 | Swift VMs have an **IAM instance profile** (prerequisite for SSM-managed, auditable admin access). | S1 | SINGLE | TAG | `aws_instance.values.iam_instance_profile` |
| 1.2-A3 | **SSM Session Manager logging** is configured (session activity to CloudWatch/S3), so admin sessions are monitored. | S1, S4 | JSON | ACCT | `aws_ssm_document` (type `Session`) `.values.content` [JSON] -> `inputs.cloudWatchLogGroupName` / `inputs.s3BucketName` |

**Scope conventions (Stage 2.5).** A1/A2 TAG-scoped to `swift:zone = "secure"`.
A3 is ACCT-scoped: a Session-type SSM document governs session logging account-wide.

---

## Stage 4: Specify

**1.2-A1: No static SSH key (Variant A)**
```
GIVEN   an aws_instance where tags["swift:zone"]=="secure"
WHEN    key_name is set (non-empty)
THEN    DENY "CSCF 1.2 [1.2-A1]: VM uses a static SSH key pair; privileged access should
        go through SSM Session Manager, not a persistent shared credential
        (§ Control Statement). (resource: %s)"
```

**1.2-A2: SSM-capable instance profile (Variant A)**
```
GIVEN   an aws_instance where tags["swift:zone"]=="secure"
WHEN    iam_instance_profile is empty/absent
THEN    DENY "CSCF 1.2 [1.2-A2]: VM has no IAM instance profile; SSM-managed, auditable
        admin access is not available (§ Control Statement). (resource: %s)"
```

**1.2-A3: SSM session logging (Variant C, JSON)**
```
GIVEN   an aws_ssm_document whose document_type == "Session"
WHEN    the content (JSON) sets neither inputs.cloudWatchLogGroupName nor inputs.s3BucketName
THEN    DENY "CSCF 1.2 [1.2-A3]: SSM Session Manager preferences do not enable session
        logging; privileged sessions are not monitored (§ guidelines, cross-ref 6.4).
        (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 1.2-A1 | S1, S2 | Control Statement | `aws_instance` | SINGLE | TAG | A | Full (SSH-key-less) |
| 1.2-A2 | S1 | Control Statement | `aws_instance` | SINGLE | TAG | A | Partial (SSM prerequisite) |
| 1.2-A3 | S1, S4 | guidelines | `aws_ssm_document` | JSON | ACCT | C | Full (session logging) |

### Completeness check

Verifiable/obligation items in § 1.2: S1, S2, S3, S4, S5 = **5** (OE is Advisory).

- **Covered by ≥ 1 assertion**: S1, S2 (partial), S4 (partial) -> **3**
- **Documented exclusions**: S3 (PROC/RUNTIME), S5 (PROC/ONPREM), and S4's log-capture half (XREF 6.4) -> the remaining verifiable items -> **2** (S3, S5)

```
covered (3) + excluded (2) == total (5)   ->   PASS
```

### Coverage summary

1.2 is mostly an OS-runtime control; its plan-evaluable, net-new surface is the
**cloud admin-access path**: SSM Session Manager instead of static SSH keys (A1),
the instance profile that enables it (A2), and session logging (A3). Broad IAM
admin, admin ports, MFA and log capture are owned by 5.1 / 1.1 / 4.2 / 6.4 and are
XREF'd. Stated limitation: 1.2 is a Tier-2 control with a deliberately small
footprint, the framework records full coverage via XREF while encoding only the
genuinely new checks.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_1_2.rego`
(package `swift_cscf.v2026.ctrl_1_2`), importing the shared helpers. Three
assertions -> three `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **A2** is a *prerequisite* signal (an instance profile is necessary but not
  sufficient for SSM Session Manager); marked Partial. A full check would join
  instance -> profile -> role -> `AmazonSSMManagedInstanceCore` (multi-hop), deferred.
- **A3** checks Session-type SSM documents; if none exists, sessions fall back to
  unlogged defaults, a gap noted for a future presence-form assertion.

**Validation.** Paired fixtures in `fixtures/`
(`ctrl_1_2_compliant.json`, `ctrl_1_2_non_compliant.json`). Compliant -> **0
violations (PASS)**; non-compliant -> **3 instances / 3 assertions (FAIL)**. Two CI
steps in `.github/workflows/cscf-gate.yml` enforce this. Evidence + attestation
samples: `evidence/samples/ctrl_1_2_*`.

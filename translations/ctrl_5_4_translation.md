# Applied Translation: CSCF v2026 Control 5.4 (Password Repository Protection)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 5.4, pp. 80-81, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4, B (all)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 5 assertions fire (5 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** Configuration
>, **Assurance mix:** A1 Direct ×2, A2 Partial ×3
>, **Delegations (owning control):** 6.4 (access logging), 5.1 (need-to-have IAM), 4.1 (rotation)
>, **Plan-time resolvability:** all R1
>, **Note:** A2/A5 rely on a credential-name heuristic, Partial by construction

> **Mapping.** 5.4 protects the *repository of recorded passwords*. In AWS the
> logical password repository is **Secrets Manager** and **SSM Parameter Store**
> (encrypted by **KMS**); the "no plaintext / no hardcoded" clauses also reach
> **RDS master passwords** and **Lambda environment variables**. The physical-media
> half of the control (safes, sealed envelopes) is not plan-evaluable and is
> excluded. Access logging on the repository is Control 6.4 (XREF); general
> need-to-know IAM is Control 5.1 (XREF), 5.4's own assertions target the
> repository's *encryption* and *repository-scoped access* plus the *no-hardcoded*
> anti-patterns.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 5.4-S1 | Recorded passwords are stored in a protected physical or logical location, with access restricted on a need-to-know basis. | Control Statement |
| 5.4-S2 | Passwords on physical media are protected (sealed tamper-evident envelope, safe, logging access to the storage location). | §guidelines (physical) |
| 5.4-S3 | Passwords stored logically are protected by **encryption-at-rest or obfuscation (no plaintext storage)**. | §guidelines (logical) |
| 5.4-S4 | Logical storage has **authenticated access with access logging** (in line with / as part of Control 6.4). | §guidelines (logical) |
| 5.4-S5 | Passwords are not recorded in user manuals or other operational means unless stored per the guidance. | §guidelines |
| 5.4-S6 | If emergency access is granted, the password is changed immediately thereafter. | §guidelines |
| 5.4-S7 | **Passwords are not hardcoded in scripts or other software code.** | §guidelines |
| 5.4-OE | Safe certification (UL/EN); apply to bridging servers. *(Optional Enhancement)* | Optional Enhancement |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 5.4-S2 (physical media) | PROC / ONPREM | Safes, sealed envelopes and physical access logging are not plan-evaluable. | - |
| 5.4-S4 (access logging) | XREF -> 6.4 | Access logging on the repository is Control 6.4. | Repository access restriction partly via 5.4-A3. |
| 5.4-S4 (authenticated access) | XREF -> 5.1 | General need-to-know IAM is Control 5.1. | Repository-scoped wildcard denial via 5.4-A3. |
| 5.4-S5 (user manuals) | PROC | Documentation practice, not a resource state. | - |
| 5.4-S6 (emergency change) | RUNTIME / PROC | A runtime operational action after emergency access. | - |
| Secret rotation | XREF -> 4.1 | Rotation is Control 4.1 (assertion 4.1-A16). | - |
| 5.4-OE | ADV | Optional Enhancement. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Assertion Register:**

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 5.4-A1 | Swift **Secrets Manager** secrets are encrypted with a **customer-managed KMS key**. | S1, S3 | SINGLE | TAG | `aws_secretsmanager_secret.values.kms_key_id` |
| 5.4-A2 | Swift **SSM parameters** that hold credentials are **`SecureString`** (no plaintext). | S3 | SINGLE (+ name heuristic) | TAG | `aws_ssm_parameter.values.type`, `.name` |
| 5.4-A3 | A Secrets Manager **resource policy grants no wildcard principal** (need-to-know). | S1, S4 | JSON | ACCT | `aws_secretsmanager_secret_policy.values.policy` [JSON] |
| 5.4-A4 | **RDS** instances do not set an inline master **password** (use Secrets-Manager-managed credentials). | S7 | SINGLE (conditional) | TAG | `aws_db_instance.values.password`, `.manage_master_user_password` |
| 5.4-A5 | **Lambda** environment variables contain **no hardcoded password-like values** (reference a secret ARN instead). | S7 | SINGLE (+ name heuristic) | TAG | `aws_lambda_function.values.environment[*].variables` |

**Scope conventions (Stage 2.5).** A1/A2/A4/A5 TAG-scoped to `swift:zone = "secure"`.
A3 is ACCT-scoped: a wildcard-principal secret policy is a defect regardless of tag.
A2/A5 add a **name heuristic** (`password`, `passwd`, `secret`, `credential`,
`token`, `apikey`) to identify credential-bearing parameters/variables.

---

## Stage 4: Specify

**5.4-A1: Secrets Manager CMK (Variant A; absence = violation)**
```
GIVEN   an aws_secretsmanager_secret where tags["swift:zone"]=="secure"
WHEN    kms_key_id is empty/absent (uses the default aws/secretsmanager key)
THEN    DENY "CSCF 5.4 [5.4-A1]: Secret is not encrypted with a customer-managed KMS
        key; the password repository must use a controlled key (§ logical). (resource: %s)"
```

**5.4-A2: SSM SecureString (Variant A + heuristic)**
```
GIVEN   an aws_ssm_parameter where tags["swift:zone"]=="secure" AND name looks like a credential
WHEN    type != "SecureString"
THEN    DENY "CSCF 5.4 [5.4-A2]: SSM parameter storing a credential is not SecureString
        (plaintext storage) (§ logical). (resource: %s)"
```

**5.4-A3: Secret policy need-to-know (Variant C, JSON)**
```
GIVEN   an aws_secretsmanager_secret_policy
WHEN    the policy (JSON) has an Allow statement whose Principal allows any identity ("*")
THEN    DENY "CSCF 5.4 [5.4-A3]: Secret resource policy grants access to any principal;
        repository access must be need-to-know (§ Statement). (resource: %s)"
```

**5.4-A4: RDS no inline password (Variant F, conditional)**
```
GIVEN   an aws_db_instance where tags["swift:zone"]=="secure"
WHEN    password is set (non-empty) AND manage_master_user_password != true
THEN    DENY "CSCF 5.4 [5.4-A4]: RDS master password is hardcoded inline; use
        Secrets-Manager-managed credentials (§ no hardcoded passwords). (resource: %s)"
```

**5.4-A5: Lambda no hardcoded secrets (Variant A + heuristic)**
```
GIVEN   an aws_lambda_function where tags["swift:zone"]=="secure"
WHEN    an environment variable whose key looks like a credential has a non-empty
        value that is not a Secrets Manager ARN reference
THEN    DENY "CSCF 5.4 [5.4-A5]: Lambda environment variable hardcodes a password-like
        value; reference a secret ARN instead (§ no hardcoded passwords). (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 5.4-A1 | S1, S3 | logical | `aws_secretsmanager_secret` | SINGLE | TAG | A | Full (CMK encryption) |
| 5.4-A2 | S3 | logical | `aws_ssm_parameter` | SINGLE | TAG | A | Partial (heuristic-scoped) |
| 5.4-A3 | S1, S4 | Statement | `aws_secretsmanager_secret_policy` | JSON | ACCT | C | Partial (wildcard case) |
| 5.4-A4 | S7 | no-hardcoded | `aws_db_instance` | SINGLE | TAG | F | Full (RDS inline password) |
| 5.4-A5 | S7 | no-hardcoded | `aws_lambda_function` | SINGLE | TAG | A | Partial (heuristic; env only) |

### Completeness check

Verifiable/obligation items in § 5.4: S1, S2, S3, S4, S5, S6, S7, OE = **8**.

- **Covered by ≥ 1 assertion**: S1, S3, S4 (partial), S7 -> **4**
- **Documented exclusions**: S2 (PROC/ONPREM), S5 (PROC), S6 (RUNTIME/PROC), OE (ADV) -> **4**

```
covered (4) + excluded (4) == total (8)   ->   PASS
```

### Coverage summary

5.4's automatable core is the **logical password repository**: Secrets Manager
CMK encryption (A1), SSM SecureString (A2), need-to-know repository policy (A3),
and the two most common **hardcoded-secret anti-patterns** in IaC, RDS inline
master passwords (A4) and Lambda plaintext env vars (A5). The physical-media half
is honestly excluded (PROC/ONPREM). A2/A5 rely on a **name heuristic**, so they
are Partial by construction, the honest limitation to state for this control.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_5_4.rego`
(package `swift_cscf.v2026.ctrl_5_4`), importing the shared helpers
(`helpers.is_swift_tagged`, `helpers.principal_allows_any`). Five assertions ->
five `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **Heuristic scoping (A2, A5).** Credential detection uses substring matching on
  names/keys; it can miss oddly-named secrets and is deliberately conservative.
- **Sensitive-value redaction (A4).** In a real `terraform plan -json`, the RDS
  `password` is a sensitive value and may be redacted; the fixture uses a literal
  the way the Phase I mock plans do. A documented caveat for real plans.
- **A1** treats a missing/empty `kms_key_id` (default AWS-managed key) as a
  violation, the control wants a controlled key for the repository.

**Validation.** Paired fixtures in `fixtures/`
(`ctrl_5_4_compliant.json`, `ctrl_5_4_non_compliant.json`). Run:

```
python pipeline/gate.py \
  --plan fixtures/ctrl_5_4_non_compliant.json \
  --policies policies \
  --controls ctrl_5_4
```

Compliant -> **0 violations (PASS)**; non-compliant -> **5 instances / 5 assertions
(FAIL)**. Two CI steps in `.github/workflows/cscf-gate.yml` enforce this. Evidence
+ attestation samples: `evidence/samples/ctrl_5_4_*`.

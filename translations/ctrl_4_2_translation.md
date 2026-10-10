# Applied Translation: CSCF v2026 Control 4.2 (Multi-Factor Authentication)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 4.2, pp. 71-73, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4, B (all)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 4 assertions fire (4 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** **Meta**
>, **Assurance mix:** A1 Direct ×1, A2 Partial ×3
>, **Delegations (owning control):** 1.1 (assume-role MFA 1.1-A12, MFA-deny 1.1-A14, MFA-capable VPN 1.1-A10)
>, **Plan-time resolvability:** all R1
>, **Note:** A3/A4 are plan-evaluable proxies for MFA-backed database/dashboard login

> **Overlap with Control 1.1.** MFA is a cross-cutting requirement. The
> *infrastructure-layer* MFA that a Terraform plan can express is already enforced
> by Control 1.1: assume-role-policy MFA conditions (1.1-A12), MFA-deny inline
> policies for secure-zone admin access (1.1-A14), and MFA-capable VPN auth
> (1.1-A10). To avoid duplication, those are recorded here as **XREF exclusions to
> 1.1**. 4.2's own assertions target the MFA surface 1.1 does *not* cover: the
> **end-user / application authentication layer**, Cognito user-pool MFA, RDS
> IAM database authentication, and OpenSearch federated (MFA-backed) auth. The
> operating-system / vendor-interface MFA that 4.2 also requires is not
> plan-evaluable (VENDOR / RUNTIME exclusions).

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 4.2-S1 | MFA is used for interactive user access to Swift-related components/applications and operating-system accounts. | Control Statement |
| 4.2-S2 | MFA principles: two distinct factors, second-factor device distinct from first, AAL2 guidance. | §guidelines |
| 4.2-S3 | MFA on ≥ 1 authentication stage for admins/end users accessing Swift apps, the HSM, the hosting system, or externally exposed firewalls (jump server, operator PC login). | §guidelines |
| 4.2-S4 | MFA for remote user administrative access (generally VPN authentication). | §guidelines |
| 4.2-S5 | The MFA authentication system is preferably located within the secure zone. | §guidelines |
| 4.2-S6 | Authentication factors are individually assigned (individual accountability). | §guidelines |
| 4.2-S7 | If SSO (e.g. SAML) is implemented, a second factor is still required. | §guidelines |
| 4.2-S8 | MFA must be used when accessing service-provider-operated Swift components. | §guidelines |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 4.2-S1 (OS accounts) | RUNTIME / ONPREM | OS-login MFA is enforced at the operating-system/IdP layer, not in a Terraform plan. | App-layer via A1/A3/A4. |
| 4.2-S2 | PROC / RUNTIME | Factor mechanics (two-device, AAL2) are an IdP/operational property. | Strong-factor part via A2. |
| 4.2-S3 (jump server / role admin access) | XREF -> 1.1 | Secure-zone admin MFA is 1.1-A12 (assume-role MFA) and 1.1-A14 (MFA-deny policy). | - |
| 4.2-S3 (messaging/comm interface, HSM, firewall) | VENDOR / ONPREM | Vendor-application and appliance MFA, not AWS resources. | - |
| 4.2-S4 (VPN) | XREF -> 1.1-A10 | MFA-capable VPN authentication is 1.1-A10. | - |
| 4.2-S5 | PLATLIM / PROC | Location of the auth system is an architectural decision. | - |
| 4.2-S6 | PROC | Individual factor assignment is an operational/IdP property. | - |
| 4.2-S7 | RUNTIME / PLATLIM | SSO second-factor enforcement is an IdP runtime behaviour. | Cognito MFA (A1) when Cognito is the IdP. |
| 4.2-S8 | PROC | Contractual/operational for service-provider access. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Net-new surface: end-user / application authentication.** Assertion Register:

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 4.2-A1 | Swift **Cognito user pools enforce MFA** (`mfa_configuration == "ON"`, not OFF/OPTIONAL). | S1, S3 | SINGLE | TAG | `aws_cognito_user_pool.values.mfa_configuration` |
| 4.2-A2 | Swift Cognito pools enable a **TOTP software-token** second factor (strong possession factor, not SMS-only). | S2 | SINGLE | TAG | `aws_cognito_user_pool.values.software_token_mfa_configuration[*].enabled` |
| 4.2-A3 | Swift **RDS** instances enable **IAM database authentication** (token-based, avoids sole reliance on a single static password). | S1 | SINGLE | TAG | `aws_db_instance.values.iam_database_authentication_enabled` |
| 4.2-A4 | Swift **OpenSearch** domains use **federated auth** (Cognito or SAML), not only an internal user database. | S1 | SINGLE | TAG | `aws_opensearch_domain.values.cognito_options[*].enabled` / `advanced_security_options[*].saml_options` |

**Scope conventions (Stage 2.5).** All TAG-scoped to `swift:zone = "secure"`.

**Multi-service enumeration note.** The user-authentication surface expressible in
a plan is: Cognito (end-user application login, A1, A2), RDS IAM auth (database
login, A3), and OpenSearch federated auth (dashboard login, A4). Role/VPN/OS MFA
is XREF'd to 1.1 or excluded as VENDOR/RUNTIME.

---

## Stage 4: Specify

**4.2-A1: Cognito MFA ON (Variant A; OFF/OPTIONAL = violation)**
```
GIVEN   an aws_cognito_user_pool where tags["swift:zone"]=="secure"
WHEN    mfa_configuration != "ON"
THEN    DENY "CSCF 4.2 [4.2-A1]: Cognito user pool does not enforce MFA
        (mfa_configuration='%s'); interactive user access requires MFA
        (§ Control Statement). (resource: %s)"
```

**4.2-A2: Cognito TOTP (Variant A)**
```
GIVEN   an aws_cognito_user_pool where tags["swift:zone"]=="secure"
WHEN    no software_token_mfa_configuration block has enabled == true
THEN    DENY "CSCF 4.2 [4.2-A2]: Cognito user pool does not enable a TOTP software-token
        second factor; a strong possession factor is required (SMS-only is insufficient)
        (§ guidelines). (resource: %s)"
```

**4.2-A3: RDS IAM database auth (Variant A)**
```
GIVEN   an aws_db_instance where tags["swift:zone"]=="secure"
WHEN    iam_database_authentication_enabled != true
THEN    DENY "CSCF 4.2 [4.2-A3]: RDS instance does not enable IAM database
        authentication; database login should not rely solely on a single static
        password (§ Control Statement). (resource: %s)"
```

**4.2-A4: OpenSearch federated auth (Variant A)**
```
GIVEN   an aws_opensearch_domain where tags["swift:zone"]=="secure"
WHEN    neither cognito_options.enabled nor advanced_security_options SAML is enabled
THEN    DENY "CSCF 4.2 [4.2-A4]: OpenSearch domain does not use federated (Cognito/SAML)
        authentication; dashboard access should be MFA-backed via an IdP, not an
        internal user database alone (§ Control Statement). (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 4.2-A1 | S1, S3 | Control Statement | `aws_cognito_user_pool` | SINGLE | TAG | A | Full (Cognito MFA) |
| 4.2-A2 | S2 | guidelines | `aws_cognito_user_pool` | SINGLE | TAG | A | Partial (strong-factor facet) |
| 4.2-A3 | S1 | Control Statement | `aws_db_instance` | SINGLE | TAG | A | Partial (IAM auth ≈ stronger auth) |
| 4.2-A4 | S1 | Control Statement | `aws_opensearch_domain` | SINGLE | TAG | A | Partial (federated auth signal) |

### Completeness check

Verifiable/obligation items in § 4.2: S1-S8 = **8** (the closing Note that
interfaces must support MFA is informational).

- **Covered by ≥ 1 assertion**: S1, S2 (partial), S3 (partial) -> **3**
- **Documented exclusions**: S3 (jump/role -> XREF 1.1; interface/OS/firewall -> VENDOR/ONPREM), S4 (XREF 1.1-A10), S5 (PLATLIM/PROC), S6 (PROC), S7 (RUNTIME), S8 (PROC) -> **5**

```
covered (3) + excluded (5) == total (8)   ->   PASS
```

### Coverage summary

4.2's plan-evaluable contribution is the **end-user / application authentication
layer**: Cognito MFA and strong TOTP factor (A1, A2), RDS IAM database auth (A3),
and OpenSearch federated auth (A4). The infrastructure-layer MFA (roles, VPN) is
already enforced by Control 1.1 and is XREF'd; OS- and vendor-interface MFA is not
plan-evaluable. Stated limitation: like 1.3, 4.2 partly overlaps controls
already implemented, the framework's XREF mechanism keeps the library
non-duplicative while still recording full coverage.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_4_2.rego`
(package `swift_cscf.v2026.ctrl_4_2`), importing the shared helpers. Four
assertions -> four `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **A2/A4** treat a missing block (no `software_token_mfa_configuration`; no
  `cognito_options`/SAML) as a violation, since absence means the strong factor /
  federated auth is not configured.
- **A3** (IAM database auth) and **A4** (federated auth) are marked **Partial**,
  they are the plan-evaluable proxies for "MFA on database/dashboard login," not
  MFA proof in the strict factor sense.
- Role/VPN/OS MFA is intentionally **not** re-encoded here (owned by 1.1 /
  excluded), so 4.2's standalone footprint is deliberately focused.

**Validation.** Paired fixtures in `fixtures/`
(`ctrl_4_2_compliant.json`, `ctrl_4_2_non_compliant.json`). Compliant -> **0
violations (PASS)**; non-compliant -> **4 instances / 4 assertions (FAIL)**. Two CI
steps in `.github/workflows/cscf-gate.yml` enforce this. Evidence + attestation
samples: `evidence/samples/ctrl_4_2_*`.

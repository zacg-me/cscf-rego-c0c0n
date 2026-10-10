# Applied Translation: CSCF v2026 Control 2.4 (Back Office Data Flow Security)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 2.4, pp. 52-54, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4 (**not B**)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 4 assertions fire (4 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** Configuration
>, **Assurance mix:** A1 Direct ×4
>, **Delegations (owning control):** 2.1 (internal transport TLS), 5.4 (key protection)
>, **Plan-time resolvability:** all R1
>, **Note:** Data-level LAU/XML-DSIG is VENDOR-excluded

> **Relationship to Control 2.1.** 2.1 (Internal Data Flow Security) already
> enforces *internal-service* transport encryption (ALB/NLB listeners, RDS,
> Redshift, ElastiCache, MSK, OpenSearch, EFS, API Gateway TLS version, KMS). 2.4
> protects the **back-office boundary**, the flows between back-office first hops
> and the Swift secure zone. To avoid duplication, internal-service TLS and key
> protection are recorded as **XREF exclusions** (to 2.1 / 5.4), and 2.4's own
> assertions target the boundary connectivity 2.1 does not cover: **site-to-site
> VPN (IPsec)**, **mutual TLS**, and **Direct Connect (MACsec)**. Message/data-level
> mechanisms (AES-GCM LAU, XML DSIG) are Swift-application features -> VENDOR
> exclusion.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 2.4-S1 | Confidentiality, integrity, and authentication mechanisms protect data exchanged between Swift components and the back-office first hops they connect to. | Control Statement |
| 2.4-S2 | Inventorise back-office<->Swift flows and assess each for confidentiality/integrity/authenticity. | §guidelines |
| 2.4-S3 | End-to-end data-level protection (e.g. AES-GCM LAU, XML DSIG) with recipient authentication and replay prevention. | §guidelines (1) |
| 2.4-S4 | For direct point-to-point connectivity, a secure protocol ensuring authentication/integrity/confidentiality, e.g. LAU + confidentiality, authenticated API over TLS, or **two-way TLS**. | §guidelines (1) |
| 2.4-S5 | Per-leg protection where bridging servers are used, and the bridging servers are themselves secured. | §guidelines (2) |
| 2.4-S6 | Define a risk-based plan to secure/migrate flows not yet protected. | §guidelines |
| 2.4-S7 | Secure protocols use current cryptographic algorithms (AES, ECDHE) with adequate key lengths. | §guidelines |
| 2.4-S8 | Credentials and private/bilateral keys used to secure flows are protected (e.g. KMS). | §guidelines |
| 2.4-legacy | Legacy direct back-office flows. *(Advisory now; mandatory in ~v2028)* | In-scope / Notes |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 2.4-S2 | PROC | Flow inventory and assessment is an analysis activity, not a resource state. | - |
| 2.4-S3 | VENDOR / RUNTIME | AES-GCM LAU / XML DSIG are Swift-application data-level mechanisms; replay prevention is runtime. | - |
| 2.4-S4 (internal two-way TLS on ALB/NLB) | XREF -> 2.1 | Internal-service transport TLS is Control 2.1. | Boundary VPN/mTLS via A1-A3. |
| 2.4-S5 | XREF / PROC | Bridging-server security is delivered by the other controls' bridging-server scope; leg inventory is procedural. | - |
| 2.4-S6 | PROC | Remediation planning / risk-based prioritisation. | - |
| 2.4-S7 (internal TLS policy) | XREF -> 2.1 | ELB/OpenSearch TLS-policy allowlists are Control 2.1 (A2/A10/A13). | VPN cipher strength via A1; DX via A4. |
| 2.4-S8 | XREF -> 5.4 / 2.1 | Key/credential protection is Control 5.4 (repository) and 2.1 (KMS A14/A15). | - |
| 2.4-legacy | ADV | Advisory in v2026 (becomes mandatory ~v2028). | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Net-new surface: back-office boundary connectivity.** Assertion Register:

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 2.4-A1 | Back-office **site-to-site VPN** tunnels use **AES-256** Phase-2 encryption (no AES-128; algorithms explicitly set). | S4, S7 | SINGLE | TAG | `aws_vpn_connection.values.tunnel{1,2}_phase2_encryption_algorithms` |
| 2.4-A2 | Back-office site-to-site VPN tunnels use **IKEv2** only (not IKEv1). | S4, S7 | SINGLE | TAG | `aws_vpn_connection.values.tunnel{1,2}_ike_versions` |
| 2.4-A3 | Back-office **API Gateway** custom domains enforce **mutual TLS** (authenticity of the connecting party). | S1, S4 | SINGLE | TAG | `aws_api_gateway_domain_name.values.mutual_tls_authentication[*].truststore_uri` |
| 2.4-A4 | **Direct Connect** connections use **MACsec** (`encryption_mode == "must_encrypt"`). | S4, S7 | SINGLE | TAG | `aws_dx_connection.values.encryption_mode` |

**Scope conventions (Stage 2.5).** All TAG-scoped to `swift:zone = "secure"`.
Architecture note: 2.4 applies to A1-A4, not B.

**Multi-service enumeration note.** The back-office boundary in AWS is reached via
site-to-site VPN (A1 cipher strength, A2 protocol version), API Gateway with mTLS
(A3 authenticity), and Direct Connect (A4 MACsec). Internal-service TLS and KMS
key protection are 2.1 / 5.4 and are XREF'd.

---

## Stage 4: Specify

**2.4-A1: VPN Phase-2 AES-256 (Variant A; weak or unset = violation)**
```
GIVEN   an aws_vpn_connection where tags["swift:zone"]=="secure"
WHEN    a tunnel's phase2 encryption algorithms are unset OR include "AES128"
THEN    DENY "CSCF 2.4 [2.4-A1]: back-office VPN tunnel does not enforce AES-256 Phase-2
        encryption (§ secure protocols). (resource: %s)"
```

**2.4-A2: VPN IKEv2 (Variant A)**
```
GIVEN   an aws_vpn_connection where tags["swift:zone"]=="secure"
WHEN    a tunnel's IKE versions are unset OR include "ikev1"
THEN    DENY "CSCF 2.4 [2.4-A2]: back-office VPN tunnel permits IKEv1; IKEv2 is required
        (§ secure protocols). (resource: %s)"
```

**2.4-A3: API Gateway mutual TLS (Variant A)**
```
GIVEN   an aws_api_gateway_domain_name where tags["swift:zone"]=="secure"
WHEN    no mutual_tls_authentication block has a truststore_uri
THEN    DENY "CSCF 2.4 [2.4-A3]: back-office API domain does not enforce mutual TLS;
        the connecting party's authenticity is not verified (§ authentication). (resource: %s)"
```

**2.4-A4: Direct Connect MACsec (Variant A)**
```
GIVEN   an aws_dx_connection where tags["swift:zone"]=="secure"
WHEN    encryption_mode != "must_encrypt"
THEN    DENY "CSCF 2.4 [2.4-A4]: Direct Connect does not enforce MACsec encryption
        (encryption_mode='%s') (§ confidentiality). (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 2.4-A1 | S4, S7 | secure protocols | `aws_vpn_connection` | SINGLE | TAG | A | Full (VPN cipher) |
| 2.4-A2 | S4, S7 | secure protocols | `aws_vpn_connection` | SINGLE | TAG | A | Full (IKE version) |
| 2.4-A3 | S1, S4 | authentication | `aws_api_gateway_domain_name` | SINGLE | TAG | A | Full (mTLS) |
| 2.4-A4 | S4, S7 | confidentiality | `aws_dx_connection` | SINGLE | TAG | A | Full (MACsec) |

### Completeness check

Verifiable/obligation items in § 2.4: S1-S8 = **8** (legacy flows are Advisory).

- **Covered by ≥ 1 assertion**: S1, S4, S7 -> **3**
- **Documented exclusions**: S2 (PROC), S3 (VENDOR/RUNTIME), S5 (XREF/PROC), S6 (PROC), S8 (XREF 5.4/2.1) -> **5**

```
covered (3) + excluded (5) == total (8)   ->   PASS
```

### Coverage summary

2.4's automatable contribution is the **back-office boundary connectivity**:
VPN cipher strength and IKE version (A1, A2), API mutual-TLS authenticity (A3),
and Direct Connect MACsec (A4). Internal-service TLS (2.1) and key protection
(5.4) are XREF'd; the data-level Swift-application mechanisms are excluded
(VENDOR). Stated limitation: like 4.2 and 1.3, 2.4 partly overlaps an existing
control (2.1), the XREF mechanism records full coverage without duplicate rules,
and 2.4's boundary-connectivity checks are genuinely new.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_2_4.rego`
(package `swift_cscf.v2026.ctrl_2_4`), importing the shared helpers. Four
assertions -> four `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **A1/A2** treat an *unset* tunnel algorithm/version list as a violation, since
  AWS defaults permit a broad (weaker) set, the control requires explicit strong
  configuration. Both tunnels are checked.
- **A3** requires a `mutual_tls_authentication` block with a `truststore_uri`;
  one-way TLS alone (transport confidentiality) is 2.1's job, so A3 is specifically
  the authenticity check.
- These resources are absent from the Phase I mock plans; 2.4 is validated on its
  own boundary-connectivity fixtures.

**Validation.** Paired fixtures in `fixtures/`
(`ctrl_2_4_compliant.json`, `ctrl_2_4_non_compliant.json`). Compliant -> **0
violations (PASS)**; non-compliant -> **4 instances / 4 assertions (FAIL)**. Two CI
steps in `.github/workflows/cscf-gate.yml` enforce this. Evidence + attestation
samples: `evidence/samples/ctrl_2_4_*`.

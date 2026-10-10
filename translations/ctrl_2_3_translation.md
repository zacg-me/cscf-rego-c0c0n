# Applied Translation: CSCF v2026 Control 2.3 (System Hardening)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 2.3, pp. 50-51, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4, B (all)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant -> 0 violations; non-compliant -> 4 assertions fire (4 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** Configuration
>, **Assurance mix:** A1 Direct ×4
>, **Delegations (owning control):** 1.1 (ports/services), 4.1 + 5.4 (default passwords), 2.6 (auto-lock)
>, **Plan-time resolvability:** all R1
>, **Note:** OS-host hardening steps are RUNTIME-excluded

> **The thinnest of the automatable set.** System hardening is largely an OS/host
> runtime activity (change default passwords, disable accounts/services, remove
> software, restrict USB, auto-lock). Those map to controls already implemented or
> to runtime: unnecessary ports/services -> Control 1.1; default passwords -> 4.1 /
> 5.4; auto-lock/inactivity -> 2.6; OS account/software removal -> RUNTIME. 2.3's
> genuinely net-new, plan-evaluable surface is **cloud attack-surface reduction**,
> the "adjust vulnerable default configurations" clause applied to managed
> services: no public exposure (RDS, S3, OpenSearch) and no privileged containers.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 2.3-S1 | Security hardening is conducted and maintained on all in-scope components (reduce attack surface via least privilege). | Control Statement |
| 2.3-S2 | Systems are hardened per vendor / industry (CIS, DISA STIG, NIST) / local security-configuration guidance. | §guidelines |
| 2.3-S3 | Minimum hardening: change default passwords; disable unnecessary accounts; disable/restrict unnecessary services, ports, protocols; remove unnecessary software; restrict physical ports; set auto-lock; **adjust vulnerable default configurations**. | §guidelines |
| 2.3-S4 | Deviations from the hardening baseline are documented with justification and mitigations. | §guidelines |
| 2.3-S5 | Systems are maintained secure (checked at least twice per year; secure settings re-applied). | §guidelines |
| 2.3-OE | Application allowlisting on the OS; apply to bridging servers. *(Optional Enhancement)* | Optional Enhancement |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 2.3-S2 | PROC | Choice of hardening baseline (CIS/STIG/NIST) is a documented decision, not a resource state. | - |
| 2.3-S3 (ports/services/protocols) | XREF -> 1.1 | Unnecessary-port/service restriction is Control 1.1 (security groups / NACLs). | - |
| 2.3-S3 (default passwords) | XREF -> 4.1 / 5.4 | Password policy / repository. | - |
| 2.3-S3 (auto-lock / inactivity) | XREF -> 2.6 | Session inactivity is Control 2.6. | - |
| 2.3-S3 (disable accounts / remove software / USB) | RUNTIME / ONPREM | OS-host runtime and physical configuration. | - |
| 2.3-S4 | PROC | Deviation documentation. | - |
| 2.3-S5 | PROC / DRIFT | Periodic re-checking is operational / post-deployment drift (Phase II continuous). | - |
| 2.3-OE | ADV / RUNTIME | Application allowlisting is an OS runtime feature. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Net-new surface: cloud attack-surface reduction (vulnerable-default configs).**
Assertion Register:

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 2.3-A1 | Swift **RDS** instances are **not publicly accessible**. | S1, S3 | SINGLE | TAG | `aws_db_instance.values.publicly_accessible` |
| 2.3-A2 | **S3 public-access blocks** enable all four settings (no public exposure). | S1, S3 | SINGLE | ACCT | `aws_s3_bucket_public_access_block.values.{block_public_acls,block_public_policy,ignore_public_acls,restrict_public_buckets}` |
| 2.3-A3 | Swift **OpenSearch** domains are **VPC-attached** (no public endpoint). | S1, S3 | SINGLE | TAG | `aws_opensearch_domain.values.vpc_options[*].subnet_ids` |
| 2.3-A4 | Swift **ECS** task definitions run **no privileged containers**. | S1, S3 | JSON | TAG | `aws_ecs_task_definition.values.container_definitions` [JSON] -> `[*].privileged` |

**Scope conventions (Stage 2.5).** A1/A3/A4 TAG-scoped to `swift:zone = "secure"`.
A2 is ACCT-scoped: an S3 public-access block that does not block is a defect
regardless of tag (and the resource type carries no tags). 2.3-A2 is general
attack-surface reduction, distinct from 6.4-A13 which scopes public-access-block
to CloudTrail log buckets for audit-log integrity.

---

## Stage 4: Specify

**2.3-A1: RDS not public (Variant A)**
```
GIVEN   an aws_db_instance where tags["swift:zone"]=="secure"
WHEN    publicly_accessible == true
THEN    DENY "CSCF 2.3 [2.3-A1]: RDS instance is publicly accessible; attack surface must be
        minimised (§ adjust vulnerable defaults). (resource: %s)"
```

**2.3-A2: S3 public-access block (Variant A)**
```
GIVEN   an aws_s3_bucket_public_access_block resource
WHEN    any of the four block settings is not true
THEN    DENY "CSCF 2.3 [2.3-A2]: S3 public-access block does not enable all four settings;
        public exposure is not fully blocked (§ adjust vulnerable defaults). (resource: %s)"
```

**2.3-A3: OpenSearch VPC (Variant A)**
```
GIVEN   an aws_opensearch_domain where tags["swift:zone"]=="secure"
WHEN    no vpc_options block declares subnet_ids
THEN    DENY "CSCF 2.3 [2.3-A3]: OpenSearch domain is not VPC-attached (public endpoint);
        attack surface must be minimised (§ adjust vulnerable defaults). (resource: %s)"
```

**2.3-A4: ECS no privileged container (Variant C, JSON)**
```
GIVEN   an aws_ecs_task_definition where tags["swift:zone"]=="secure"
WHEN    a container in container_definitions (JSON) has privileged == true
THEN    DENY "CSCF 2.3 [2.3-A4]: ECS task definition runs a privileged container; disable
        unnecessary capabilities (§ least privilege). (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 2.3-A1 | S1, S3 | vulnerable defaults | `aws_db_instance` | SINGLE | TAG | A | Full (RDS public) |
| 2.3-A2 | S1, S3 | vulnerable defaults | `aws_s3_bucket_public_access_block` | SINGLE | ACCT | A | Full (S3 public) |
| 2.3-A3 | S1, S3 | vulnerable defaults | `aws_opensearch_domain` | SINGLE | TAG | A | Full (OpenSearch endpoint) |
| 2.3-A4 | S1, S3 | least privilege | `aws_ecs_task_definition` | JSON | TAG | C | Full (privileged container) |

### Completeness check

Verifiable/obligation items in § 2.3: S1-S5 = **5** (OE is Advisory).

- **Covered by ≥ 1 assertion**: S1, S3 (the vulnerable-default-config subset) -> **2**
- **Documented exclusions**: S2 (PROC), S4 (PROC), S5 (PROC/DRIFT) -> **3**
  (plus S3's ports/passwords/auto-lock sub-clauses XREF'd to 1.1 / 4.1 / 5.4 / 2.6)

```
covered (2) + excluded (3) == total (5)   ->   PASS
```

### Coverage summary

2.3's automatable contribution is **cloud attack-surface reduction**, no public
RDS/S3/OpenSearch exposure and no privileged ECS containers, i.e. the
"adjust vulnerable default configurations" minimum applied to managed services.
The OS-host hardening steps (accounts, software, USB, auto-lock) and the choice of
hardening baseline are XREF'd or excluded as RUNTIME/PROC. Stated limitation: 2.3
is the thinnest automatable control, its net-new footprint is small, and most of
its substance lives in the OS runtime and in adjacent controls, recorded via XREF.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_2_3.rego`
(package `swift_cscf.v2026.ctrl_2_3`), importing the shared helpers. Four
assertions -> four `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **A2** is ACCT-scoped (the resource carries no tags); it overlaps 6.4-A13 in
  mechanism but differs in scope/intent (general hardening vs. audit-log-bucket
  integrity).
- **A4** parses `container_definitions` (a JSON array string) and flags any
  container with `privileged == true`.
- Most of 2.3 is OS-runtime; these four are the plan-evaluable "vulnerable default"
  checks, the honest limit of shift-left hardening.

**Validation.** Paired fixtures in `fixtures/`
(`ctrl_2_3_compliant.json`, `ctrl_2_3_non_compliant.json`). Compliant -> **0
violations (PASS)**; non-compliant -> **4 instances / 4 assertions (FAIL)**. Two CI
steps in `.github/workflows/cscf-gate.yml` enforce this. Evidence + attestation
samples: `evidence/samples/ctrl_2_3_*`.

# Applied Translation: CSCF v2026 Control 1.3 (Virtualisation or Cloud Platform Protection)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 1.3, pp. 38-40, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory (Advisory for architecture B), **Architecture:** A1, A2, A3, A4, B
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant fixture -> 0 violations; non-compliant fixture -> 5 assertions fire (5 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** **Meta**
>, **Assurance mix:** A1 Direct ×4, A2 Partial ×1
>, **Delegations (owning control):** 1.1, 1.2, 4.1, 4.2, 2.2, 1.4, 2.7, 3.1 (CSP)
>, **Plan-time resolvability:** all R1
>, **Note:** Low yield is correct for a Meta control: its text re-applies other controls

> **1.3 is a meta-control.** Its Control Statement is *"secure the virtualisation
> or cloud platform, VMs, and supporting virtual infrastructure to the **same
> level as physical systems**."* Most of its guidelines therefore say "apply the
> other controls to the virtualisation layer too" - secure-zone placement (->1.1),
> privileged access (->1.2), login/password (->4.1), MFA (->4.2), security updates
> (->2.2), internet restriction (->1.4), vulnerability scanning (->2.7), physical
> protection (->3.1). Those are recorded as **XREF exclusions**. What 1.3 adds
> that no other control covers is **VM / cloud-platform-specific hardening**, the
> instance metadata service, disk encryption at rest, and platform-level VM
> isolation. That is where 1.3's own assertions sit.

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 1.3-S1 | Secure the virtualisation/cloud platform, virtual machines, and supporting virtual infrastructure (e.g. firewalls) **to the same level as physical systems**. | Control Statement |
| 1.3-S2 | The same security requirements apply to the platform/VMs as to other systems: secure-zone location, privileged-access restrictions, login/password policies, security updates, restriction of internet access. | §guidelines b1 |
| 1.3-S3 | Vulnerability scanning is performed on Swift-related VMs and, when possible, on the platform. | §guidelines b2 |
| 1.3-S4 | The platform systems are subject to physical protection preventing unauthorised physical access. | §guidelines b3 |
| 1.3-S5 | **VM isolation** is ensured on the platform to prevent lateral movement out of a VM (to other VMs / the hypervisor / bypassing network controls). | §guidelines b4 |
| 1.3-S5a | Filtering/inspection of network flows reaching Swift-related VMs is performed, preferably external to the platform or enforced at the hypervisor level. | §guidelines b4.o1 |
| 1.3-S5b | If isolation is ensured, hosted VMs maintain their own security classification. | §guidelines b4.o2 |
| 1.3-S6 | When MFA is implemented for interactive access to Swift VM OSes (per 4.2), MFA is not mandatory at the platform-management level. | §guidelines b5 |
| 1.3-S7 | When relying on a third party for the platform, engage the third party to obtain reasonable comfort the objective is met. | §guidelines b6 |
| 1.3-OE | Apply the control to all bridging servers used for back-office<->Swift data exchange. *(Optional Enhancement)* | Optional Enhancement |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 1.3-S2 (secure zone) | XREF -> 1.1 | Secure-zone placement/segmentation is Control 1.1. | - |
| 1.3-S2 (privileged access) | XREF -> 1.2 | OS privileged-account control is Control 1.2. | - |
| 1.3-S2 (login/password) | XREF -> 4.1 | Password policy is Control 4.1. | - |
| 1.3-S2 (security updates) | XREF -> 2.2 | Security-update installation is Control 2.2. | - |
| 1.3-S2 (internet restriction) | XREF -> 1.4 | Internet-access restriction is Control 1.4. | - |
| 1.3-S3 (vuln scanning) | XREF -> 2.7 | Vulnerability scanning is Control 2.7. | - |
| 1.3-S4 (physical) | XREF -> 3.1 / PROC | Physical protection of the cloud platform is the provider's responsibility (AWS shared-responsibility); attestable via AWS compliance reports, not a Terraform plan. | - |
| 1.3-S5a (hypervisor-level filtering) | PLATLIM | Hypervisor-level packet inspection is not represented as a Terraform resource. | Partial via 1.1 security groups (VM network filtering). |
| 1.3-S5b (VM classification) | PROC | A classification decision, not a plan-evaluable resource state. | - |
| 1.3-S6 (MFA) | XREF -> 4.2 | Multi-factor authentication is Control 4.2. | - |
| 1.3-S7 (third-party comfort) | PROC | Contractual/assurance activity with the provider. | - |
| 1.3-OE | ADV | Optional Enhancement. | - |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Net-new automatable surface: VM / cloud-platform hardening.** Assertion Register:

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 1.3-A1 | Swift VMs enforce **IMDSv2** (token-required instance metadata). | S1, S5 | SINGLE | TAG | `aws_instance.values.metadata_options[*].http_tokens == "required"` |
| 1.3-A2 | Swift VMs restrict the **IMDS hop limit to 1** (prevents metadata relay / lateral reach from containers/proxies). | S5 | SINGLE | TAG | `aws_instance.values.metadata_options[*].http_put_response_hop_limit` |
| 1.3-A3 | Swift VM **root volumes are encrypted at rest**. | S1 | SINGLE | TAG | `aws_instance.values.root_block_device[*].encrypted == true` |
| 1.3-A4 | Swift **EBS volumes are encrypted at rest**. | S1 | SINGLE | TAG | `aws_ebs_volume.values.encrypted == true` |
| 1.3-A5 | Swift VMs use **dedicated or host tenancy** (platform-level VM isolation). | S1, S5 | SINGLE | TAG | `aws_instance.values.tenancy in {"dedicated","host"}` |

**Scope conventions (Stage 2.5).** All TAG-scoped to `swift:zone = "secure"`
(reusing `helpers.is_swift_tagged`). These are properties of the Swift VMs and
their storage specifically, so an account-wide scope would over-report on
non-Swift compute, consistent with the Phase I scope-enforcement lesson.

**Multi-service enumeration note.** The VM/platform surface in AWS is: instance
metadata service (**A1, A2**, the top lateral-movement vector on EC2), VM disk
encryption (**A3** root + **A4** attached volumes), and tenancy/isolation
(**A5**). Network-flow filtering to VMs (S5a) is left to 1.1's security-group
rules (partial) plus a PLATLIM exclusion for the hypervisor level.

---

## Stage 4: Specify

**1.3-A1: IMDSv2 required (Variant A; absence = violation)**
```
GIVEN   an aws_instance where tags["swift:zone"]=="secure"
WHEN    no metadata_options block sets http_tokens == "required"
THEN    DENY "CSCF 1.3 [1.3-A1]: VM does not enforce IMDSv2 (token-required metadata);
        the instance metadata service is a lateral-movement/credential-theft vector
        (§ guidelines). (resource: %s)"
```

**1.3-A2: IMDS hop limit (Variant A)**
```
GIVEN   an aws_instance where tags["swift:zone"]=="secure"
WHEN    metadata_options.http_put_response_hop_limit > 1
THEN    DENY "CSCF 1.3 [1.3-A2]: VM allows an IMDS hop limit > 1, enabling metadata
        relay beyond the instance (§ guidelines). (resource: %s)"
```

**1.3-A3: Root volume encryption (Variant A)**
```
GIVEN   an aws_instance where tags["swift:zone"]=="secure"
WHEN    a root_block_device has encrypted != true
THEN    DENY "CSCF 1.3 [1.3-A3]: VM root volume is not encrypted at rest (§ guidelines).
        (resource: %s)"
```

**1.3-A4: EBS volume encryption (Variant A)**
```
GIVEN   an aws_ebs_volume where tags["swift:zone"]=="secure"
WHEN    encrypted != true
THEN    DENY "CSCF 1.3 [1.3-A4]: Swift EBS volume is not encrypted at rest (§ guidelines).
        (resource: %s)"
```

**1.3-A5: VM tenancy isolation (Variant A; coverage = Partial)**
```
GIVEN   an aws_instance where tags["swift:zone"]=="secure"
WHEN    tenancy not in {"dedicated","host"}
THEN    DENY "CSCF 1.3 [1.3-A5]: VM uses shared (default) tenancy; platform-level VM
        isolation requires dedicated or host tenancy (§ guidelines). (resource: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 1.3-A1 | S1, S5 | guidelines | `aws_instance` | SINGLE | TAG | A | Full (IMDSv2) |
| 1.3-A2 | S5 | guidelines | `aws_instance` | SINGLE | TAG | A | Full (hop limit) |
| 1.3-A3 | S1 | guidelines | `aws_instance` | SINGLE | TAG | A | Full (root at-rest) |
| 1.3-A4 | S1 | guidelines | `aws_ebs_volume` | SINGLE | TAG | A | Full (volume at-rest) |
| 1.3-A5 | S1, S5 | guidelines | `aws_instance` | SINGLE | TAG | A | Partial (tenancy is one facet of isolation) |

### Completeness check

Verifiable/obligation items in § 1.3: S1, S2, S3, S4, S5, S5a, S6, S7, OE = **9**
(S5b is informational context (a classification decision) not a verifiable
requirement, so it is excluded from the denominator per Stage 4.5).

- **Covered by ≥ 1 assertion**: S1, S5 (VM hardening + isolation) -> **2**
- **Documented exclusions**: S2 (XREF 1.1/1.2/4.1/2.2/1.4), S3 (XREF 2.7), S4 (XREF 3.1/PROC), S5a (PLATLIM), S6 (XREF 4.2), S7 (PROC), OE (ADV) -> **7**

```
covered (2) + excluded (7) == total verifiable items (9)   ->   PASS
```

### Coverage summary

1.3's automatable contribution is **VM / cloud-platform hardening**, the piece no
other control owns: IMDSv2 and hop-limit (A1, A2), disk encryption at rest for VM
roots and volumes (A3, A4), and tenancy-based platform isolation (A5). The rest of
1.3 is, by its own wording, the *other* controls applied to the virtualisation
layer, and is XREF-excluded. Stated limitation: 1.3 is a
**meta-control**, so its standalone automatable footprint is small; its value is
that it *extends the existing controls onto the compute layer* rather than adding
wholly independent logic.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_1_3.rego`
(package `swift_cscf.v2026.ctrl_1_3`), importing the shared helpers. Five
assertions -> five `deny` rules. Passes `opa check` and `opa fmt`.

**Encoding notes / limitations**
- **Absence handling.** A1 treats a missing `metadata_options` block (or one
  without `http_tokens=="required"`) as a violation. A3 fires only when a
  `root_block_device` is present and not encrypted (a plan without the block
  cannot be judged), a documented gap for real plans.
- **A5 tenancy** is the strictest reading of "VM isolation"; dedicated/host
  tenancy has cost implications, so it is marked **Partial** and should be
  presented as the high-assurance interpretation, not the only valid one.
- The Phase I mock plans contain **no `aws_instance` / `aws_ebs_volume`**, so a
  smoke-run of 1.3 against them yields zero violations (executes cleanly, nothing
  to evaluate), 1.3 needs its own compute-bearing fixtures.

**Validation (done).** Paired fixtures in `fixtures/`
(`ctrl_1_3_compliant.json`, `ctrl_1_3_non_compliant.json`), each carrying
`aws_instance` + `aws_ebs_volume`. Run:

```
python pipeline/gate.py \
  --plan fixtures/ctrl_1_3_non_compliant.json \
  --policies policies \
  --controls ctrl_1_3
```

Result: compliant -> **0 violations (PASS)**; non-compliant -> **5 instances / 5
assertions (FAIL)**, every assertion A1-A5 firing. Two CI steps in
`.github/workflows/cscf-gate.yml` enforce this on every push/PR. Committed
evidence + attestation samples: `evidence/samples/ctrl_1_3_*`.

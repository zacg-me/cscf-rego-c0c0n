# Applied Translation: CSCF v2026 Control 1.4 (Restriction of Internet Access)

**Author:** Zachariah George
**Framework:** Translation Framework v1.2.1 (Parse -> Decompose -> Scope -> Map -> Specify -> Trace -> Encode)
**CSCF source:** v2026 (01 July 2025), § 1.4, pp. 40-42, the CSCF v2026 document (available from Swift)
**Control type:** Mandatory, **Architecture:** A1, A2, A3, A4, B (all)
**Status:** Phase II decomposition, encoded, **validated against paired fixtures**, and **wired into the CI gate**. Compliant fixture -> 0 violations; non-compliant fixture -> 6 assertions fire (7 instances).

> **Framework v2.0 classification.**
>, **Control archetype:** Configuration
>, **Assurance mix:** A1 Direct ×3, A2 Partial ×1, A3 Proxy ×1
>, **Delegations (owning control):** 1.1 (IGW route, public-IP subnet, all-protocol SG/NACL egress), 4.2 (MFA)
>, **Plan-time resolvability:** **1.4-A6 is R3 (apply-time)**, joins instance->SG by runtime `id`; may fail open on a real plan. All others R1
>, **Note:** 1.4-A4 (VPC endpoint) is a Proxy signal, not proof of egress avoidance

> **Relationship to Control 1.1.** 1.1 (Swift Environment Protection) already
> enforces the *inbound* segmentation boundary and several *outbound* network
> facts (Internet-Gateway routes, public-IP subnets, all-protocol egress, NACL
> egress). 1.4 is specifically about **restricting outbound Internet access from
> the secure zone**. To avoid duplication (Framework §3, Stage 5 rule 5 and the
> XREF exclusion category), requirements already fully covered by a 1.1 assertion
> are recorded here as **XREF exclusions to 1.1**, and 1.4's own assertions target
> internet-egress paths that 1.1 does **not** check (NAT gateway routes,
> egress-only IGW, browsing-port egress, VPC-endpoint usage, jump-server /
> operator instance internet exposure).

---

## Stage 1: Parse

### 1.1 Source Requirements List

| ID | Source (verbatim / close paraphrase) | CSCF § |
|----|--------------------------------------|--------|
| 1.4-S1 | All general-purpose and dedicated operator PCs, and systems within the secure zone, have **controlled direct internet access** in line with business. | Control Statement |
| 1.4-S2 | General-purpose internet browsing (incl. e-mail) from systems within the secure zone **is not permitted**. | §a |
| 1.4-S3 | Internet access from systems within the secure zone **is highly restricted and ideally should be blocked**. | §a |
| 1.4-S4 | When possible, activities requiring the Internet are conducted **outside** the secure zone. | §a |
| 1.4-S5 | If internet access is needed from the secure zone, grant only to **allowlisted URL destinations through a proxy with content inspection** and blocking/filtering; **outbound-initiated connections only**. | §a |
| 1.4-S6 | The **jump server does not have internet access**. | §a |
| 1.4-S7 | Control internet access on general-purpose operator PCs used to reach the service provider / connector / browser GUI. | §b |
| 1.4-S8 | Control access via one of: remote-desktop/VM solution; allowlisted-URL proxy (outbound-only, content inspection); Web Gateway with denylist. | §b |
| 1.4-S9 | Alternative: enforce a jump server with **no internet access combined with MFA** (per control 4.2). | §b |
| 1.4-S10 | Internet access from middleware server / virtualisation platform is highly restricted/blocked. *(Advisory)* | §c |
| 1.4-S11 | If needed from those systems, allowlisted-URL proxy with content inspection. *(Advisory)* | §c |
| 1.4-S12 | Apply the control to all bridging servers used for back-office<->Swift data exchange. *(Optional Enhancement)* | Optional Enhancement |

### 1.2 Exclusions Register

| Source | Category | Rationale | Partial coverage |
|--------|----------|-----------|------------------|
| 1.4-S4 | PROC | "Conduct internet activities outside the secure zone" is an operational practice, not a plan-evaluable resource state. | - |
| 1.4-S5 (proxy/URL allowlist, content inspection) | PLATLIM / VENDOR | A forward proxy's URL-allowlist and content-inspection config is not expressed as a Terraform resource, even when the proxy host is. | Partial via 1.4-A1/A3 (network egress paths). |
| 1.4-S5 (outbound-initiated only) | RUNTIME | Statefulness of connections is a runtime firewall behaviour, not a plan attribute. | Partial via SG/NACL egress checks (1.1, 1.4-A3). |
| 1.4-S7 (operator-PC control) | ONPREM | General-purpose operator PCs are typically on-prem / general-IT endpoints, not AWS resources in the plan. | Partial where operator hosts are AWS instances (1.4-A5). |
| 1.4-S8 | PLATLIM / PROC | Remote-desktop/VM brokering, Web Gateway and denylist are proxy/architectural mechanisms not represented in a Terraform plan. | Partial via 1.4-A4 (VPC-endpoint egress avoidance). |
| 1.4-S9 (MFA) | XREF -> 4.2 | MFA enforcement is control 4.2's assertion set. | Jump-server-no-internet part covered by 1.4-A5/A6. |
| 1.4-S10, S11 | ADV | Advisory (§c). Not in the mandatory assertion register. | - |
| 1.4-S12 | ADV | Optional Enhancement. | - |
| Internet-Gateway route from secure zone | XREF -> 1.1-A6 | Direct IGW route already denied by 1.1-A6. | Fully covered by 1.1. |
| Public-IP subnets | XREF -> 1.1-A5 | `map_public_ip_on_launch` already denied by 1.1-A5. | Fully covered by 1.1 (subnet level); 1.4-A5 adds instance level. |
| All-protocol unrestricted egress (SG) | XREF -> 1.1-A4 | Protocol `-1` egress to `0.0.0.0/0` already denied by 1.1-A4. | 1.4-A3 adds browsing-port (80/443) egress. |
| All-protocol NACL egress | XREF -> 1.1-A8 | Default-NACL all-egress already denied by 1.1-A8. | Fully covered by 1.1. |

---

## Stage 2 (Decompose, Stage 2.5) Scope, Stage 3, Map

**Assertion Register (with scope type, scope level, and Terraform mapping):**

| ID | Assertion (compliant state) | Src | Scope type | Scope level | Terraform resource -> attribute |
|----|------------------------------|-----|------------|-------------|--------------------------------|
| 1.4-A1 | No secure-zone route sends `0.0.0.0/0` to a **NAT gateway** (uncontrolled outbound Internet path). | S1, S3 | SINGLE | VPC | `aws_route.values.destination_cidr_block` + `.nat_gateway_id` |
| 1.4-A2 | No secure-zone route sends `::/0` to an **egress-only Internet gateway** (IPv6 outbound Internet). | S3 | SINGLE | VPC | `aws_route.values.destination_ipv6_cidr_block` + `.egress_only_gateway_id` |
| 1.4-A3 | No secure-zone security group permits **outbound 80/443 to `0.0.0.0/0` or `::/0`** (direct internet browsing/egress). | S2, S3 | SINGLE | VPC | `aws_security_group.values.egress[*]` (`from_port`/`to_port`, `cidr_blocks`, `ipv6_cidr_blocks`) |
| 1.4-A4 | The secure zone provides at least one **VPC endpoint** so AWS-service traffic need not egress to the Internet. | S1, S8 | PRESENCE | VPC | `aws_vpc_endpoint` - `count(...) > 0` |
| 1.4-A5 | **Jump-server / operator instances** do not auto-assign a **public IP**. | S6, S7 | SINGLE | TAG | `aws_instance.values.associate_public_ip_address` |
| 1.4-A6 | A **jump-server instance's security groups** do not permit egress to `0.0.0.0/0` (jump server has no Internet access). | S6 | RELATION | TAG | `aws_instance.values.vpc_security_group_ids` -> `aws_security_group.values.id` -> `.egress[*].cidr_blocks` |

**Scope conventions (Stage 2.5).**
- **VPC scope** (A1-A4): resources in the Swift VPC, identified as in Control 1.1 (VPC tag / `input.swift_vpc_id`). For network resources without a direct VPC tag (routes, SGs), evaluate all and rely on the secure-zone deployment being the plan under test, consistent with 1.1's VPC-scoped network rules.
- **TAG scope** (A5, A6): `swift:zone = "secure"` for secure-zone membership, plus a **new role tag `swift:role = "jump_server"`** to identify jump-server / operator instances. This convention is introduced by 1.4 and must be applied by the infrastructure team to operator/jump hosts.

**Multi-service enumeration note.** The Internet-egress surface in AWS is: IGW routes (-> 1.1-A6, XREF), NAT-gateway routes (**A1**), egress-only IGW routes (**A2**), security-group egress (**A3**; all-protocol case -> 1.1-A4 XREF), NACL egress (-> 1.1-A8, XREF), instance public IPs (**A5**; subnet case -> 1.1-A5 XREF), and the *positive* avoidance mechanism, VPC endpoints (**A4**). A1-A6 cover the paths not already owned by 1.1.

---

## Stage 4: Specify

**1.4-A1: NAT-gateway default route (Variant A)**
```
GIVEN   an aws_route resource
WHEN    destination_cidr_block == "0.0.0.0/0" AND nat_gateway_id is present/non-empty
THEN    DENY "CSCF 1.4 [1.4-A1]: secure-zone route sends all IPv4 traffic to a NAT
        gateway (uncontrolled outbound Internet). (§ a). (resource: %s)"
```

**1.4-A2: Egress-only IGW route (Variant A)**
```
GIVEN   an aws_route resource
WHEN    destination_ipv6_cidr_block == "::/0" AND egress_only_gateway_id is present
THEN    DENY "CSCF 1.4 [1.4-A2]: secure-zone route sends all IPv6 traffic to an
        egress-only Internet gateway. (§ a). (resource: %s)"
```

**1.4-A3: Browsing-port egress to Internet (Variant A, two deny rules v4/v6)**
```
GIVEN   an aws_security_group resource
WHEN    an egress rule covers port 80 or 443
        AND cidr_blocks contains 0.0.0.0/0  (rule 1)  OR ipv6_cidr_blocks contains ::/0 (rule 2)
THEN    DENY "CSCF 1.4 [1.4-A3]: security group allows direct outbound HTTP/HTTPS to the
        Internet; browsing/egress from the secure zone must be via a controlled proxy
        (§ a). (resource: %s)"
```

**1.4-A4: VPC-endpoint presence (Variant B, PRESENCE; coverage = Partial)**
```
GIVEN   the planned resources
WHEN    no aws_vpc_endpoint resource exists
THEN    DENY "CSCF 1.4 [1.4-A4]: no VPC endpoint is configured; AWS-service traffic
        should use VPC endpoints rather than egressing to the Internet (§ a, § b)."
```

**1.4-A5: Instance public-IP assignment (Variant A, TAG)**
```
GIVEN   an aws_instance resource where tags["swift:zone"]=="secure"
        AND tags["swift:role"]=="jump_server"
WHEN    associate_public_ip_address == true
THEN    DENY "CSCF 1.4 [1.4-A5]: jump-server/operator instance auto-assigns a public IP;
        it must have no direct Internet exposure (§ a, § b). (resource: %s)"
```

**1.4-A6: Jump-server SG internet egress (Variant E, RELATION, TAG)**
```
GIVEN   an aws_instance where tags["swift:role"]=="jump_server"
WHEN    one of its vpc_security_group_ids references an aws_security_group
        AND that SG has an egress rule with cidr_blocks containing 0.0.0.0/0
THEN    DENY "CSCF 1.4 [1.4-A6]: jump server's security group permits outbound Internet
        access; the jump server must have none (§ a). (resource: %s, sg: %s)"
```

---

## Stage 4.5: Trace

### Traceability matrix

| Assertion | Src ref(s) | CSCF § | Terraform resource | Scope type | Scope level | Variant | Coverage |
|-----------|-----------|--------|--------------------|------------|-------------|---------|----------|
| 1.4-A1 | S1, S3 | §a | `aws_route` | SINGLE | VPC | A | Full (NAT path) |
| 1.4-A2 | S3 | §a | `aws_route` | SINGLE | VPC | A | Full (IPv6 EIGW path) |
| 1.4-A3 | S2, S3 | §a | `aws_security_group` | SINGLE | VPC | A | Partial (network layer; proxy/URL excluded) |
| 1.4-A4 | S1, S8 | §a, §b | `aws_vpc_endpoint` | PRESENCE | VPC | B | Partial (positive egress-avoidance signal) |
| 1.4-A5 | S6, S7 | §a, §b | `aws_instance` | SINGLE | TAG | A | Full (instance public-IP) |
| 1.4-A6 | S6 | §a | `aws_instance`->`aws_security_group` | RELATION | TAG | E | Partial (plan-time SG-id join; see limitation) |

### Completeness check

Walking every verifiable/obligation item in § 1.4 (S1-S12):

- **Covered by ≥ 1 assertion** (full or partial): S1, S2, S3, S6, S7 -> **5**
- **Documented exclusions**: S4 (PROC), S5 (PLATLIM/RUNTIME), S8 (PLATLIM/PROC), S9 (XREF 4.2), S10 (ADV), S11 (ADV), S12 (ADV) -> **7**
- **Total extractable items**: 12

```
covered (5) + excluded (7) == total (12)   ->   PASS
```

Plus four **XREF exclusions to Control 1.1** (IGW route, public-IP subnet, all-protocol SG egress, all-protocol NACL egress) which serve 1.4's objective but are owned by 1.1's assertion set, recorded so 1.4 adds no duplicate rules.

### Coverage summary

1.4's automatable surface is the **outbound Internet-egress path** of the secure
zone. Six assertions cover the NAT / egress-only-IGW / browsing-port / public-IP /
jump-server paths and the VPC-endpoint avoidance signal. The genuinely
un-automatable core of 1.4, **proxy URL-allowlisting with content inspection**
(S5, S8), is honestly excluded (PLATLIM/VENDOR): it is not expressible in a
Terraform plan, and is the single most important limitation to state for this
control.

---

## Stage 5: Encode

Encoded as `policies/swift_cscf/v2026/ctrl_1_4.rego`
(package `swift_cscf.v2026.ctrl_1_4`), importing the shared helpers
(`data.swift_cscf.v2026.helpers`), **no duplication of Phase I policy code**, per
the phase-discipline rule. Six assertions -> seven `deny` rules (A3 has an IPv4 and
an IPv6 rule). The file passes `opa check` against the helpers package.

**Encoding notes / limitations**
- **A6 plan-time join.** Joining `aws_instance.vpc_security_group_ids` to
  `aws_security_group.id` relies on IDs being present in the plan. In real
  `terraform plan -json` output (real plans) these are often *known after apply*
  (null), so A6 may not fire on a fresh plan, a documented plan-time limitation,
  shared with 1.1-A6's IGW-id join.
- **VPC scoping of routes/SGs.** Like 1.1's network rules, A1-A3 evaluate all
  routes/SGs in the plan under test rather than filtering by an explicit VPC tag
  (routes and rules seldom carry one); this is the "broadest justified scope"
  default (Framework Stage 2.5 rule 4).
- **A4 is a presence signal**, not proof of full egress avoidance, marked
  Partial. It should be treated as advisory-strength within a mandatory control.

**Validation (done).** Paired fixtures live in `fixtures/`
(`ctrl_1_4_compliant.json`, `ctrl_1_4_non_compliant.json`). The gate now accepts
a `--controls` override, so 1.4 is evaluated on its own
against the shared helpers:

```
python pipeline/gate.py \
  --plan fixtures/ctrl_1_4_non_compliant.json \
  --policies policies \
  --controls ctrl_1_4
```

Result: compliant -> **0 violations (PASS, exit 0)**; non-compliant -> **7 instances
/ 6 distinct assertions (FAIL, exit 1)**, every assertion A1-A6 firing. Two CI
steps in `.github/workflows/cscf-gate.yml` enforce this on every push/PR (the
Phase I baseline job is unchanged). Committed evidence + attestation samples:
`evidence/samples/ctrl_1_4_*`.

**Still open (real plans):** the A6 plan-time SG-id join and VPC scoping of
routes/SGs remain limitations under real `terraform plan -json`; the fixtures use
resolved ids the way the Phase I mock plans do.

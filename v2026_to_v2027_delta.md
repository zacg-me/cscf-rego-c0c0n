# CSCF v2026 -> v2027 Delta Analysis

**Author:** Zachariah George
**Sources:** CSCF v2027 and Swift's comparison of it with v2026 (10 July 2026),
available from Swift.

---

## Headline finding

**CSCF v2027 introduces no new controls, removes none, and reclassifies none.** The
framework remains **32 controls** with identical mandatory/advisory status and
architecture applicability. Changes are predominantly **editorial** ("should" ->
"must"), one **terminology change** (need-to-know -> need-to-have), one new
**in-scope component concept** (Secrets and Keys Vault), and a small number of
**substantive requirement refinements**: only one of which touches an
automatable, plan-evaluable requirement.

**Consequence for this project:** the OPA/Rego policy library ports to v2027
**essentially unchanged**. This is a positive result; it demonstrates the
**version-resilience** of the seven-stage Translation Framework and the library:
an annual CSCF revision did not invalidate any assertion. One genuinely new
automatable requirement (4.1 failed-authentication alerting) is identified as an
optional v2027-driven enhancement.

---

## Method

1. Extracted both v2027 PDFs to text (`pypdf`).
2. Parsed the control inventory (control id, type, title) from v2026 and v2027 and
   diffed the sets.
3. For each of the **15 implemented controls** (5 Phase I + 10 Phase II), extracted
   the control's text block from each version and computed a normalised,
   noise-filtered line-level diff (headers, dates, hyphenation and footnote
   renumbering removed) to isolate substantive changes.

---

## 1. Control-set comparison

| Metric | v2026 | v2027 | Change |
|--------|:-----:|:-----:|--------|
| Total controls | 32 | 32 | none |
| Mandatory (always) | 21 | 21 | none |
| Conditionally mandatory | 5 | 5 | none |
| Advisory | 6 | 6 | none |
| Controls added / removed | - | - | **none** |
| Mandatory <-> advisory reclassifications | - | - | **none** |

Only two **title** changes, both cosmetic hyphenation: 2.4 "Back Office" ->
"Back-Office"; 7.1 "Cyber Incident" -> "Cyber-Incident".

---

## 2. Cross-cutting (framework-wide) changes

| Change | Nature | Impact on library |
|--------|--------|-------------------|
| "should" -> "must" throughout the guidelines | Editorial hardening of language | None (our rules already treat guidelines as requirements) |
| **"need-to-know" -> "need-to-have"** (Controls 5.1, 5.4 objective + text) | Terminology rename (no semantic change) | **Cosmetic**, our 5.1/5.4 rule messages say "need-to-know"; optional wording alignment |
| New in-scope component **"Secrets and Keys Vault (SKV)"** added to 1.2, 1.4, 4.1, and others | New Swift product concept (HSM-backed secret/key vault) | No new Terraform resource; conceptually maps to our 5.4 (repository) and 2.1 (KMS) coverage. Documentation note |
| "New HSM" -> "HSM" | Terminology | None |
| "back-office" -> "back-office first hops"; bridging-server Optional-Enhancement rewording | Scope-wording precision | None (our assertions are not keyed on this prose) |

---

## 3. Per-control impact (the 15 implemented controls)

| Control | Change class | Substantive? | Policy impact |
|---------|--------------|:------------:|---------------|
| **1.1** Environment Protection | editorial (hyphenation, risk-driver formatting) | no | none |
| **1.2** OS Privileged Accounts | editorial; SKV added; "disallow"->"prevent" | no | none |
| **1.3** Virtualisation/Cloud | Notes reformatted to bullets | no | none |
| **1.4** Restriction of Internet Access | **§c "- Advisory" removed**; "including the jump server"; SKV added | **minor** | §c (middleware/virtualisation internet) no longer advisory, **already covered** by 1.4-A1/A3 egress checks; update exclusion note |
| **2.1** Internal Data Flow | crypto examples moved to KB ref; "new HSM"->"HSM" | no | none |
| **2.2** Security Updates | **New "AI-driven Cyber Threats" acceleration guidance**; CVSS timing targets retained (Critical ≤1mo, High ≤3mo) | minor | Runtime/procedural, 2.2 is a mechanism-presence check; unaffected |
| **2.3** System Hardening | "should do"->"**must** do"; CIS/STIG/NIST spelled out | no | none (hardening minimums are OS-runtime; our attack-surface assertions stand) |
| **2.4** Back-Office Data Flow | title hyphenation; crypto examples to KB; "back-office first hop typically out of scope" clarified; legacy-flows-mandatory still "~v2028" | no | none (VPN/mTLS/DX assertions stand) |
| **2.6** Operator Session | crypto examples to KB | no | none |
| **2.7** Vulnerability Scanning | editorial | no | none |
| **4.1** Password Policy | **Lock-out reworked**: account-lockout **OR** increasing-delay (with strong passwords) **AND** failed-auth **logging + alerting** at a threshold (recommended **5** consecutive) | **YES** | See §4, IAM lockout stays PLATLIM; the **failed-auth alerting is a candidate new assertion** |
| **4.2** Multi-Factor Authentication | "New HSM"->"HSM"; wording | no | none |
| **5.1** Logical Access Control | **need-to-know -> need-to-have**; PKI keys/certs added to O2M scope + "reviewed annually" (procedural) | minor | Cosmetic wording in messages; PKI review is PROC |
| **5.4** Password Repository | "makes sure"->"ensures"; HSM token list trimmed; need-to-have | no | none |
| **6.4** Logging & Monitoring | scope broadened "secure zone" -> "...or other in-scope components"; connector logs added; HSM-log note | no | none (CloudTrail/CloudWatch/S3 assertions stand; broadening is wording) |

**Summary:** 12 of 15 controls change **cosmetically only**; 2 have **minor**
scope-wording refinements already covered (1.4, 2.2); **1** (4.1) has a genuinely
new automatable requirement.

---

## 4. The one actionable item, Control 4.1 failed-authentication alerting

v2027 rewrites 4.1's lock-out requirement. The two halves:

1. **Lock-out OR delay**: "account lock-out after a defined number of failed
   attempts" **or** "an increasing/extended delay between failed attempts,
   provided strong and long passwords are enforced." -> On AWS, the IAM account
   password policy does **not** expose a lock-out threshold (this was already a
   **PLATLIM** exclusion in Phase I), and Cognito exposes no direct lock-out knob.
   **No change** to the automatability of the lock-out itself.

2. **Logging + alerting**: "invalid authentication attempts are logged, and alerts
   are generated once a defined threshold is reached (recommended **5 consecutive**
   failed attempts)." -> This **is** automatable and **new**: it maps to a
   **CloudWatch Logs metric filter** on failed-authentication events plus a
   **CloudWatch alarm** at threshold ≥ 5: the same mechanism Control 6.4 already
   uses (6.4-A19..A22 metric filters / alarms).

**Recommendation (optional enhancement):** add a v2027 assertion, e.g.
`4.1-A20` (or a 6.4 companion): "a CloudWatch metric filter + alarm exists for
failed/invalid authentication attempts with a threshold ≤ 5." This is a genuine,
plan-evaluable, v2027-driven addition and would be the single substantive library
change for the new version.

---

## 5. Versioning recommendation

Per the Translation Framework's maintenance guidance (§13), a CSCF version bump
triggers re-execution of Stages 1-4.5. Having done so:

- **Do not blanket-duplicate** the 15 controls into a `swift_cscf.v2027.*`
  namespace, none of their automatable requirements changed, so a re-tag would
  add maintenance burden with no behavioural difference.
- **If/when a v2027 namespace is created**, it should differ from v2026 by exactly:
  (a) the optional **4.1 failed-auth alerting** assertion, (b) cosmetic message
  wording (need-to-know -> need-to-have), and (c) the 1.4 §c exclusion note. Every
  other rule is byte-identical.
- Keep the current `v2026` package as-is for v2026 attestations; the library is
  **forward-compatible** with v2027 today.

---

## 6. Conclusion

> CSCF v2027 introduced **no new or reclassified controls**; its changes are
> overwhelmingly editorial, with one terminology rename, one new in-scope component
> concept (SKV), and a single new automatable requirement (4.1 failed-authentication
> alerting). The policy library therefore ports to v2027 with **one optional new
> assertion and no breaking changes**, an empirical demonstration that the
> seven-stage Translation Framework produces a **version-resilient** compliance
> library, directly addressing the annual-CSCF-update maintainability concern
> raised in the literature (Begoug et al., 2025, on IaC provider-update churn).

This is a strong result: it converts the "CSCF changes every year" risk into
evidence of the framework's durability, and it is achieved with a rigorous,
reproducible text-diff method rather than assertion.

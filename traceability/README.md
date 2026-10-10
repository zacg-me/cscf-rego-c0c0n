# Traceability matrix: all 15 controls

Phase I committed to *"a bidirectional traceability matrix: every CSCF
sub-requirement linked to its assertion, deny rule, and (where applicable)
exclusion rationale."* The Phase I spreadsheet delivered that for its five
controls. The ten Phase II controls recorded their traceability in separate
translation documents. This directory joins them into one matrix.

| File | What it is |
|---|---|
| `CSCF_Traceability_Matrix.xlsx` | The matrix, for reading, five sheets, described below |
| `traceability.json` | The same data, machine-readable; the conformance suite checks it |
| `traceability.csv` | The assertions sheet, for review in a diff |
| `build_matrix.py` | The generator |
| `phase1_register.json` | Snapshot of the Phase I spreadsheet, so the matrix rebuilds without Excel tooling |

```bash
python traceability/build_matrix.py --xlsx
```

## It is generated, not maintained

Every row is derived from an authoritative source, and nothing is typed in by
hand:

| Column | Source |
|---|---|
| Rules, and the assertion each reports | the Rego library, the `[X.Y-An]` id in each rule's message |
| Requirements, statements, exclusions (Phase II) | `translations/ctrl_*_translation.md` |
| Assertions and exclusions (Phase I) | the frozen Phase I spreadsheet |
| Scope implemented | the same test `pipeline/audit/scope_audit.py` applies |
| Verdict on the generated plan | `plans/non_compliant_resolved_evidence.json` |

The conformance suite rebuilds the matrix and compares it with the committed
`traceability.json`. A rule, assertion or verdict that changes without the
matrix being regenerated fails the build, so the matrix cannot drift from the
code the way the Phase I matrix's Scope column did.

## The sheets

**Summary**, per control: assertions, rules, exclusions, and the verdict
breakdown on the generated non-compliant plan. Built from policy library 2.0.0.

**Assertions (forward)**, requirement -> assertion -> rules -> verdict. For each
of the 129 assertions: its source requirements, CSCF section, Terraform
resource, declared scope and whether it is implemented, the rules that realise
it, the verdict, and any defect, including what the 2.0.0 re-issue corrected
and whether it was a scope that 1.0.0 declared and did not apply.

**Rules (backward)**, rule -> assertion. All 144 deny rules with file, line,
package, the phase that introduced the control, declared scope and whether that
scope is applied.

**Requirements**: sub-requirement -> assertions and exclusions, with a
disposition for each.

**Exclusions**: the 114 requirements not decidable from a deployment plan,
with category, rationale and any partial coverage.

## What it shows

| | |
|---|---:|
| Controls | 15 |
| Assertions | 129 |
| Rules | 144 (policy library 2.0.0) |
| Sub-requirements traced | 118, 59 covered, 45 excluded, 14 both; **0 untraced** |
| Exclusions | 114 (36 Phase I, 78 Phase II) |
| On the generated non-compliant plan | 121 fire, 4 undetermined, 4 explained, **0 silent** |
| Declared scope not implemented | **0** (35 assertions / 39 rules in 1.0.0, fixed in 2.0.0) |

The four "explained" assertions: two are mutually exclusive with assertions that
fire (4.1-A1, 4.1-A18), one is subsumed by a stronger neighbour and has no rule
of its own (6.4-A9), and one belongs to the CSCF v2027 delta (4.1-A20).

## Limitations

**Phase I kept no separate requirement register.** Its sub-requirements survive
only as source references on its assertions, and its exclusions cite CSCF
sections rather than requirement ids. So the Requirements sheet can show every
Phase I requirement that an assertion covers, but it cannot show a Phase I
requirement that was *only* excluded, those are in the Exclusions sheet,
keyed by section. For the ten Phase II controls, where each requirement was
recorded with its text, traceability is complete in both directions.

**The matrix records the library as it behaves,** not as it was meant to. It
is generated from the code, so when 1.0.0 declared scopes its rules did not
apply, the matrix showed 35 assertions as "not implemented"; that is how the
defect was visible, and it is why the re-issue (`../policies/CHANGELOG.md`) was
needed. A matrix that showed only the intended picture would repeat the Phase I
mistake of documenting intent rather than behaviour.

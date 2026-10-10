#!/usr/bin/env bash
# Real Terraform plans: terraform plan -> resolvability pass -> CSCF compliance gate.
#
#   plan_and_gate.sh [compliant|non_compliant]   (default: both)
#
# Needs terraform and opa on PATH. No AWS account: the fixtures configure the
# provider with mock credentials and skip every credential/metadata lookup.
#
# The gate is given the resolvability report, so assertions that depend on a
# value unknown at plan time are reported as UNDETERMINED rather than counted
# as passes. They do not block here; pass --fail-on-undetermined to gate.py for
# the conservative posture.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
p2="$(dirname "$here")"

# All fifteen implemented mandatory controls, not just the Phase I five: both
# environments are references for the whole library (review findings R3, R4).
CONTROLS="ctrl_1_1,ctrl_1_2,ctrl_1_3,ctrl_1_4,ctrl_2_1,ctrl_2_2,ctrl_2_3,ctrl_2_4"
CONTROLS="$CONTROLS,ctrl_2_6,ctrl_2_7,ctrl_4_1,ctrl_4_2,ctrl_5_1,ctrl_5_4,ctrl_6_4"

fixtures=("${1:-compliant}" "${2:-}")
[[ $# -eq 0 ]] && fixtures=(compliant non_compliant)

status=0
for fixture in "${fixtures[@]}"; do
    [[ -z "$fixture" ]] && continue
    echo "=== $fixture ==============================================="
    dir="$p2/terraform/$fixture"

    terraform -chdir="$dir" init -input=false -no-color >/dev/null
    terraform -chdir="$dir" plan -input=false -no-color -out=tfplan.binary >/dev/null
    terraform -chdir="$dir" show -json tfplan.binary > "$p2/plans/${fixture}_live_plan.json"

    python "$here/resolve_plan.py" \
        --plan "$p2/plans/${fixture}_live_plan.json" \
        --out "$p2/plans/${fixture}_resolved_plan.json" \
        --report "$p2/plans/${fixture}_resolvability.json"

    # The compliant fixture must pass the gate; the non-compliant one must be
    # blocked, so its expected exit status is the inverse.
    if python "$here/gate.py" \
        --plan "$p2/plans/${fixture}_resolved_plan.json" \
        --policies "$p2/policies" \
        --controls "$CONTROLS" \
        --resolvability "$p2/plans/${fixture}_resolvability.json" \
        --plan-scope full \
        --evidence "$p2/plans/${fixture}_resolved_evidence.json"; then
        gate_passed=1
    else
        gate_passed=0
    fi

    python "$p2/evidence/report.py" \
        --evidence "$p2/plans/${fixture}_resolved_evidence.json" \
        --out "$p2/plans/${fixture}_resolved_report.html"

    if [[ "$fixture" == "compliant" && $gate_passed -eq 0 ]]; then
        echo "ERROR: the compliant plan was blocked by the gate" >&2
        status=1
    elif [[ "$fixture" != "compliant" && $gate_passed -eq 1 ]]; then
        echo "ERROR: the non-compliant plan was NOT blocked -- detection broken" >&2
        status=1
    fi
done

exit $status

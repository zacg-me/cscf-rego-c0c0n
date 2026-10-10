# SWIFT CSCF v2026, Control 2.7: Vulnerability Scanning
# Framework v1.2.1: Phase II (new control; see translations/ctrl_2_7_translation.md)
# Assertions: 2.7-A1 (1 deny rule)
# Control Objective: Identify known vulnerabilities via a regular scanning process
#   and act upon the results.
#
# The scanning process (cadence, tooling, remediation) is PROC/RUNTIME; the only
# plan-evaluable sliver is that the AWS Amazon Inspector continuous-scanning
# mechanism is enabled for compute (EC2). Presence check with Partial coverage.
# Uses the shared helpers.

package swift_cscf.v2026.ctrl_2_7

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 2.7-A1: Amazon Inspector is enabled for EC2 vulnerability scanning
# Source: CSCF v2026, § Control Statement (systems scanned for vulnerabilities)
# Scope: ACCT | Variant: B (presence + coverage)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_inspector2_enabler"
		"EC2" in r.values.resource_types
	]) == 0

	msg := "CSCF 2.7 [2.7-A1]: Amazon Inspector is not enabled for EC2 vulnerability scanning; a continuous scanning mechanism must be in place (§ Control Statement)."
}

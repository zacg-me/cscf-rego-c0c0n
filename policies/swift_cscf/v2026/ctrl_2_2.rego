# SWIFT CSCF v2026, Control 2.2: Security Updates
# Framework v1.2.1: Phase II (new control; see translations/ctrl_2_2_translation.md)
# Assertions: 2.2-A1, 2.2-A2 (2 deny rules)
# Control Objective: Minimise known technical vulnerabilities by keeping systems
#   within vendor support and applying mandatory / timely security updates.
#
# Whether hosts are actually patched is OS-host RUNTIME; the only plan-evaluable
# sliver is the presence of the AWS SSM Patch Manager mechanism (baseline +
# scheduled association). Presence checks with Partial coverage. Uses the shared
# helpers.

package swift_cscf.v2026.ctrl_2_2

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 2.2-A1: An SSM Patch Manager baseline is configured
# Source: CSCF v2026, § mandatory software updates
# Scope: ACCT | Variant: B (presence)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_ssm_patch_baseline"
	]) == 0

	msg := "CSCF 2.2 [2.2-A1]: No SSM Patch Manager baseline is configured; a security-update mechanism must be in place (§ mandatory software updates)."
}

# ============================================================================
# 2.2-A2: A patch-automation association is scheduled
# Source: CSCF v2026, § security updates promptly applied
# Scope: ACCT | Variant: B (presence)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_ssm_association"
	]) == 0

	msg := "CSCF 2.2 [2.2-A2]: No SSM patch-automation association is scheduled; security updates must be applied on a defined schedule (§ security updates)."
}

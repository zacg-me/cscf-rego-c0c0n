# SWIFT CSCF v2026, Control 2.6: Operator Session Confidentiality and Integrity
# Framework v1.2.1: Phase II (new control; see translations/ctrl_2_6_translation.md)
# Assertions: 2.6-A1 through 2.6-A3 (3 deny rules)
# Control Objective: Protect the confidentiality and integrity of interactive
#   operator sessions that connect to the Swift infrastructure.
#
# Transport TLS / crypto for sessions is Control 2.1 (XREF-excluded); SSH is
# removed by 1.2's SSM-managed model. The rules below cover the net-new session
# lifetime + session-data protection: Client VPN session timeout, SSM Session
# Manager idle-timeout and KMS encryption. Uses the shared helpers.

package swift_cscf.v2026.ctrl_2_6

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 2.6-A1: Client VPN endpoints enforce a bounded session timeout (<= 8h)
# Source: CSCF v2026, § inactivity lock-out (minimal necessary time frame)
# Scope: TAG | Variant: A  (unset defaults to 24h = violation)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ec2_client_vpn_endpoint"
	helpers.is_swift_tagged(resource)

	object.get(resource.values, "session_timeout_hours", 24) > 8

	msg := sprintf(
		"CSCF 2.6 [2.6-A1]: Client VPN session timeout exceeds the minimum (8h); operator sessions must be limited to the minimal necessary time frame (§ inactivity lock-out). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.6-A2: SSM Session Manager enforces an idle-session timeout (<= 20 minutes)
# Source: CSCF v2026, § inactivity lock-out (OS/jump-server level)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ssm_document"
	resource.values.document_type == "Session"

	content := json.unmarshal(resource.values.content)
	not _idle_timeout_bounded(content)

	msg := sprintf(
		"CSCF 2.6 [2.6-A2]: SSM Session Manager does not enforce an idle-session timeout of 20 minutes or less (§ inactivity lock-out). (resource: %s)",
		[resource.address],
	)
}

_idle_timeout_bounded(content) if {
	raw := object.get(content.inputs, "idleSessionTimeout", "")
	raw != ""
	to_number(raw) <= 20
}

# ============================================================================
# 2.6-A3: SSM Session Manager encrypts session data with a KMS key
# Source: CSCF v2026, § Control Statement (confidentiality of operator sessions)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ssm_document"
	resource.values.document_type == "Session"

	content := json.unmarshal(resource.values.content)
	object.get(content.inputs, "kmsKeyId", "") == ""

	msg := sprintf(
		"CSCF 2.6 [2.6-A3]: SSM Session Manager does not encrypt session data with a KMS key; operator-session confidentiality is not protected (§ Control Statement). (resource: %s)",
		[resource.address],
	)
}

# SWIFT CSCF v2026, Control 1.2: Operating System Privileged Account Control
# Framework v1.2.1: Phase II (new control; see translations/ctrl_1_2_translation.md)
# Assertions: 1.2-A1 through 1.2-A3 (3 deny rules)
# Control Objective: Restrict and control the allocation and usage of
#   administrator-level operating system accounts.
#
# Mostly an OS-runtime control. Broad IAM admin -> 5.1, admin ports -> 1.1, MFA ->
# 4.2/1.1, log capture -> 6.4 (all XREF-excluded); AWS root user is not
# TF-manageable (ROOT). The rules below cover the net-new cloud admin-access path:
# SSM Session Manager (managed/auditable) instead of static SSH keys, and session
# logging. Uses the shared helpers.

package swift_cscf.v2026.ctrl_1_2

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 1.2-A1: Swift VMs use no static SSH key pair (admin access via SSM Session Mgr)
# Source: CSCF v2026, § Control Statement (restrict/control admin account usage)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)

	object.get(resource.values, "key_name", "") != ""

	msg := sprintf(
		"CSCF 1.2 [1.2-A1]: VM uses a static SSH key pair (key_name set); privileged access should go through SSM Session Manager, not a persistent shared credential (§ Control Statement). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.2-A2: Swift VMs have an IAM instance profile (prerequisite for SSM management)
# Source: CSCF v2026, § Control Statement (usage controlled and monitored)
# Scope: TAG | Variant: A | Coverage: Partial (necessary, not sufficient)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)

	object.get(resource.values, "iam_instance_profile", "") == ""

	msg := sprintf(
		"CSCF 1.2 [1.2-A2]: VM has no IAM instance profile; SSM-managed, auditable admin access is not available (§ Control Statement). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.2-A3: SSM Session Manager logging is configured (sessions are monitored)
# Source: CSCF v2026, § guidelines (individual admin access logged; cross-ref 6.4)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ssm_document"
	resource.values.document_type == "Session"

	content := json.unmarshal(resource.values.content)
	not _session_logging_enabled(content)

	msg := sprintf(
		"CSCF 1.2 [1.2-A3]: SSM Session Manager preferences do not enable session logging (no CloudWatch log group or S3 bucket); privileged sessions are not monitored (§ guidelines, cross-ref 6.4). (resource: %s)",
		[resource.address],
	)
}

_session_logging_enabled(content) if {
	object.get(content.inputs, "cloudWatchLogGroupName", "") != ""
}

_session_logging_enabled(content) if {
	object.get(content.inputs, "s3BucketName", "") != ""
}

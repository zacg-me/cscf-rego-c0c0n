# SWIFT CSCF v2026, Control 6.4: Logging and Monitoring
# Policy library 2.0.0 (re-issue of the Phase I control; see ../../CHANGELOG.md)
# Assertions: 6.4-A1 through 6.4-A24
# Control Objective: Record security events, detect and respond to anomalous
#   actions and operations within the user's Swift environment.

package swift_cscf.v2026.ctrl_6_4

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.zone_scope

# ============================================================================
# LOGGING INFRASTRUCTURE
# ============================================================================

# ============================================================================
# 6.4-A1: Multi-Region CloudTrail Existence
# Source: CSCF v2026, § Overall goals, § Logging (S1, S4)
# Scope: ACCT | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_cloudtrail"
		r.values.is_multi_region_trail == true
	]) == 0

	msg := "CSCF 6.4 [6.4-A1]: No multi-region CloudTrail configured. CSCF requires logging of security events across the entire Swift environment (§ Overall goals, § Logging)."
}

# ============================================================================
# 6.4-A2: CloudTrail Logging Enabled
# Source: CSCF v2026, § Overall goals, § Logging (S1, S4)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudtrail"
	not resource.values.enable_logging == true

	msg := sprintf(
		"CSCF 6.4 [6.4-A2]: CloudTrail logging disabled (§ Logging). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 6.4-A3: Global Service Events Captured
# Source: CSCF v2026, § Logging (S5, S6)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudtrail"
	not resource.values.include_global_service_events == true

	msg := sprintf(
		"CSCF 6.4 [6.4-A3]: CloudTrail does not capture global events (IAM, STS). Required for account usage traceability (§ Logging). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 6.4-A4: Management Events Read/Write Coverage
# Source: CSCF v2026, § Logging (S4, S6)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudtrail"

	selector := resource.values.event_selector[_]
	selector.read_write_type != "All"

	msg := sprintf(
		"CSCF 6.4 [6.4-A4]: CloudTrail event selector read_write_type is '%s', must be 'All' (§ Logging). (resource: %s)",
		[selector.read_write_type, resource.address],
	)
}

# ============================================================================
# 6.4-A5: VPC Flow Logs (shared with 1.1-A9)
# Source: CSCF v2026, § Logging, § Monitoring (S6, S9)
# Scope: VPC | Variant: B (presence check)
# A flow log counts only if it records the Swift zone.
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_flow_log"
		r.values.traffic_type == "ALL"
		zone_scope.in_swift_zone(r)
	]) == 0

	msg := "CSCF 6.4 [6.4-A5]: No VPC Flow Log capturing ALL traffic. CSCF requires firewall and network-level logging (§ Logging, cross-ref: 1.1)."
}

# ============================================================================
# 6.4-A6: RDS Database Audit Logging
# Source: CSCF v2026, § Logging, minimum logs (S6)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_instance"
	helpers.is_swift_tagged(resource)

	exports := object.get(resource.values, "enabled_cloudwatch_logs_exports", [])
	count(exports) == 0

	msg := sprintf(
		"CSCF 6.4 [6.4-A6]: RDS instance does not export any logs to CloudWatch. CSCF requires database logs (§ Logging). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# LOG FORWARDING AND CENTRALISATION
# ============================================================================

# ============================================================================
# 6.4-A7: CloudTrail to CloudWatch Forwarding
# Source: CSCF v2026, § Overall goals, § Monitoring (S1, S2, S8)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudtrail"

	cw_arn := object.get(resource.values, "cloud_watch_logs_group_arn", "")
	cw_arn == ""

	msg := sprintf(
		"CSCF 6.4 [6.4-A7]: CloudTrail not forwarding to CloudWatch. Required for active monitoring and alerting (§ Overall goals, § Monitoring). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# LOG RETENTION
# ============================================================================

# ============================================================================
# 6.4-A8: CloudTrail Log Group Retention (12 months)
# Source: CSCF v2026, § Log retention (S11, S13)
# Scope: XREF | Variant: A
# Note: retention_in_days == 0 means "never expire" which is compliant
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudwatch_log_group"

	retention := object.get(resource.values, "retention_in_days", 0)
	retention != 0
	retention < 365

	msg := sprintf(
		"CSCF 6.4 [6.4-A8]: CloudWatch log group retention is %d days, need >= 365 for audit logs (§ Log retention). (resource: %s)",
		[retention, resource.address],
	)
}

# ============================================================================
# 6.4-A9: VPC Flow Log Group Retention (31+ days, recommend 93)
# Source: CSCF v2026, § Log retention (S12)
# Scope: XREF | Variant: A
# Note: This rule evaluates all log groups. In practice, VPC Flow Log groups
#   should be identified by cross-referencing aws_flow_log.log_group_name.
#   For simplicity, the retention check in A8 covers all groups at 365 days.
#   This rule is intentionally less restrictive as a separate threshold.
# ============================================================================

# Covered by A8's broader check. This assertion exists in the register for
# traceability to the CSCF's differentiated retention requirement (31 days
# for firewall logs vs. 12 months for application logs). In practice, enforcing
# 365 days universally (A8) satisfies both requirements.

# ============================================================================
# LOG PROTECTION: TAMPER EVIDENCE
# ============================================================================

# ============================================================================
# 6.4-A10: CloudTrail Log File Validation
# Source: CSCF v2026, § Log retention, § Overall goals (S3, S11)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudtrail"
	not resource.values.enable_log_file_validation == true

	msg := sprintf(
		"CSCF 6.4 [6.4-A10]: CloudTrail log file validation disabled. Required for tamper-evident forensics (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# LOG PROTECTION: ENCRYPTION
# ============================================================================

# ============================================================================
# 6.4-A11: CloudTrail KMS Encryption
# Source: CSCF v2026, § Log retention (S11)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudtrail"

	kms_key := object.get(resource.values, "kms_key_id", "")
	kms_key == ""

	msg := sprintf(
		"CSCF 6.4 [6.4-A11]: CloudTrail logs not encrypted with KMS. Required to protect from enterprise admin compromise (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 6.4-A12: CloudWatch Log Group KMS Encryption
# Source: CSCF v2026, § Log retention (S11)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudwatch_log_group"

	kms_key := object.get(resource.values, "kms_key_id", "")
	kms_key == ""

	msg := sprintf(
		"CSCF 6.4 [6.4-A12]: CloudWatch log group not KMS-encrypted. Audit logs must be protected from credential compromise (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# LOG PROTECTION: S3 BUCKET INTEGRITY
# ============================================================================

# ============================================================================
# 6.4-A13: S3 Log Bucket Public Access Block
# Source: CSCF v2026, § Log retention (S11)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_public_access_block"

	_missing_public_access_block(resource.values)

	msg := sprintf(
		"CSCF 6.4 [6.4-A13]: S3 bucket does not block all public access. Audit logs must not be publicly accessible (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

_missing_public_access_block(v) if { not v.block_public_acls == true }
_missing_public_access_block(v) if { not v.block_public_policy == true }
_missing_public_access_block(v) if { not v.restrict_public_buckets == true }
_missing_public_access_block(v) if { not v.ignore_public_acls == true }

# ============================================================================
# 6.4-A14: S3 Log Bucket Versioning
# Source: CSCF v2026, § Log retention (S3, S14)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_versioning"

	vc := helpers.block(resource.values, "versioning_configuration")
	status := object.get(vc, "status", "Disabled")
	status != "Enabled"

	msg := sprintf(
		"CSCF 6.4 [6.4-A14]: S3 bucket versioning not enabled. Required for log recovery and forensic integrity (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 6.4-A15: S3 Log Bucket Object Lock
# Source: CSCF v2026, § Log retention (S11, S14)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket"

	# Only check buckets that appear to be log buckets (heuristic: name contains "log" or "trail" or "audit")
	_is_log_bucket_name(resource.values.bucket)
	not resource.values.object_lock_enabled == true

	msg := sprintf(
		"CSCF 6.4 [6.4-A15]: S3 log bucket Object Lock not enabled. Prevents log deletion during retention (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

_is_log_bucket_name(name) if { contains(name, "log") }
_is_log_bucket_name(name) if { contains(name, "trail") }
_is_log_bucket_name(name) if { contains(name, "audit") }

# ============================================================================
# 6.4-A16: S3 Log Bucket Lifecycle, No Premature Deletion
# Source: CSCF v2026, § Log retention (S11, S13, S14)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_lifecycle_configuration"

	rule := resource.values.rule[_]
	expiration := helpers.block(rule, "expiration")
	days := object.get(expiration, "days", 0)
	days > 0
	days < 365

	msg := sprintf(
		"CSCF 6.4 [6.4-A16]: S3 lifecycle expires objects in %d days, need >= 365 (§ Log retention). (resource: %s)",
		[days, resource.address],
	)
}

# ============================================================================
# 6.4-A17: S3 Log Bucket Deletion Deny Policy
# Source: CSCF v2026, § Log retention (S11)
# Scope: XREF | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_policy"

	# Only check log-related buckets (XREF scope)
	bucket_name := object.get(resource.values, "bucket", "")
	_is_log_bucket_name(bucket_name)

	policy := json.unmarshal(resource.values.policy)
	not _has_delete_deny(policy)

	msg := sprintf(
		"CSCF 6.4 [6.4-A17]: S3 bucket policy does not deny object deletion. Audit logs must be protected from destruction (§ Log retention). (resource: %s)",
		[resource.address],
	)
}

_has_delete_deny(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Deny"
	actions := helpers.actions_from_statement(stmt)
	helpers.action_contains(actions, "s3:DeleteObject")
}

# ============================================================================
# 6.4-A18: S3 Log Bucket Server-Side Encryption
# Source: CSCF v2026, § Log retention (S11)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"

	rule := helpers.block(resource.values, "rule")
	sse := helpers.block(rule, "apply_server_side_encryption_by_default")
	algo := object.get(sse, "sse_algorithm", "")
	not algo in {"aws:kms", "aws:kms:dsse"}

	msg := sprintf(
		"CSCF 6.4 [6.4-A18]: S3 bucket not using KMS encryption (algorithm: '%s'). Audit logs must be encrypted at rest (§ Log retention). (resource: %s)",
		[algo, resource.address],
	)
}

# ============================================================================
# MONITORING AND ALERTING
# ============================================================================

# ============================================================================
# 6.4-A19: CloudWatch Alarm, Root Account Usage
# Source: CSCF v2026, § Monitoring (S1, S7)
# Scope: XREF | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_cloudwatch_log_metric_filter"
		contains(r.values.pattern, "userIdentity.type")
		contains(r.values.pattern, "Root")
	]) == 0

	msg := "CSCF 6.4 [6.4-A19]: No CloudWatch metric filter for root account usage. CSCF requires monitoring of privileged account activity (§ Monitoring)."
}

# ============================================================================
# 6.4-A20: CloudWatch Alarm, IAM Policy Changes
# Source: CSCF v2026, § Logging, § Monitoring (S1, S6, S7)
# Scope: XREF | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_cloudwatch_log_metric_filter"
		_is_iam_change_filter(r.values.pattern)
	]) == 0

	msg := "CSCF 6.4 [6.4-A20]: No CloudWatch metric filter for IAM policy changes. CSCF requires logging of changes to user groups and access (§ Logging, § Monitoring)."
}

_is_iam_change_filter(pattern) if {
	contains(pattern, "CreatePolicy")
}

_is_iam_change_filter(pattern) if {
	contains(pattern, "AttachRolePolicy")
}

_is_iam_change_filter(pattern) if {
	contains(pattern, "PutGroupPolicy")
}

_is_iam_change_filter(pattern) if {
	contains(pattern, "DeletePolicy")
}

# ============================================================================
# 6.4-A21: CloudWatch Alarm, Console Sign-In Failures
# Source: CSCF v2026, § Logging, § Monitoring (S1, S6, S7)
# Scope: XREF | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_cloudwatch_log_metric_filter"
		contains(r.values.pattern, "ConsoleLogin")
		contains(r.values.pattern, "Failed")
	]) == 0

	msg := "CSCF 6.4 [6.4-A21]: No CloudWatch metric filter for console sign-in failures. CSCF requires logging of failed login attempts (§ Logging)."
}

# ============================================================================
# 6.4-A22: CloudWatch Alarm Action Configured
# Source: CSCF v2026, § Monitoring (S2, S10)
# Scope: XREF | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cloudwatch_metric_alarm"

	actions := object.get(resource.values, "alarm_actions", [])
	count(actions) == 0

	msg := sprintf(
		"CSCF 6.4 [6.4-A22]: Alarm has no actions configured. Suspicious activity must be routed to the security team via SNS (§ Monitoring). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# CONTINUOUS THREAT DETECTION AND COMPLIANCE
# ============================================================================

# ============================================================================
# 6.4-A23: GuardDuty Enabled
# Source: CSCF v2026, § Overall goals, § Monitoring (S4, S8)
# Scope: ACCT | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_guardduty_detector"
		r.values.enable == true
	]) == 0

	msg := "CSCF 6.4 [6.4-A23]: No GuardDuty detector enabled. CSCF requires continuous threat detection (§ Overall goals, § Monitoring)."
}

# ============================================================================
# 6.4-A24: AWS Config Recorder Enabled
# Source: CSCF v2026, § Logging, § Monitoring (S4, S8)
# Scope: ACCT | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_config_configuration_recorder"
	]) == 0

	msg := "CSCF 6.4 [6.4-A24]: No AWS Config configuration recorder. CSCF requires continuous compliance monitoring (§ Logging, § Monitoring)."
}

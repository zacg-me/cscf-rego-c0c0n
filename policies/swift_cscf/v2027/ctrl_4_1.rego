# SWIFT CSCF v2027, Control 4.1: Password Policy (v2027 delta)
# Framework v1.2.1: Phase II (v2027 delta; see ../../../v2026_to_v2027_delta.md)
# Assertion: 4.1-A20 (1 deny rule), NEW in v2027
#
# v2027 rewrote 4.1's lock-out requirement: account lock-out OR increasing delay,
# AND "invalid authentication attempts are logged, and alerts are generated once a
# defined threshold is reached (recommended 5 consecutive failed attempts)."
#
# The IAM lock-out threshold itself remains PLATLIM (not exposed by AWS), those
# v2026 assertions are unchanged and stay in swift_cscf.v2026.ctrl_4_1.
# This file adds ONLY the genuinely-new, plan-evaluable v2027 requirement: a
# CloudWatch metric filter on failed-authentication events plus an alarm at a
# threshold <= 5. Uses the shared v2026 helpers; this is the
# only rule in the v2027 namespace (the rest of the library ports over unchanged).

package swift_cscf.v2027.ctrl_4_1

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 4.1-A20 (v2027): Failed-authentication logging + alerting at a threshold <= 5
# Source: CSCF v2027, § 4.1 lock-out (invalid attempts logged; alerts at threshold)
# Scope: ACCT | Variant: E (cross-resource: metric filter -> alarm)
# ============================================================================

deny contains msg if {
	not _failed_auth_alerting_configured

	msg := "CSCF 4.1 [4.1-A20]: No CloudWatch metric filter and alarm (threshold <= 5) for failed authentication attempts; v2027 requires invalid authentication attempts to be logged and alerted (§ 4.1 lock-out)."
}

_failed_auth_alerting_configured if {
	# A metric filter matching failed-authentication events
	mf := helpers.all_resources[_]
	mf.type == "aws_cloudwatch_log_metric_filter"
	_failed_auth_pattern(mf.values.pattern)

	transform := mf.values.metric_transformation[_]
	metric_name := transform.name

	# ...and an alarm on that metric with a threshold of at most 5
	alarm := helpers.all_resources[_]
	alarm.type == "aws_cloudwatch_metric_alarm"
	alarm.values.metric_name == metric_name
	alarm.values.threshold <= 5
}

_failed_auth_pattern(pattern) if contains(lower(pattern), "fail")

_failed_auth_pattern(pattern) if contains(lower(pattern), "denied")

_failed_auth_pattern(pattern) if contains(lower(pattern), "invalid")

_failed_auth_pattern(pattern) if contains(lower(pattern), "unauthorized")

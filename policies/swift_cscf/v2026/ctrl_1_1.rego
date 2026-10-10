# SWIFT CSCF v2026, Control 1.1: Swift Environment Protection
# Policy library 2.0.0 (re-issue of the Phase I control; see ../../CHANGELOG.md)
# Assertions: 1.1-A1 through 1.1-A14
# Control Objective: Ensure the protection of the user's Swift infrastructure
#   from potentially compromised elements of the general IT environment.
#
# Every rule applies the scope its header declares. VPC scope is
# `zone_scope.in_swift_zone` (the Swift VPC binding, or the zone tag when the
# plan carries no binding); a sub-resource that has neither -- a route, a
# standalone security-group or ACL rule, a VPN authorisation rule -- takes the
# scope of its parent.

package swift_cscf.v2026.ctrl_1_1

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.parent_scope
import data.swift_cscf.v2026.zone_scope

ADMIN_PORTS := {22, 3389}

# ============================================================================
# 1.1-A1: Default Security Group Lockdown
# Source: CSCF v2026, § a) Overall design goals, § c) Boundary Protection
# Scope: VPC | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_default_security_group"
	zone_scope.in_swift_zone(resource)

	ingress := object.get(resource.values, "ingress", [])
	egress := object.get(resource.values, "egress", [])
	count(ingress) + count(egress) > 0

	msg := sprintf(
		"CSCF 1.1 [1.1-A1]: Default VPC security group has rules defined. All traffic must use explicit security groups (§ a, § c). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.1-A2: No Unrestricted Inbound Access
# Source: CSCF v2026, § c) Boundary Protection
# Scope: VPC | Variant: A
# Binding: inline ingress blocks, and the standalone rule resources
#   (aws_vpc_security_group_ingress_rule, aws_security_group_rule)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.ingress[_]
	cidr_blocks := object.get(rule, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidr_blocks)

	msg := sprintf(
		"CSCF 1.1 [1.1-A2]: Security group allows unrestricted inbound from 0.0.0.0/0. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.ingress[_]
	ipv6_blocks := object.get(rule, "ipv6_cidr_blocks", [])
	helpers.has_unrestricted_ipv6_cidr(ipv6_blocks)

	msg := sprintf(
		"CSCF 1.1 [1.1-A2]: Security group allows unrestricted inbound from ::/0. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_vpc_security_group_ingress_rule"
	parent_scope.parent_in_swift_zone(rule, "security_group_id", "aws_security_group")
	_open_to_world(rule.values)

	msg := sprintf(
		"CSCF 1.1 [1.1-A2]: Security group allows unrestricted inbound from 0.0.0.0/0. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[rule.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_security_group_rule"
	parent_scope.parent_in_swift_zone(rule, "security_group_id", "aws_security_group")
	rule.values.type == "ingress"
	cidrs := object.get(rule.values, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidrs)

	msg := sprintf(
		"CSCF 1.1 [1.1-A2]: Security group allows unrestricted inbound from 0.0.0.0/0. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[rule.address],
	)
}

# ============================================================================
# 1.1-A3: Administrative Port Restriction
# Source: CSCF v2026, § d.1) Local Operator Access
# Scope: VPC | Variant: A
# Binding: as 1.1-A2. An all-protocols rule (protocol "-1") opens every port,
#   so every admin port with it, although its from_port/to_port are 0.
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.ingress[_]
	admin_port := ADMIN_PORTS[_]
	helpers.port_in_range(rule.from_port, rule.to_port, admin_port)

	cidr_blocks := object.get(rule, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidr_blocks)

	msg := sprintf(
		"CSCF 1.1 [1.1-A3]: Security group exposes admin port %d to the internet (§ d.1). (resource: %s)",
		[admin_port, resource.address],
	)
}

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.ingress[_]
	admin_port := ADMIN_PORTS[_]
	helpers.port_in_range(rule.from_port, rule.to_port, admin_port)

	ipv6_blocks := object.get(rule, "ipv6_cidr_blocks", [])
	helpers.has_unrestricted_ipv6_cidr(ipv6_blocks)

	msg := sprintf(
		"CSCF 1.1 [1.1-A3]: Security group exposes admin port %d to the internet via IPv6 (§ d.1). (resource: %s)",
		[admin_port, resource.address],
	)
}

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.ingress[_]
	rule.protocol == "-1"
	cidrs := object.get(rule, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidrs)

	admin_port := ADMIN_PORTS[_]

	msg := sprintf(
		"CSCF 1.1 [1.1-A3]: Security group exposes admin port %d to the internet (§ d.1). (resource: %s)",
		[admin_port, resource.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_vpc_security_group_ingress_rule"
	parent_scope.parent_in_swift_zone(rule, "security_group_id", "aws_security_group")
	_open_to_world(rule.values)

	admin_port := ADMIN_PORTS[_]
	_covers_port(rule.values, admin_port)

	msg := sprintf(
		"CSCF 1.1 [1.1-A3]: Security group exposes admin port %d to the internet (§ d.1). (resource: %s)",
		[admin_port, rule.address],
	)
}

# ============================================================================
# 1.1-A4: Egress Restriction
# Source: CSCF v2026, § c) Boundary Protection
# Scope: VPC | Variant: A
# Binding: inline egress blocks, and the standalone rule resources
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.egress[_]
	rule.protocol == "-1"

	cidr_blocks := object.get(rule, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidr_blocks)

	msg := sprintf(
		"CSCF 1.1 [1.1-A4]: Security group allows unrestricted outbound on all ports. CSCF requires outbound connectivity to be limited (§ c). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.egress[_]
	rule.protocol == "-1"

	ipv6_blocks := object.get(rule, "ipv6_cidr_blocks", [])
	helpers.has_unrestricted_ipv6_cidr(ipv6_blocks)

	msg := sprintf(
		"CSCF 1.1 [1.1-A4]: Security group allows unrestricted outbound via IPv6 on all ports (§ c). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_vpc_security_group_egress_rule"
	parent_scope.parent_in_swift_zone(rule, "security_group_id", "aws_security_group")
	rule.values.ip_protocol == "-1"
	_open_to_world(rule.values)

	msg := sprintf(
		"CSCF 1.1 [1.1-A4]: Security group allows unrestricted outbound on all ports. CSCF requires outbound connectivity to be limited (§ c). (resource: %s)",
		[rule.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_security_group_rule"
	parent_scope.parent_in_swift_zone(rule, "security_group_id", "aws_security_group")
	rule.values.type == "egress"
	rule.values.protocol == "-1"
	cidrs := object.get(rule.values, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidrs)

	msg := sprintf(
		"CSCF 1.1 [1.1-A4]: Security group allows unrestricted outbound on all ports. CSCF requires outbound connectivity to be limited (§ c). (resource: %s)",
		[rule.address],
	)
}

# ============================================================================
# 1.1-A5: No Public IP Auto-Assignment
# Source: CSCF v2026, § a) Overall design goals, § c) Boundary Protection
# Scope: VPC | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_subnet"
	zone_scope.in_swift_zone(resource)

	resource.values.map_public_ip_on_launch == true

	msg := sprintf(
		"CSCF 1.1 [1.1-A5]: Subnet auto-assigns public IPs. Swift subnets must not expose instances to the internet (§ a, § c). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.1-A6: No Internet Gateway Route
# Source: CSCF v2026, § a) Overall design goals, § c) Boundary Protection
# Scope: VPC (via route table) | Variant: E (cross-resource relationship)
# ============================================================================

deny contains msg if {
	route := helpers.all_resources[_]
	route.type == "aws_route"
	parent_scope.route_in_swift_vpc(route)

	gateway_id := object.get(route.values, "gateway_id", "")
	gateway_id != ""

	# Check if the gateway_id references an internet gateway. An empty id is
	# contained in every string, so it would match every route (review R9.4).
	igw := helpers.all_resources[_]
	igw.type == "aws_internet_gateway"
	igw_id := object.get(igw.values, "id", "")
	igw_id != ""
	contains(gateway_id, igw_id)

	msg := sprintf(
		"CSCF 1.1 [1.1-A6]: Route table has a direct route to an Internet Gateway. Swift secure zone must not have direct internet connectivity (§ a, § c). (resource: %s)",
		[route.address],
	)
}

# Fallback: flag any route with gateway_id starting with "igw-"
deny contains msg if {
	route := helpers.all_resources[_]
	route.type == "aws_route"
	parent_scope.route_in_swift_vpc(route)

	gateway_id := object.get(route.values, "gateway_id", "")
	startswith(gateway_id, "igw-")

	msg := sprintf(
		"CSCF 1.1 [1.1-A6]: Route has gateway_id '%s' which appears to be an Internet Gateway (§ a, § c). (resource: %s)",
		[gateway_id, route.address],
	)
}

# ============================================================================
# 1.1-A7: Default NACL Inbound Restriction
# Source: CSCF v2026, § c) Boundary Protection
# Scope: VPC | Variant: A
# Binding: default and custom ACLs, inline rules and aws_network_acl_rule
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_default_network_acl"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.ingress[_]
	rule.protocol == "-1"
	rule.cidr_block == "0.0.0.0/0"
	rule.action == "allow"

	msg := sprintf(
		"CSCF 1.1 [1.1-A7]: Default NACL allows all inbound traffic. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	acl := helpers.all_resources[_]
	acl.type == "aws_network_acl"
	zone_scope.in_swift_zone(acl)

	rule := acl.values.ingress[_]
	_allows_everything(rule)

	msg := sprintf(
		"CSCF 1.1 [1.1-A7]: Network ACL allows all inbound traffic. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[acl.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_network_acl_rule"
	_acl_in_swift_zone(rule)
	rule.values.egress == false
	_rule_allows_everything(rule.values)

	msg := sprintf(
		"CSCF 1.1 [1.1-A7]: Network ACL allows all inbound traffic. CSCF requires explicit allowlisting (§ c). (resource: %s)",
		[rule.address],
	)
}

# ============================================================================
# 1.1-A8: Default NACL Outbound Restriction
# Source: CSCF v2026, § c) Boundary Protection
# Scope: VPC | Variant: A
# Binding: as 1.1-A7
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_default_network_acl"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.egress[_]
	rule.protocol == "-1"
	rule.cidr_block == "0.0.0.0/0"
	rule.action == "allow"

	msg := sprintf(
		"CSCF 1.1 [1.1-A8]: Default NACL allows all outbound traffic. CSCF requires outbound connectivity limited (§ c). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	acl := helpers.all_resources[_]
	acl.type == "aws_network_acl"
	zone_scope.in_swift_zone(acl)

	rule := acl.values.egress[_]
	_allows_everything(rule)

	msg := sprintf(
		"CSCF 1.1 [1.1-A8]: Network ACL allows all outbound traffic. CSCF requires outbound connectivity limited (§ c). (resource: %s)",
		[acl.address],
	)
}

deny contains msg if {
	rule := helpers.all_resources[_]
	rule.type == "aws_network_acl_rule"
	_acl_in_swift_zone(rule)
	rule.values.egress == true
	_rule_allows_everything(rule.values)

	msg := sprintf(
		"CSCF 1.1 [1.1-A8]: Network ACL allows all outbound traffic. CSCF requires outbound connectivity limited (§ c). (resource: %s)",
		[rule.address],
	)
}

# ============================================================================
# 1.1-A9: VPC Flow Logs Enabled
# Source: CSCF v2026, § c) Boundary Protection (cross-ref: 6.4)
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

	msg := "CSCF 1.1 [1.1-A9]: No VPC Flow Log capturing ALL traffic is configured. CSCF requires boundary connections to be logged (§ c, cross-ref: 6.4)."
}

# ============================================================================
# 1.1-A10: Client VPN Authentication Type
# Source: CSCF v2026, § d.2) Remote Operator Access
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ec2_client_vpn_endpoint"
	helpers.is_swift_tagged(resource)

	auth_options := resource.values.authentication_options
	not _has_strong_vpn_auth(auth_options)

	msg := sprintf(
		"CSCF 1.1 [1.1-A10]: Client VPN does not use certificate or directory-service auth. CSCF requires VPN authentication with MFA capability (§ d.2). (resource: %s)",
		[resource.address],
	)
}

_has_strong_vpn_auth(options) if {
	option := options[_]
	option.type == "certificate-authentication"
}

_has_strong_vpn_auth(options) if {
	option := options[_]
	option.type == "directory-service-authentication"
}

# ============================================================================
# 1.1-A11: Client VPN Authorization Scope
# Source: CSCF v2026, § d.2) Remote Operator Access
# Scope: TAG (via VPN endpoint) | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ec2_client_vpn_authorization_rule"
	parent_scope.parent_swift_tagged(resource, "client_vpn_endpoint_id", "aws_ec2_client_vpn_endpoint")

	resource.values.target_network_cidr == "0.0.0.0/0"
	access_group := object.get(resource.values, "access_group_id", "")
	access_group == ""

	msg := sprintf(
		"CSCF 1.1 [1.1-A11]: VPN auth rule grants access to all networks without group restriction. Remote access must be scoped (§ d.2). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.1-A12: Instance Profile MFA Condition
# Source: CSCF v2026, § e) Separation from Enterprise IT, § d.1)
# Scope: TAG | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_role"
	helpers.is_swift_tagged(resource)

	# Only human-assumable roles -- service roles (Lambda, ECS, etc.) cannot use MFA
	helpers.is_human_assumable(resource)

	policy := json.unmarshal(resource.values.assume_role_policy)
	not _requires_mfa(policy)

	msg := sprintf(
		"CSCF 1.1 [1.1-A12]: IAM role does not enforce MFA in assume-role policy. CSCF requires separate auth with MFA for secure zone access (§ e, § d.1). (resource: %s)",
		[resource.address],
	)
}

# The trust policy carries an MFA condition, and no Allow statement carries one
# that is switched off. Library 1.0.0 tested only that the condition key was
# present, so `"aws:MultiFactorAuthPresent": "false"` -- the opposite of the
# requirement -- read as compliant (review R6).
_requires_mfa(policy) if {
	_has_mfa_condition(policy)
	not _disables_mfa(policy)
}

_has_mfa_condition(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Condition.Bool["aws:MultiFactorAuthPresent"]
}

_has_mfa_condition(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Condition.BoolIfExists["aws:MultiFactorAuthPresent"]
}

_has_mfa_condition(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Condition.NumericLessThan["aws:MultiFactorAuthAge"]
}

_disables_mfa(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"
	value := stmt.Condition.Bool["aws:MultiFactorAuthPresent"]
	not helpers.is_true(value)
}

_disables_mfa(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"
	value := stmt.Condition.BoolIfExists["aws:MultiFactorAuthPresent"]
	not helpers.is_true(value)
}

# ============================================================================
# 1.1-A13: Permissions Boundary Enforcement
# Source: CSCF v2026, § e) Separation from Enterprise IT
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_role"
	helpers.is_swift_tagged(resource)

	# Only human-assumable roles -- service roles don't need boundaries. The
	# trust policy must be readable for that to be decided (review R9.2).
	helpers.is_human_assumable(resource)

	boundary := object.get(resource.values, "permissions_boundary", "")
	boundary == ""

	msg := sprintf(
		"CSCF 1.1 [1.1-A13]: IAM role has no permissions boundary. CSCF requires protection from privilege escalation beyond the secure zone (§ e). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.1-A14: Jump Server MFA Deny Policy
# Source: CSCF v2026, § d.1) Local Operator Access
# Scope: TAG (via parent role) | Variant: C (JSON parse)
# `aws_iam_role_policy` takes no tags, so scope comes from the role it
# attaches to -- which the rule resolves anyway, to check the role is
# human-assumable (found on generated plans).
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_role_policy"

	role := parent_scope.role_for(resource)
	helpers.is_swift_tagged(role)
	helpers.is_human_assumable(role)

	policy := json.unmarshal(resource.values.policy)
	not _denies_non_mfa(policy)

	msg := sprintf(
		"CSCF 1.1 [1.1-A14]: IAM policy does not include Deny for non-MFA sessions. CSCF requires MFA for admin access to the secure zone (§ d.1). (resource: %s)",
		[resource.address],
	)
}

# A Deny statement that refuses sessions without MFA, in either spelling (R7).
_denies_non_mfa(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Deny"
	helpers.is_false(stmt.Condition.BoolIfExists["aws:MultiFactorAuthPresent"])
}

_denies_non_mfa(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Deny"
	helpers.is_false(stmt.Condition.Bool["aws:MultiFactorAuthPresent"])
}

# ============================================================================
# 1.1-A15: Bucket Policy Principal Outside the Trust Boundary
# Source: CSCF v2026, § c) Boundary Protection
# Scope: TAG (via bucket) | Variant: E (cross-resource relationship)
# A bucket in the secure zone may grant access only to accounts inside the
# declared trust boundary (input.swift_trust_boundary_accounts, bound by
# resolve_plan.py). The bucket and the policy can each pass every per-resource
# check while the grant still crosses the boundary: the verdict needs the
# principal, the bucket's zone and the boundary together. A condition narrows a
# grant but does not bring its principal inside. With no boundary bound the
# rule cannot decide, and the gate reports it undetermined (library 2.1.0).
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_policy"
	parent_scope.in_swift_zone_via_bucket(resource)

	bound := input.swift_trust_boundary_accounts
	boundary := {a | some a in bound}

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"
	some account in helpers.principal_accounts(stmt.Principal)
	not account in boundary

	msg := sprintf(
		"CSCF 1.1 [1.1-A15]: S3 bucket policy grants account %s, outside the declared Swift trust boundary (§ Boundary Protection). (resource: %s)",
		[account, resource.address],
	)
}

# A canonical user id names an account (or a CloudFront origin access
# identity) the plan cannot place inside the boundary. Not provably inside is
# outside: the grant has to be written with an account ARN to pass (2.1.1).
deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_policy"
	parent_scope.in_swift_zone_via_bucket(resource)

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"
	stmt.Principal.CanonicalUser

	msg := sprintf(
		"CSCF 1.1 [1.1-A15]: S3 bucket policy grants a canonical user, which cannot be placed inside the declared Swift trust boundary (§ Boundary Protection). (resource: %s)",
		[resource.address],
	)
}

# Allow with NotPrincipal grants every principal except those listed --
# accounts outside any boundary included, whatever the boundary is (2.1.1).
deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_policy"
	parent_scope.in_swift_zone_via_bucket(resource)

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"
	stmt.NotPrincipal

	msg := sprintf(
		"CSCF 1.1 [1.1-A15]: S3 bucket policy allows every principal except those listed (NotPrincipal), accounts outside the declared Swift trust boundary included (§ Boundary Protection). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# Shared predicates
# ============================================================================

_open_to_world(values) if object.get(values, "cidr_ipv4", "") == "0.0.0.0/0"

_open_to_world(values) if object.get(values, "cidr_ipv6", "") == "::/0"

# A standalone rule covers a port when its range includes it, or when it names
# every protocol -- in which case from_port and to_port are absent entirely.
_covers_port(values, port) if {
	helpers.port_in_range(values.from_port, values.to_port, port)
}

_covers_port(values, _) if {
	values.ip_protocol == "-1"
}

# An inline ACL rule (ingress/egress block of an ACL) that admits everything.
_allows_everything(rule) if {
	object.get(rule, "protocol", "") == "-1"
	object.get(rule, "action", "") == "allow"
	_any_source(rule)
}

# The same for a standalone aws_network_acl_rule, which names its action
# `rule_action` rather than `action`.
_rule_allows_everything(values) if {
	object.get(values, "protocol", "") == "-1"
	object.get(values, "rule_action", "") == "allow"
	_any_source(values)
}

_any_source(rule) if object.get(rule, "cidr_block", "") == "0.0.0.0/0"

_any_source(rule) if object.get(rule, "ipv6_cidr_block", "") == "::/0"

# A standalone ACL rule belongs to a custom ACL or to the VPC's default one.
_acl_in_swift_zone(rule) if {
	parent_scope.parent_in_swift_zone(rule, "network_acl_id", "aws_network_acl")
}

_acl_in_swift_zone(rule) if {
	parent_scope.parent_in_swift_zone(rule, "network_acl_id", "aws_default_network_acl")
}

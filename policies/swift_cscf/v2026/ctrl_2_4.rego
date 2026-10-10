# SWIFT CSCF v2026, Control 2.4: Back Office Data Flow Security
# Framework v1.2.1: Phase II (new control; see translations/ctrl_2_4_translation.md)
# Assertions: 2.4-A1 through 2.4-A4 (4 deny rules)
# Control Objective: Ensure the confidentiality, integrity, and authenticity of
#   data exchanged between back-office first hops and Swift infrastructure.
#
# Internal-service transport TLS (-> 2.1) and key protection (-> 5.4 / 2.1 KMS)
# are XREF-excluded; data-level Swift-application mechanisms (AES-GCM LAU, XML
# DSIG) are VENDOR-excluded. The rules below target the net-new back-office
# BOUNDARY connectivity: site-to-site VPN, mutual TLS, and Direct Connect.
# Uses the shared helpers.

package swift_cscf.v2026.ctrl_2_4

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 2.4-A1: Back-office site-to-site VPN tunnels enforce AES-256 Phase-2 encryption
# Source: CSCF v2026, § secure protocols (current cryptographic algorithms)
# Scope: TAG | Variant: A  (unset or AES128-containing = violation)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_vpn_connection"
	helpers.is_swift_tagged(resource)

	not _phase2_aes256(resource)

	msg := sprintf(
		"CSCF 2.4 [2.4-A1]: Back-office VPN tunnel does not enforce AES-256 Phase-2 encryption on both tunnels (§ secure protocols). (resource: %s)",
		[resource.address],
	)
}

_phase2_aes256(resource) if {
	t1 := object.get(resource.values, "tunnel1_phase2_encryption_algorithms", [])
	count(t1) > 0
	not "AES128" in t1
	t2 := object.get(resource.values, "tunnel2_phase2_encryption_algorithms", [])
	count(t2) > 0
	not "AES128" in t2
}

# ============================================================================
# 2.4-A2: Back-office site-to-site VPN tunnels use IKEv2 (not IKEv1)
# Source: CSCF v2026, § secure protocols (authentication of the connection)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_vpn_connection"
	helpers.is_swift_tagged(resource)

	not _ikev2_only(resource)

	msg := sprintf(
		"CSCF 2.4 [2.4-A2]: Back-office VPN tunnel permits IKEv1 (or leaves the IKE version unset); IKEv2 is required (§ secure protocols). (resource: %s)",
		[resource.address],
	)
}

_ikev2_only(resource) if {
	v1 := object.get(resource.values, "tunnel1_ike_versions", [])
	count(v1) > 0
	not "ikev1" in v1
	v2 := object.get(resource.values, "tunnel2_ike_versions", [])
	count(v2) > 0
	not "ikev1" in v2
}

# ============================================================================
# 2.4-A3: Back-office API Gateway custom domains enforce mutual TLS
# Source: CSCF v2026, § authentication (authenticity of the connecting party)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_api_gateway_domain_name"
	helpers.is_swift_tagged(resource)

	not _has_mutual_tls(resource)

	msg := sprintf(
		"CSCF 2.4 [2.4-A3]: Back-office API domain does not enforce mutual TLS; the connecting party's authenticity is not verified (§ authentication). (resource: %s)",
		[resource.address],
	)
}

_has_mutual_tls(resource) if {
	mtls := resource.values.mutual_tls_authentication[_]
	mtls.truststore_uri != ""
}

# ============================================================================
# 2.4-A4: Direct Connect connections enforce MACsec encryption
# Source: CSCF v2026, § confidentiality (protect data in transit)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_dx_connection"
	helpers.is_swift_tagged(resource)

	mode := object.get(resource.values, "encryption_mode", "no_encrypt")
	mode != "must_encrypt"

	msg := sprintf(
		"CSCF 2.4 [2.4-A4]: Direct Connect does not enforce MACsec encryption (encryption_mode='%s'); back-office link confidentiality is not guaranteed (§ confidentiality). (resource: %s)",
		[mode, resource.address],
	)
}

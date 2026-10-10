# SWIFT CSCF v2026: Parent-owned scope resolution
# Framework: LCT v2.0, Binding plane (Target Profile correction)
#
# Many resource types that a scoped assertion reads cannot carry a zone tag or a
# vpc_id of their own: attachments and sub-resources such as
# `aws_s3_bucket_policy`, `aws_iam_role_policy`, `aws_route`,
# `aws_security_group_rule` or `aws_efs_file_system_policy`. The AWS provider
# rejects a `tags` argument on them, so a rule that tests the tag on the
# resource itself can never fire -- three Phase I assertions were unsatisfiable
# for exactly that reason (terraform/README.md).
#
# The normative assertion is unchanged; only its scope binding moves. A
# sub-resource inherits the scope of the resource it belongs to, so this package
# resolves that parent and reports whether *it* is in the Swift zone.

package swift_cscf.v2026.parent_scope

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.zone_scope

# ============================================================================
# Generic parent lookup
# ============================================================================
#
# `child.values[attribute]` names the parent -- by id, name or ARN -- and the
# parent is a resource of `type` in the same plan. Both are stated at the call
# site, e.g.
#
#     parent_scope.parent_swift_tagged(resource, "file_system_id", "aws_efs_file_system")
#
# so the Gate B admissibility check can verify that the child type has the
# attribute and the parent type can carry the tag.

# TAG scope via the parent.
parent_swift_tagged(child, attribute, type) if {
	parent := _parents(child, attribute, type)[_]
	helpers.is_swift_tagged(parent)
}

# VPC scope via the parent (the binding, or the zone tag when there is none).
parent_in_swift_zone(child, attribute, type) if {
	parent := _parents(child, attribute, type)[_]
	zone_scope.in_swift_zone(parent)
}

_parents(child, attribute, type) := {parent |
	key := object.get(child.values, attribute, "")
	key != ""
	parent := helpers.all_resources[_]
	parent.type == type
	_identifies(parent, key)
}

# ============================================================================
# Named lookups, for rules that need the parent itself
# ============================================================================

# The bucket an aws_s3_bucket_policy attaches to. The `bucket` argument holds
# either the bucket's name or its id, and for an S3 bucket those are the same
# string; both are matched so the join survives either spelling.
bucket_for(policy) := bucket if {
	key := object.get(policy.values, "bucket", "")
	key != ""
	bucket := helpers.all_resources[_]
	bucket.type == "aws_s3_bucket"
	_identifies(bucket, key)
}

# The role an aws_iam_role_policy attaches to, matched on name or id.
role_for(policy) := role if {
	key := object.get(policy.values, "role", "")
	key != ""
	role := helpers.all_resources[_]
	role.type == "aws_iam_role"
	_identifies(role, key)
}

_identifies(resource, key) if {
	object.get(resource.values, "name", "") == key
}

_identifies(resource, key) if {
	object.get(resource.values, "bucket", "") == key
}

_identifies(resource, key) if {
	object.get(resource.values, "id", "") == key
}

_identifies(resource, key) if {
	object.get(resource.values, "arn", "") == key
}

# The route table a route belongs to. `aws_route` takes no tags and has no
# vpc_id, so a VPC-scoped rule over routes has to resolve the table first.
route_table_for(route) := table if {
	key := object.get(route.values, "route_table_id", "")
	key != ""
	table := helpers.all_resources[_]
	table.type == "aws_route_table"
	_identifies(table, key)
}

# A route is in the Swift zone when its route table is.
route_in_swift_vpc(route) if {
	zone_scope.in_swift_zone(route_table_for(route))
}

# An attachment is in scope when the resource it attaches to is Swift-tagged.
in_swift_zone_via_bucket(policy) if {
	helpers.is_swift_tagged(bucket_for(policy))
}

in_swift_zone_via_role(policy) if {
	helpers.is_swift_tagged(role_for(policy))
}

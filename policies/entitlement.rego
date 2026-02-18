package terraform.cloudsmith.entitlement

import rego.v1

# ============================================================
# Cloudsmith Entitlement Token Policies
# Enforces standards for cloudsmith_entitlement resources
# ============================================================

entitlement_resources contains r if {
    r := input.resource_changes[_]
    r.type == "cloudsmith_entitlement"
    r.change.actions[_] != "delete"
}

# DENY: Entitlement tokens must have a name
deny contains msg if {
    r := entitlement_resources[_]
    not r.change.after.name
    msg := sprintf("CS-ENT-001: %v - entitlement token must have a name", [r.address])
}

deny contains msg if {
    r := entitlement_resources[_]
    r.change.after.name == ""
    msg := sprintf("CS-ENT-001: %v - entitlement token name must not be empty", [r.address])
}

# DENY: Entitlement must reference a repository
deny contains msg if {
    r := entitlement_resources[_]
    not r.change.after.repository
    msg := sprintf("CS-ENT-002: %v - entitlement must specify a repository", [r.address])
}

# DENY: Entitlement must reference a namespace
deny contains msg if {
    r := entitlement_resources[_]
    not r.change.after.namespace
    msg := sprintf("CS-ENT-003: %v - entitlement must specify a namespace", [r.address])
}

# WARN: Entitlements without restrictions are overly permissive
warn contains msg if {
    r := entitlement_resources[_]
    not r.change.after.limit_num_clients
    not r.change.after.limit_num_downloads
    not r.change.after.limit_package_query
    not r.change.after.limit_path_query
    not r.change.after.limit_date_range_from
    not r.change.after.limit_date_range_to
    msg := sprintf("CS-ENT-004: %v - entitlement has no restrictions; consider limiting scope", [r.address])
}

# WARN: Entitlements without expiry
warn contains msg if {
    r := entitlement_resources[_]
    not r.change.after.limit_date_range_to
    msg := sprintf("CS-ENT-005: %v - entitlement has no expiry date (limit_date_range_to); consider setting one", [r.address])
}

# DENY: Entitlement must not allow unlimited clients in production
max_clients := 100

deny contains msg if {
    r := entitlement_resources[_]
    clients := r.change.after.limit_num_clients
    clients != null
    clients > max_clients
    msg := sprintf("CS-ENT-006: %v - entitlement allows %v clients (max: %v)", [r.address, clients, max_clients])
}

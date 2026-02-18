package terraform.cloudsmith.access

import rego.v1

# ============================================================
# Cloudsmith Access Control Policies
# Enforces standards for services, teams, and privileges
# ============================================================

# --- Service Accounts (API Keys) ---

service_resources contains r if {
    r := input.resource_changes[_]
    r.type == "cloudsmith_service"
    r.change.actions[_] != "delete"
}

# DENY: Service accounts must have a name
deny contains msg if {
    r := service_resources[_]
    not r.change.after.name
    msg := sprintf("CS-SVC-001: %v - service account must have a name", [r.address])
}

# DENY: Service accounts must have a description for audit
deny contains msg if {
    r := service_resources[_]
    not r.change.after.description
    msg := sprintf("CS-SVC-002: %v - service account must have a description", [r.address])
}

deny contains msg if {
    r := service_resources[_]
    r.change.after.description == ""
    msg := sprintf("CS-SVC-002: %v - service account description must not be empty", [r.address])
}

# DENY: Service accounts must belong to an organization
deny contains msg if {
    r := service_resources[_]
    not r.change.after.organization
    msg := sprintf("CS-SVC-003: %v - service account must specify an organization", [r.address])
}

# --- Teams ---

team_resources contains r if {
    r := input.resource_changes[_]
    r.type == "cloudsmith_team"
    r.change.actions[_] != "delete"
}

# DENY: Teams must have a name
deny contains msg if {
    r := team_resources[_]
    not r.change.after.name
    msg := sprintf("CS-TEAM-001: %v - team must have a name", [r.address])
}

# DENY: Teams must belong to an organization
deny contains msg if {
    r := team_resources[_]
    not r.change.after.organization
    msg := sprintf("CS-TEAM-002: %v - team must specify an organization", [r.address])
}

# DENY: Team slug must follow naming convention
deny contains msg if {
    r := team_resources[_]
    slug := r.change.after.slug
    slug != null
    not regex.match(`^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$`, slug)
    msg := sprintf("CS-TEAM-003: %v - team slug '%v' must be lowercase alphanumeric with hyphens", [r.address, slug])
}

# --- Repository Privileges ---

privilege_resources contains r if {
    r := input.resource_changes[_]
    r.type == "cloudsmith_repository_privileges"
    r.change.actions[_] != "delete"
}

# Allowed privilege levels
allowed_privileges := ["Read", "Write", "Admin"]

# WARN: Admin privilege grants should be reviewed
warn contains msg if {
    r := privilege_resources[_]
    svc := r.change.after.service[_]
    svc.privilege == "Admin"
    msg := sprintf("CS-PRIV-001: %v - service '%v' granted Admin on repository; ensure this is intended", [r.address, svc.slug])
}

warn contains msg if {
    r := privilege_resources[_]
    team := r.change.after.team[_]
    team.privilege == "Admin"
    msg := sprintf("CS-PRIV-002: %v - team '%v' granted Admin on repository; ensure this is intended", [r.address, team.slug])
}

warn contains msg if {
    r := privilege_resources[_]
    user := r.change.after.user[_]
    user.privilege == "Admin"
    msg := sprintf("CS-PRIV-003: %v - user '%v' granted Admin on repository; ensure this is intended", [r.address, user.slug])
}

# DENY: Write privilege for services must have a corresponding team or user admin
# (Ensures no orphaned write-access service accounts)
warn contains msg if {
    r := privilege_resources[_]
    svc := r.change.after.service[_]
    svc.privilege == "Write"
    not r.change.after.team
    not r.change.after.user
    msg := sprintf("CS-PRIV-004: %v - service '%v' has Write access but no team/user admins defined", [r.address, svc.slug])
}

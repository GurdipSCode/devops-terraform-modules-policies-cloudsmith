package terraform.cloudsmith.general

import rego.v1

# ============================================================
# Cloudsmith General Governance Policies
# Blast radius, provider safety, deletion protection
# ============================================================

# All Cloudsmith resource changes
cloudsmith_resources contains r if {
    r := input.resource_changes[_]
    startswith(r.type, "cloudsmith_")
}

# --- Blast Radius ---

max_deletions := 3

deletions := [r |
    r := cloudsmith_resources[_]
    r.change.actions[_] == "delete"
]

deny contains msg if {
    count(deletions) > max_deletions
    msg := sprintf("CS-GEN-001: Plan deletes %v Cloudsmith resources (max: %v). Break into smaller changes.", [count(deletions), max_deletions])
}

max_total_changes := 20

all_changes := [r |
    r := cloudsmith_resources[_]
    r.change.actions[_] != "no-op"
    r.change.actions[_] != "read"
]

deny contains msg if {
    count(all_changes) > max_total_changes
    msg := sprintf("CS-GEN-002: Plan modifies %v Cloudsmith resources (max: %v). Break into smaller changes.", [count(all_changes), max_total_changes])
}

# --- Protected Resources ---

protected_types := [
    "cloudsmith_repository",
    "cloudsmith_service",
    "cloudsmith_repository_privileges",
]

warn contains msg if {
    r := cloudsmith_resources[_]
    r.type in protected_types
    r.change.actions[_] == "delete"
    msg := sprintf("CS-GEN-003: Deleting protected resource '%v' at %v — requires review", [r.type, r.address])
}

# --- Provider Configuration ---

# DENY: Provider must not have API key hardcoded (check for literal strings)
# This checks the Terraform config JSON (via hcl2json), not the plan
deny contains msg if {
    provider := input.configuration.provider_config.cloudsmith
    key := provider.expressions.api_key
    key.constant_value != null
    msg := "CS-GEN-004: Cloudsmith API key must not be hardcoded in provider config. Use env var CLOUDSMITH_API_KEY or a secrets manager."
}

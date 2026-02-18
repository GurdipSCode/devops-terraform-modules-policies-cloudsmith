package terraform.cloudsmith.webhook

import rego.v1

# ============================================================
# Cloudsmith Webhook Policies
# Enforces standards for cloudsmith_webhook resources
# ============================================================

webhook_resources contains r if {
    r := input.resource_changes[_]
    r.type == "cloudsmith_webhook"
    r.change.actions[_] != "delete"
}

# DENY: Webhooks must use HTTPS target URLs
deny contains msg if {
    r := webhook_resources[_]
    url := r.change.after.target_url
    url != null
    startswith(url, "http://")
    msg := sprintf("CS-HOOK-001: %v - webhook target_url must use HTTPS, got: %v", [r.address, url])
}

# DENY: Webhooks must have a target URL
deny contains msg if {
    r := webhook_resources[_]
    not r.change.after.target_url
    msg := sprintf("CS-HOOK-002: %v - webhook must have a target_url", [r.address])
}

# DENY: Webhooks must reference a repository
deny contains msg if {
    r := webhook_resources[_]
    not r.change.after.repository
    msg := sprintf("CS-HOOK-003: %v - webhook must specify a repository", [r.address])
}

# DENY: Webhooks must reference a namespace
deny contains msg if {
    r := webhook_resources[_]
    not r.change.after.namespace
    msg := sprintf("CS-HOOK-004: %v - webhook must specify a namespace", [r.address])
}

# WARN: Webhooks should have a secret for payload verification
warn contains msg if {
    r := webhook_resources[_]
    not r.change.after.secret_header
    msg := sprintf("CS-HOOK-005: %v - webhook has no secret_header; payloads cannot be verified", [r.address])
}

# WARN: Webhooks should be active
warn contains msg if {
    r := webhook_resources[_]
    r.change.after.is_active == false
    msg := sprintf("CS-HOOK-006: %v - webhook is inactive at creation; ensure this is intentional", [r.address])
}

# ZeroTrustIAM OPA policy (example)
# Load into OPA as: data.ztiam.authz
# Query path: /v1/data/ztiam/authz/allow

package ztiam.authz

import future.keywords.if
import future.keywords.in

default allow := false

# Deny suspended / deleted
deny_reason["account_not_active"] if {
	input.user.status != "ACTIVE"
}

# Deny high-risk privileged actions
deny_reason["high_risk_privileged"] if {
	input.action in {"delete", "manage"}
	input.context.risk_score > 0.45
}

# Require MFA for write+ when risk >= 0.3
deny_reason["mfa_required"] if {
	input.action in {"write", "delete", "manage"}
	input.context.risk_score >= 0.3
	not input.context.mfa_verified
}

# Allow active users for read by default
allow if {
	input.user.status == "ACTIVE"
	input.action == "read"
	count(deny_reason) == 0
}

allow if {
	input.user.status == "ACTIVE"
	input.action in {"write", "delete", "manage"}
	input.user.role in {"admin", "editor"}
	count(deny_reason) == 0
}

# Structured decision for clients that read result object
decision := {
	"allow": allow,
	"reasons": [r | deny_reason[r]],
}

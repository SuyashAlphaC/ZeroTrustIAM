// ZeroTrustIAM Cedar policy examples
// Deploy to Amazon Verified Permissions or cedar-agent

// Permit active users to read
permit (
  principal,
  action == Action::"read",
  resource
) when {
  context.status == "ACTIVE" &&
  context.riskScore < 0.6
};

// Permit editors/admins to write when MFA verified under medium risk
permit (
  principal,
  action in [Action::"write", Action::"delete", Action::"manage"],
  resource
) when {
  context.status == "ACTIVE" &&
  context.role in ["editor", "admin"] &&
  context.riskScore < 0.45 &&
  (context.riskScore < 0.3 || context.mfaVerified == true)
};

// Explicit forbid for suspended accounts
forbid (
  principal,
  action,
  resource
) when {
  context.status != "ACTIVE"
};

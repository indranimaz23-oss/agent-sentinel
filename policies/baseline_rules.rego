package agent.authz

default allow := false

# Allow if no deny rule matches
allow {
  not deny[_]
}

# Deny destructive actions after-hours in production (baseline uses UTC)
deny["prod-destructive-after-hours"] {
  input.context.environment == "production"
  is_destructive_action
  hour_utc >= 17
}

# Destructive actions (extend as scope expands)
is_destructive_action {
  input.action == "aws:s3:DeleteBucket"
}

# Extract hour (UTC) from RFC3339 timestamp
hour_utc := h {
  t := time.parse_rfc3339_ns(input.context.timestamp)
  clock := time.clock(t)
  h := clock[0]
}

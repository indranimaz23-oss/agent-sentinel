package agent.authz

default allow := false

# Allow if no deny rule matches
allow {
  not deny[_]
}

# Deny destructive actions after 17:00 UTC (baseline; adjust to env later)
deny["destructive-after-hours"] {
  is_destructive_action
  hour >= 17
}

# What counts as "destructive" (extend this list as scope expands)
is_destructive_action {
  input.action == "aws:s3:DeleteBucket"
}

# Parse hour from RFC3339 timestamp (UTC)
hour := h {
  t := time.parse_rfc3339_ns(input.context.timestamp)
  parts := time.clock(t)
  h := parts[0]
}

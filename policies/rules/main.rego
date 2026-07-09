package tracepath.main

import data.tracepath.budget
import data.tracepath.allowlist
import data.tracepath.ratelimit

# Aggregate all policy decisions
# Input: {
#   "action": "audit_step",
#   "agent_type": "...",
#   "tool_name": "...",
#   "estimated_cost_cents": 0,
#   "spent_so_far_cents": 0,
#   "calls_last_minute": 0
# }

default allow := false

allow if {
    budget.allow
    allowlist.allow
    ratelimit.allow
}

deny contains msg if {
    some msg in budget.deny
}

deny contains msg if {
    some msg in allowlist.deny
}

deny contains msg if {
    some msg in ratelimit.deny
}

# Only evaluated if all policies pass
decision := {
    "allowed": allow,
    "denials": deny,
    "policies_checked": ["budget", "allowlist", "ratelimit"],
}

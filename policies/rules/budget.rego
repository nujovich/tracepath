package tracepath.budget

# Default budget limits per session (in cents, so 1000 = $10.00)
default budget_limit := 1000

# Check if cumulative spending would exceed the budget
# Input: {"session_id": "...", "tool_name": "...", "estimated_cost_cents": N, "spent_so_far_cents": N}
default allow := false

allow if {
    input.estimated_cost_cents + input.spent_so_far_cents <= input.budget_limit
}

deny contains msg if {
    not allow
    msg := sprintf("budget exceeded: cost %d + spent %d > limit %d",
                   [input.estimated_cost_cents, input.spent_so_far_cents, input.budget_limit])
}
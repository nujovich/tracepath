package tracepath.ratelimit

# Rate limiting: max calls per minute per session
# Input: {"session_id": "...", "calls_last_minute": N}
default max_calls_per_minute := 60

# max calls per 5 minutes
default max_calls_per_5min := 200

default allow := false

allow if {
    input.calls_last_minute <= max_calls_per_minute
}

deny contains msg if {
    input.calls_last_minute > max_calls_per_minute
    msg := sprintf("rate limit exceeded: %d calls in last minute (max %d)",
                   [input.calls_last_minute, max_calls_per_minute])
}
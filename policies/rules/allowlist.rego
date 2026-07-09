package tracepath.allowlist

# Tools allowed per agent type
# Input: {"agent_id": "...", "agent_type": "...", "tool_name": "..."}

agent_tools := {
    "coder": {"read_file", "write_file", "terminal", "search_files", "patch", "execute_code"},
    "researcher": {"web_search", "web_extract", "browser_navigate", "browser_snapshot"},
    "coordinator": {"delegate_task", "cronjob", "todo", "clarify"},
    "default": {"read_file", "web_search", "web_extract"},
}

# Union of all allowed tools (global allowlist)
global_allowed contains t if {
    some tools in agent_tools
    t := tools[_]
}

default allow := false

allow if {
    global_allowed[input.tool_name]
}

# Further restrict by agent type if specified
allow if {
    tools := agent_tools[input.agent_type]
    tools[input.tool_name]
}

deny contains msg if {
    not allow
    msg := sprintf("tool '%s' not in allowlist for agent_type '%s'",
                   [input.tool_name, object.get(input, "agent_type", "unspecified")])
}
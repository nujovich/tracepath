-- Tracepath audit events schema v2
CREATE TABLE IF NOT EXISTS audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    agent_type      TEXT,
    step_number     INTEGER NOT NULL,
    tool_name       TEXT NOT NULL,
    tool_input      JSONB NOT NULL DEFAULT '{}',
    tool_output     JSONB NOT NULL DEFAULT '{}',
    signature       TEXT NOT NULL,
    policy_decision TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_model TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_provider TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_prompt_tokens BIGINT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_completion_tokens BIGINT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_total_tokens BIGINT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_latency_ms DOUBLE PRECISION;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS llm_cost_cents DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_audit_events_session   ON audit_events (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_agent     ON audit_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created   ON audit_events (created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_tool      ON audit_events (tool_name);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS agents (
    agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spiffe_id TEXT NOT NULL UNIQUE,
    agent_name TEXT NOT NULL,
    owner TEXT NOT NULL,
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agents_spiffe_id ON agents (spiffe_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents (status);

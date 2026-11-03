-- SQLite migration 0001: agents
CREATE TABLE IF NOT EXISTS agents (
    agent_id    TEXT    PRIMARY KEY,               -- UUID stored as text
    spiffe_id   TEXT    NOT NULL UNIQUE,
    agent_name  TEXT    NOT NULL,
    owner       TEXT    NOT NULL,
    allowed_scopes TEXT NOT NULL DEFAULT '[]',     -- JSON array
    status      TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','revoked')),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    revoked_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_agents_spiffe_id ON agents (spiffe_id);
CREATE INDEX IF NOT EXISTS idx_agents_status     ON agents (status);


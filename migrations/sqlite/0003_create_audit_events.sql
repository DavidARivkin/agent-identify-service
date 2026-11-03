-- SQLite migration 0003: audit_events
CREATE TABLE IF NOT EXISTS audit_events (
    event_id        TEXT    PRIMARY KEY,
    occurred_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    event_type      TEXT    NOT NULL,
    actor_spiffe_id TEXT,
    agent_id        TEXT,
    resource        TEXT,
    action          TEXT,
    outcome         TEXT    NOT NULL,
    request_id      TEXT,
    details         TEXT    NOT NULL DEFAULT '{}'   -- JSON stored as text
);

CREATE INDEX IF NOT EXISTS idx_audit_events_time  ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor_spiffe_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_agent ON audit_events (agent_id);


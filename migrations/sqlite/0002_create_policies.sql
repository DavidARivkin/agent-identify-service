-- SQLite migration 0002: policies
CREATE TABLE IF NOT EXISTS policies (
    policy_id   TEXT    PRIMARY KEY,
    spiffe_id   TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    effect      TEXT    NOT NULL CHECK (effect IN ('allow','deny')),
    created_by  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_policies_lookup ON policies (spiffe_id, resource, action, effect);


CREATE TABLE IF NOT EXISTS policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spiffe_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow','deny')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policies_lookup ON policies (spiffe_id, resource, action, effect);

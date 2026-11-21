-- agent-ci fork: gated branches (`[branches.NAME] gated = true` in
-- `.veilrules`). The landing service of a gated branch lands only the rows
-- an admin verifier approved (`POST .../gate/{branch}/approve`), in the
-- verifier's order (`gate_order`), and only while the branch's tip is the
-- one the verifier tested them on (`gate_tip`, hex): a compare-and-swap.
-- Idempotent (IF NOT EXISTS).
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS gate_ok BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS gate_tip TEXT;
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS gate_order BIGINT;
CREATE INDEX IF NOT EXISTS landing_queue_gate ON landing_queue (project_id, branch, gate_order) WHERE state = 'queued' AND gate_ok;

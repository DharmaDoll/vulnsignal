ALTER TABLE intel_state ADD COLUMN hot_rule_version INTEGER NOT NULL DEFAULT 1;
PRAGMA user_version = 12;

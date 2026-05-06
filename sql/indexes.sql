CREATE INDEX IF NOT EXISTS idx_signals_vuln_id      ON signals(vuln_id);
CREATE INDEX IF NOT EXISTS idx_signals_type         ON signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_signals_observed_at  ON signals(observed_at);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_id     ON findings(vuln_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id    ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_risk_score  ON findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_fetch_log_feed       ON fetch_log(feed, attempted_at DESC);

-- ShadowPot indexes (MySQL). See schema/indexes.sqlite.sql for the reasoning
-- behind each one and docs/INDEXES.md for the measurements.
--
-- NOT MEASURED ON MySQL. The numbers in docs/INDEXES.md are SQLite's, taken on
-- the development machine. MySQL's planner, buffer pool and row format are
-- different enough that the verdicts could differ, and this project has not
-- run the benchmark against a live MySQL server. Treat these as a reasonable
-- starting point carried over from the SQLite measurements, not as a result.
--
-- MySQL has no CREATE INDEX IF NOT EXISTS, so re-applying this file raises
-- errno 1061 (duplicate key name). shadowpot/db.py catches exactly that and
-- continues, which is why these are plain CREATE INDEX statements.

CREATE INDEX idx_login_attempts_session ON login_attempts (session_pk);
CREATE INDEX idx_login_attempts_cred    ON login_attempts (cred_id);
CREATE INDEX idx_sessions_source        ON sessions (source_id);
CREATE INDEX idx_commands_input         ON commands (input(255));

-- @name      dataset_summary
-- @title     What this dataset is
-- @question  How much data is here, over what period, and is any of it synthetic?
-- @uses      scalar subqueries
--
-- This runs first in every report so that the scope of every number below it
-- is stated before the numbers are. synthetic_sessions is not decoration: if
-- it is non-zero the report refuses to present its findings as real, because
-- a figure from generated data that reaches a resume is a fabricated claim.
SELECT
    (SELECT COUNT(*) FROM sessions)                              AS sessions,
    (SELECT COUNT(*) FROM sessions WHERE is_synthetic = 1)        AS synthetic_sessions,
    (SELECT COUNT(*) FROM sources)                               AS distinct_ips,
    (SELECT COUNT(*) FROM login_attempts)                        AS login_attempts,
    (SELECT COUNT(*) FROM login_attempts WHERE success = 1)       AS login_successes,
    (SELECT COUNT(*) FROM commands)                              AS commands,
    (SELECT COUNT(*) FROM file_transfers)                        AS file_transfers,
    (SELECT COUNT(*) FROM artifacts)                             AS distinct_artifacts,
    (SELECT MIN(start_ts) FROM sessions)                         AS first_session,
    (SELECT MAX(COALESCE(end_ts, start_ts)) FROM sessions)        AS last_session,
    (SELECT COUNT(DISTINCT substr(start_ts, 1, 10)) FROM sessions
      WHERE start_ts IS NOT NULL)                                AS days_observed;

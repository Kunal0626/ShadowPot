-- @name      ingest_quality
-- @title     What the loader read, and what it threw away
-- @question  Can the numbers above be trusted, and what was dropped?
-- @uses      GROUP BY-free aggregate reporting, NULLIF
--
-- Every other query in this directory reports what was found. This one
-- reports what was LOST, which is the only way a reader can judge the rest.
-- A report that shows findings without showing its own data-quality figures
-- is asking to be believed rather than checked.
--
-- NULLIF(lines_read, 0) guards the percentage against a division by zero on
-- a run that read nothing -- which happens on every incremental run where
-- no new lines arrived, and is a normal outcome rather than an error.
SELECT  run_id,
        started_at,
        finished_at,
        files_scanned,
        lines_read,
        lines_applied,
        lines_duplicate,
        lines_malformed,
        events_unknown,
        events_incomplete,
        ROUND(100.0 * lines_applied / NULLIF(lines_read, 0), 2) AS pct_applied
FROM        ingest_runs
ORDER BY    run_id;

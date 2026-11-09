-- @name      bot_vs_human
-- @title     Scripted or hand-driven sessions (HEURISTIC)
-- @question  Which sessions look automated, and which look like someone typing?
-- @uses      CTEs, window function (LAG), ordered aggregation, GROUP BY
-- @dialect   mysql: TIMESTAMPDIFF(MICROSECOND, ...) replaces julianday
--            differences, and is EXACT rather than float-approximate, so
--            the precision note below applies only to SQLite;
--            GROUP_CONCAT takes SEPARATOR instead of a second argument.
--            GROUP_CONCAT also TRUNCATES at group_concat_max_len, 1024
--            bytes by default, which would silently corrupt the
--            sequence-reuse signal for long scripts. Raise it first:
--            SET SESSION group_concat_max_len = 1048576;
--
-- THIS IS A HEURISTIC, NOT A MEASUREMENT. It cannot be otherwise: the log
-- records what arrived, not who or what sent it. Two signals, both stated
-- here so a reader can disagree with the thresholds rather than having to
-- trust them:
--
--   1. TYPING SPEED. Mean gap between consecutive commands under 250 ms.
--      A human typing a shell command of even ten characters and pressing
--      Enter takes longer than that between commands; fast typists average
--      roughly 100 ms per keystroke. So a quarter-second MEAN across a whole
--      session is not someone at a keyboard.
--
--   2. SEQUENCE REUSE. The exact command sequence appears in more than one
--      session. Independent humans do not type byte-identical command lists
--      in the same order; a payload script does it every time.
--
-- Both signals are SUFFICIENT conditions for "scripted", so the order below
-- changes only which reason is reported, not the classification. Speed is
-- checked first because it is direct evidence about this one session, whereas
-- reuse is evidence about a population. Reuse still earns its place: a script
-- that sleeps between stages has human-looking gaps and defeats signal 1
-- entirely.
--
-- The reuse signal requires at least 3 commands. Short sequences collide by
-- chance -- plenty of unrelated people type `uname -a` and nothing else -- so
-- without that floor the signal reports coincidence as evidence.
--
-- HONEST LIMITATION OF THE VALIDATION. On the synthetic dataset this
-- separates cleanly, but that proves only that the SQL is correct: the
-- generator was written to emit bot gaps of 8-90 ms and interactive gaps of
-- 1.5-14 s, so it cannot disconfirm a 250 ms threshold. Whether 250 ms is
-- right for real attackers is unmeasured until this is run on a real capture.
--
-- julianday() differences are used for the gap, not unixepoch(..,'subsec'),
-- because julianday exists in every SQLite worth supporting. Measured
-- precision on this build (3.50.4): an exact 8 ms gap comes back as
-- 8.006394 ms, an error of 6 microseconds. At a 250 ms threshold that is
-- irrelevant; it would matter if the threshold were in microseconds.
WITH gaps AS (
    SELECT  session_pk,
            TIMESTAMPDIFF(
                MICROSECOND,
                LAG(ts) OVER (PARTITION BY session_pk
                              ORDER BY ts, command_id),
                ts
            ) / 1000.0 AS gap_ms
    FROM    commands
),
pace AS (
    SELECT  session_pk,
            AVG(gap_ms) AS mean_gap_ms,
            MIN(gap_ms) AS min_gap_ms
    FROM    gaps
    WHERE   gap_ms IS NOT NULL
    GROUP BY session_pk
),
scripts AS (
    SELECT  session_pk,
            COUNT(*) AS command_count,
            GROUP_CONCAT(input ORDER BY ts, command_id SEPARATOR '\n') AS script
    FROM    commands
    GROUP BY session_pk
),
reuse AS (
    SELECT script, COUNT(*) AS sessions_sharing_script
    FROM   scripts
    GROUP BY script
)
SELECT  sc.session_pk,
        src.ip,
        ses.duration_ms,
        sc.command_count,
        ROUND(pace.mean_gap_ms, 1)  AS mean_gap_ms,
        ROUND(pace.min_gap_ms, 1)   AS min_gap_ms,
        r.sessions_sharing_script,
        CASE
          WHEN pace.mean_gap_ms IS NOT NULL AND pace.mean_gap_ms < 250
            THEN 'scripted: commands faster than human typing'
          WHEN sc.command_count >= 3 AND r.sessions_sharing_script > 1
            THEN 'scripted: command sequence reused across sessions'
          WHEN pace.mean_gap_ms IS NULL
            THEN 'unclassified: a single command gives no pace to measure'
          ELSE 'human-like'
        END AS verdict
FROM        scripts  AS sc
LEFT JOIN   pace     AS pace ON pace.session_pk = sc.session_pk
JOIN        reuse    AS r    ON r.script        = sc.script
JOIN        sessions AS ses  ON ses.session_pk  = sc.session_pk
JOIN        sources  AS src  ON src.source_id   = ses.source_id
ORDER BY    verdict, sc.command_count DESC, sc.session_pk;

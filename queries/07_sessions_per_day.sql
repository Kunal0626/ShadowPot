-- @name      sessions_per_day
-- @title     Activity per day
-- @question  How did traffic volume change over the observation window?
-- @uses      CTE, joins, GROUP BY
--
-- Note every COUNT(DISTINCT ...). Joining sessions to BOTH login_attempts and
-- commands multiplies rows: a session with 10 logins and 6 commands produces
-- 60 join rows, so a plain COUNT(la.attempt_id) would report 60 attempts
-- instead of 10. That fan-out is the single easiest way to publish a number
-- that is six times too large, and COUNT(DISTINCT ...) is what prevents it.
WITH per_session AS (
    SELECT  substr(start_ts, 1, 10) AS day,
            session_pk,
            source_id
    FROM    sessions
    WHERE   start_ts IS NOT NULL
)
SELECT  d.day,
        COUNT(DISTINCT d.session_pk)    AS sessions,
        COUNT(DISTINCT d.source_id)     AS distinct_ips,
        COUNT(DISTINCT la.attempt_id)   AS login_attempts,
        COUNT(DISTINCT c.command_id)    AS commands
FROM        per_session    AS d
LEFT JOIN   login_attempts AS la ON la.session_pk = d.session_pk
LEFT JOIN   commands       AS c  ON c.session_pk  = d.session_pk
GROUP BY    d.day
ORDER BY    d.day;

-- @name      attempts_per_source
-- @title     Login attempts per source address
-- @question  Which addresses are doing the most work?
-- @uses      view, joins, GROUP BY
--
-- distinct_usernames is a single-column COUNT(DISTINCT ...) on purpose.
-- MySQL supports COUNT(DISTINCT a, b) and SQLite does not, so counting
-- distinct PAIRS here would have needed a dialect override for no real gain.
SELECT  src.ip,
        src.ip_version,
        COUNT(*)                        AS attempts,
        COUNT(DISTINCT v.session_pk)    AS sessions,
        COUNT(DISTINCT v.username)      AS distinct_usernames,
        SUM(v.success)                  AS successes
FROM        v_login_attempts AS v
JOIN        sessions         AS s   ON s.session_pk   = v.session_pk
JOIN        sources          AS src ON src.source_id  = s.source_id
GROUP BY    src.source_id, src.ip, src.ip_version
ORDER BY    attempts DESC, src.ip;

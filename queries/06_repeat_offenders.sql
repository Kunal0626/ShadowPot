-- @name      repeat_offenders
-- @title     Addresses seen on more than one day
-- @question  Which attackers come back, rather than scanning once and leaving?
-- @uses      GROUP BY ... HAVING
--
-- Returning on a later day separates a host that is persistently targeting
-- this address from one that swept the whole internet once. HAVING is doing
-- the real work: the filter is on an aggregate over each group, so it cannot
-- be expressed in WHERE, which is evaluated before grouping.
--
-- substr(start_ts, 1, 10) is the UTC date, valid only because every
-- timestamp is stored in one canonical ISO-8601 form that the schema's CHECK
-- constraints enforce. queries/mysql/ has the DATE() version.
SELECT  src.ip,
        COUNT(DISTINCT substr(s.start_ts, 1, 10))   AS active_days,
        COUNT(*)                                    AS sessions,
        MIN(s.start_ts)                             AS first_seen,
        MAX(COALESCE(s.end_ts, s.start_ts))         AS last_seen
FROM        sessions AS s
JOIN        sources  AS src ON src.source_id = s.source_id
WHERE       s.start_ts IS NOT NULL
GROUP BY    src.source_id, src.ip
HAVING      COUNT(DISTINCT substr(s.start_ts, 1, 10)) > 1
ORDER BY    active_days DESC, sessions DESC, src.ip;

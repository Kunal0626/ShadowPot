-- @name      session_duration_distribution
-- @title     How long sessions last
-- @question  Are these connections drive-by probes or sustained sessions?
-- @uses      CTE, window function over an aggregate, CASE bucketing
--
-- duration_ms is Cowrie's own measurement, not end_ts - start_ts. The two are
-- independent observations and differ by a few milliseconds; this uses the
-- honeypot's figure because that is what the honeypot measured.
--
-- Buckets rather than a mean, because the distribution is strongly bimodal:
-- a mass of sub-second credential probes and a thin tail of real sessions.
-- A mean over those two populations describes neither. SQLite has no median
-- function, so buckets also avoid pretending to a precision we cannot
-- compute portably.
--
-- Bucket labels are prefixed 0: 1: 2: ... so that ORDER BY on the label is
-- chronological rather than alphabetical.
WITH measured AS (
    SELECT duration_ms FROM sessions WHERE duration_ms IS NOT NULL
),
bucketed AS (
    SELECT CASE
             WHEN duration_ms <      1000 THEN '0: under 1s'
             WHEN duration_ms <      5000 THEN '1: 1s to 5s'
             WHEN duration_ms <     30000 THEN '2: 5s to 30s'
             WHEN duration_ms <    120000 THEN '3: 30s to 2m'
             WHEN duration_ms <   3600000 THEN '4: 2m to 1h'
             ELSE                              '5: over 1h'
           END AS bucket
    FROM measured
)
SELECT  bucket,
        COUNT(*)                                            AS sessions,
        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2)  AS pct_of_measured
FROM        bucketed
GROUP BY    bucket
ORDER BY    bucket;

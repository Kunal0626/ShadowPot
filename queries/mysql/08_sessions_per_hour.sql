-- @name      sessions_per_hour
-- @title     Activity by hour of day (UTC)
-- @question  Is this traffic diurnal, like people, or flat, like software?
-- @uses      window function over an aggregate, GROUP BY
-- @dialect   mysql: HOUR() replaces strftime('%H', ts)
--
-- SUM(COUNT(*)) OVER () computes the grand total alongside each group's
-- count, which turns an absolute count into a percentage in one pass. The
-- alternative is a self-join or a second query against the same table.
--
-- Hours are UTC, not local. A flat distribution is itself a finding: human
-- operators sleep and bots do not.
SELECT  HOUR(start_ts)               AS hour_utc,
        COUNT(*)                                                AS sessions,
        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2)      AS pct_of_sessions
FROM        sessions
WHERE       start_ts IS NOT NULL
GROUP BY    hour_utc
ORDER BY    hour_utc;

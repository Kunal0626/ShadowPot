-- @name      client_fingerprints
-- @title     SSH client banners and HASSH fingerprints
-- @question  What software is connecting, and do distinct addresses share one
--            client build?
-- @uses      joins, GROUP BY, COALESCE
--
-- The banner is self-reported and trivially forged. HASSH is derived from the
-- algorithms the client actually offers during key exchange, so it describes
-- the real implementation rather than what it claims to be. Comparing the two
-- columns is the point: many addresses sharing one HASSH while reporting
-- different banners is one toolkit wearing different hats.
--
-- Both are LEFT JOINed and COALESCEd because a session that never completed
-- key exchange has neither, and dropping those rows would overstate how much
-- is known about the traffic.
SELECT  COALESCE(cl.version, '(no banner sent)')    AS client_version,
        COALESCE(s.hassh, '(no key exchange)')      AS hassh,
        COUNT(*)                                    AS sessions,
        COUNT(DISTINCT s.source_id)                 AS distinct_ips
FROM        sessions AS s
LEFT JOIN   clients  AS cl ON cl.client_id = s.client_id
GROUP BY    cl.version, s.hassh
ORDER BY    sessions DESC, client_version, hassh;

-- @name      downloads_and_fetchers
-- @title     Files that entered the honeypot, and who fetched them
-- @question  What payloads were pulled in, and how widely shared are they?
-- @uses      joins, GROUP BY, COALESCE
--
-- Ordered by distinct_ips first: a sample fetched by many unrelated addresses
-- is a shared piece of tooling, which is a more useful signal than one
-- fetched repeatedly by a single host.
--
-- url IS NULL is not missing data. Cowrie fires file_download for stdin
-- captures and shell redirects too, which have no URL at all, so those rows
-- are labelled rather than filtered out or shown as blank.
SELECT  COALESCE(ft.url, '(no url: stdin or shell redirect capture)') AS url,
        ft.sha256,
        a.outfile,
        COUNT(*)                            AS transfers,
        COUNT(DISTINCT ses.source_id)       AS distinct_ips,
        COUNT(DISTINCT ft.session_pk)       AS sessions,
        MIN(ft.ts)                          AS first_seen,
        MAX(ft.ts)                          AS last_seen
FROM        file_transfers AS ft
JOIN        sessions       AS ses ON ses.session_pk = ft.session_pk
LEFT JOIN   artifacts      AS a   ON a.sha256       = ft.sha256
WHERE       ft.direction = 'download'
GROUP BY    ft.url, ft.sha256, a.outfile
ORDER BY    distinct_ips DESC, transfers DESC, url;

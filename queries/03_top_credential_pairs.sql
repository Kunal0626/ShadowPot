-- @name      top_credential_pairs
-- @title     Most-tried username and password pairs
-- @question  Which exact credential pairs are being sprayed?
-- @uses      GROUP BY, joins
--
-- GROUP BY la.cred_id, not (username, password): the pair already has a
-- single integer identity in `credentials`, so grouping on it compares
-- 4-byte integers instead of two variable-length strings. That integer
-- identity is one of the main reasons the credentials table exists.
SELECT  cr.username,
        cr.password,
        COUNT(*)                        AS attempts,
        COUNT(DISTINCT s.source_id)     AS distinct_ips,
        SUM(la.success)                 AS successes
FROM        login_attempts AS la
JOIN        credentials    AS cr ON cr.cred_id    = la.cred_id
JOIN        sessions       AS s  ON s.session_pk  = la.session_pk
GROUP BY    la.cred_id, cr.username, cr.password
ORDER BY    attempts DESC, cr.username, cr.password;

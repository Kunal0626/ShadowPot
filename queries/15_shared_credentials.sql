-- @name      shared_credentials
-- @title     Credentials tried from many different addresses
-- @question  Which credential pairs are shared across a botnet rather than
--            belonging to one host's own wordlist?
-- @uses      GROUP BY ... HAVING, joins
--
-- One credential pair arriving from many unrelated addresses means those
-- hosts are working from a common list -- the clearest botnet signal this
-- dataset can produce without any external intelligence.
--
-- The threshold of 5 distinct addresses is arbitrary and deliberately
-- visible in the SQL rather than hidden in application code, so it can be
-- argued with. HAVING is required because the condition is on an aggregate
-- computed per group.
SELECT  cr.username,
        cr.password,
        COUNT(DISTINCT ses.source_id)   AS distinct_ips,
        COUNT(*)                        AS attempts,
        COUNT(DISTINCT ses.session_pk)  AS sessions
FROM        login_attempts AS la
JOIN        credentials    AS cr  ON cr.cred_id   = la.cred_id
JOIN        sessions       AS ses ON ses.session_pk = la.session_pk
GROUP BY    la.cred_id, cr.username, cr.password
HAVING      COUNT(DISTINCT ses.source_id) >= 5
ORDER BY    distinct_ips DESC, attempts DESC, cr.username;

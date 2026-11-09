-- @name      successful_credentials
-- @title     Credentials that were accepted
-- @question  Which credentials got in, and when?
-- @uses      view, GROUP BY
--
-- In a honeypot every success is staged: Cowrie accepts whatever its userdb
-- is configured to accept. So this measures WHICH staged credential the
-- attackers found, not that anything was really compromised. The report says
-- so, because "attackers successfully logged in" would otherwise read as a
-- breach.
SELECT  auth_method,
        username,
        secret,
        COUNT(*)    AS successes,
        MIN(ts)     AS first_success,
        MAX(ts)     AS last_success
FROM        v_login_attempts
WHERE       success = 1
GROUP BY    auth_method, username, secret
ORDER BY    successes DESC, username, secret;

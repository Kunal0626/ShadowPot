-- @name      top_passwords
-- @title     Most-tried passwords
-- @question  Which passwords are in the dictionaries attacking this host?
-- @uses      view, GROUP BY
--
-- Password attempts only. A public-key attempt has no password at all, and
-- v_login_attempts puts the key fingerprint in `secret` for those, so mixing
-- them in would count fingerprints as passwords.
--
-- The empty password is real data and appears as ''. It is one of the most
-- commonly attempted values, which is exactly why the schema could not use
-- '' as a "no password offered" sentinel.
SELECT  secret                      AS password,
        COUNT(*)                    AS attempts,
        COUNT(DISTINCT session_pk)  AS sessions,
        SUM(success)                AS successes
FROM        v_login_attempts
WHERE       auth_method = 'password'
GROUP BY    secret
ORDER BY    attempts DESC, password;

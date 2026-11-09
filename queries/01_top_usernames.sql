-- @name      top_usernames
-- @title     Most-tried usernames
-- @question  Which account names do attackers guess most often?
-- @uses      view, GROUP BY
--
-- Counts BOTH password and public-key attempts, because a username is tried
-- either way and the question is about the account name, not the method.
-- v_login_attempts flattens login_attempts' exclusive arc so this does not
-- have to repeat the double LEFT JOIN.
SELECT  username,
        COUNT(*)                    AS attempts,
        COUNT(DISTINCT session_pk)  AS sessions,
        SUM(success)                AS successes
FROM        v_login_attempts
GROUP BY    username
ORDER BY    attempts DESC, username;

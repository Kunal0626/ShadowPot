-- @name      first_commands
-- @title     The first command of a session
-- @question  What does an attacker do in the first second after getting a shell?
-- @uses      view, window function (inside the view), GROUP BY
--
-- The first command is the most diagnostic single field in the dataset: it is
-- the start of a payload script, before anything has had a chance to fail.
--
-- `seq` is not stored anywhere. Nothing in a Cowrie event carries a sequence
-- number, so v_session_commands derives it with
--     ROW_NUMBER() OVER (PARTITION BY session_pk ORDER BY ts, command_id)
-- and this query just asks for seq = 1. See docs/NORMALIZATION.md section 6.2
-- for why it is computed rather than stored, and docs/INDEXES.md for the
-- measurement of what that costs.
SELECT  input                       AS first_command,
        COUNT(*)                    AS sessions,
        SUM(1 - implemented)        AS times_unimplemented
FROM        v_session_commands
WHERE       seq = 1
GROUP BY    input
ORDER BY    sessions DESC, first_command;

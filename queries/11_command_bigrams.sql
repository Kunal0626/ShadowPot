-- @name      command_bigrams
-- @title     Which command follows which
-- @question  What are the recurring command sequences, as opposed to popular
--            single commands?
-- @uses      CTE, window function (LEAD), GROUP BY
--
-- LEAD pulls the next row's value into the current row, within one session,
-- in timestamp order. Pairing each command with its successor turns a bag of
-- commands into the shape of a script.
--
-- The alternative is a self-join on (session_pk, seq) and (session_pk,
-- seq + 1), which needs the derived seq materialized and reads the table
-- twice. LEAD does it in one ordered pass.
WITH sequenced AS (
    SELECT  session_pk,
            ts,
            input,
            LEAD(input) OVER (PARTITION BY session_pk
                              ORDER BY ts, command_id) AS next_input
    FROM    commands
)
SELECT  input                       AS first_command,
        next_input                  AS second_command,
        COUNT(*)                    AS occurrences,
        COUNT(DISTINCT session_pk)  AS sessions
FROM        sequenced
WHERE       next_input IS NOT NULL
GROUP BY    input, next_input
ORDER BY    occurrences DESC, first_command, second_command;

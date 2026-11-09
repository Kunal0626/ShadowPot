-- @name      top_commands
-- @title     Most-run commands
-- @question  What are attackers actually trying to do once inside?
-- @uses      GROUP BY
--
-- times_unimplemented counts cowrie.command.failed, which means the emulated
-- shell has no such command -- NOT that the command ran and returned
-- non-zero. A high count against one command is as much a finding about
-- Cowrie's emulation gaps as about the attacker, and it is how attackers
-- fingerprint a honeypot.
SELECT  input,
        COUNT(*)                    AS times_run,
        COUNT(DISTINCT session_pk)  AS sessions,
        SUM(1 - implemented)        AS times_unimplemented
FROM        commands
GROUP BY    input
ORDER BY    times_run DESC, input;

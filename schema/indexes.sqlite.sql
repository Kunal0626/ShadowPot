-- ShadowPot indexes (SQLite) -- every one measured, none assumed.
--
-- The measurements that justify these, and the measurements that rejected
-- three other candidates, are in docs/INDEXES.md. Re-run
-- tools/bench_indexes.py to regenerate that document; do not edit it by hand.
--
-- These live in a separate file from schema.sqlite.sql on purpose. The schema
-- ships no index beyond those implied by PRIMARY KEY and UNIQUE, so the
-- before/after benchmark starts from a genuinely unindexed baseline. Mixing
-- them into one file would make that measurement impossible to repeat.
--
-- Benchmarked at roughly 11,000 sessions / 95,000 login attempts / 16,000
-- commands. At the default 7-day sample size (around 600 sessions) none of
-- this is measurable: SQLite reads those tables in under a millisecond.
-- Scale is part of the result, which is why docs/INDEXES.md prints the row
-- counts beside every number.
--
-- NO SPEEDUP FIGURES ARE QUOTED IN THIS FILE, on purpose. `make bench`
-- regenerates docs/INDEXES.md, and a number copied into a second place
-- drifts away from the measurement that produced it -- which is how
-- documentation starts lying. docs/INDEXES.md is authoritative; this file
-- records only which queries use each index and why, which is stable.
--
-- The effects at this scale are in the 1.1x to 1.2x range and vary run to
-- run, because the absolute times are tens of milliseconds and the planner's
-- choices depend on the statistics ANALYZE happens to have collected. The
-- PLAN CHANGE from scan to search is the robust signal; the timing is
-- supporting evidence, not proof.

-- Used by three queries, more than any other candidate, and a result that
-- CONTRADICTED the prediction written into the benchmark tool.
--
-- The expectation was that this index would be redundant, because
-- login_attempts already has UNIQUE(session_pk, ts) and session_pk is that
-- index's leading column, so it can serve a lookup on session_pk alone. The
-- planner disagreed, and the reason is width: this index stores one integer
-- per row where the UNIQUE index stores an integer plus a 27-character
-- timestamp. For a join that needs only session_pk, the narrow index fits far
-- more rows per page and therefore reads far fewer pages.
--
-- Worth keeping as a reminder that "a prefix of an existing index covers it"
-- is a statement about correctness, not about cost.
CREATE INDEX IF NOT EXISTS idx_login_attempts_session
    ON login_attempts (session_pk);

-- Used by two queries (03 top credential pairs, 15 shared credentials), which
-- both GROUP BY cred_id. The plan change from scan to search is real, and the
-- benefit grows with the attempt count -- the column that grows fastest in a
-- real deployment, since every brute-force guess adds a row.
CREATE INDEX IF NOT EXISTS idx_login_attempts_cred
    ON login_attempts (cred_id);

-- Used by 06 repeat_offenders. sessions is joined or grouped by source_id in
-- four queries, but only one changed plan: the others read every session row
-- regardless, so ordering buys them nothing.
CREATE INDEX IF NOT EXISTS idx_sessions_source
    ON sessions (source_id);

-- Used by 10 top_commands. Grouping by a text column benefits from an index
-- that already holds it in sorted order, which removes the sort.
CREATE INDEX IF NOT EXISTS idx_commands_input
    ON commands (input);

-- ---------------------------------------------------------------------------
-- DELIBERATELY NOT CREATED. Each of these was created, measured alone, and
-- used by no query plan. They are listed so that the decision is visible
-- rather than looking like an oversight:
--
--   login_attempts(keycred_id)  public-key attempts are a small fraction of
--                               the table, so the planner prefers a scan
--   sessions(start_ts)          the day and hour queries read every session
--                               anyway, so ordering buys nothing
--   file_transfers(sha256)      the table is small enough that the join to
--                               artifacts is cheaper as a scan
--
-- Re-measure before adding any of them. On a real deployment with a very
-- different shape -- far more public-key attempts, or far more file
-- transfers -- the answers could change, and the point of this file is that
-- each line in it has a number behind it.
-- ---------------------------------------------------------------------------

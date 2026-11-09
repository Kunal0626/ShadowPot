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
-- Benchmarked at 11,318 sessions / 90,000+ login attempts / 16,026 commands.
-- At the default 7-day sample size (601 sessions) none of this is measurable:
-- SQLite reads those tables in under a millisecond. Scale is part of the
-- result, which is why docs/INDEXES.md prints the row counts beside every
-- number.

-- Used by 3 queries, best measured speedup 1.43x -- the largest of any
-- candidate, and a result that CONTRADICTED the prediction written into the
-- benchmark tool.
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

-- Used by 2 queries (03 top credential pairs, 15 shared credentials), which
-- both GROUP BY cred_id. Measured speedup is only 1.05x and that is close to
-- noise at this scale, but the plan change from scan to search is real and
-- the benefit grows with the attempt count, which is the column that grows
-- fastest in a real deployment.
CREATE INDEX IF NOT EXISTS idx_login_attempts_cred
    ON login_attempts (cred_id);

-- Used by 06 repeat_offenders, 1.12x. sessions is joined or grouped by
-- source_id in four queries; only one of them changed plan, because the
-- others read the whole table anyway.
CREATE INDEX IF NOT EXISTS idx_sessions_source
    ON sessions (source_id);

-- Used by 10 top_commands, 1.16x. Grouping by a text column benefits from an
-- index that already holds it in sorted order, which removes the sort.
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

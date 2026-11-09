-- ShadowPot schema (SQLite dialect) -- schema_version 2
--
-- Design rationale, the full 1NF/2NF/3NF walk and the ER diagram live in
-- docs/NORMALIZATION.md. Field-level provenance for every column sourced from
-- a Cowrie event lives in docs/LOG_FORMAT.md. This file carries only the
-- reasoning you need while reading the DDL itself.
--
-- Three conventions used throughout:
--
--  1. STRICT tables. Requires SQLite >= 3.37.
--
--     Be precise about what this buys, because it is easy to overstate: a
--     STRICT column does NOT demand an exact type. It attempts a LOSSLESS
--     conversion and raises SQLITE_CONSTRAINT_DATATYPE only when one is not
--     possible. Measured against an INTEGER column:
--         '2222'   -> accepted, stored as integer 2222
--         2222.0   -> accepted, stored as integer 2222
--         '22.5'   -> REJECTED, "cannot store REAL value in INTEGER column"
--         2222.5   -> REJECTED (lossy)
--         ''       -> REJECTED
--         'abc'    -> REJECTED
--
--     So it will not catch a parser that stringifies a port number, but it
--     will catch one that puts a timestamp, an empty string or a fractional
--     value where an integer belongs. That is still worth having: without
--     STRICT, every one of those is stored verbatim and silently poisons
--     comparisons and SUM/AVG downstream. The loader does its own validation
--     on top; this is the backstop, not the only guard.
--
--  2. Timestamps are TEXT in exactly one canonical form:
--     YYYY-MM-DDTHH:MM:SS.ffffffZ
--     SQLite has no date type, and ISO-8601 in this form sorts
--     lexicographically in chronological order, so ORDER BY ts is correct
--     without any conversion. The CHECK constraints below enforce the form.
--     This is not pedantry. Cowrie emits `...+0000` (no colon) whenever TZ is
--     not UTC, and SQLite's date functions return NULL for that form while
--     happily storing it as text. Measured (SQLite 3.50.4, Python stdlib):
--         date('2026-11-06T14:22:31.123456Z')      -> '2026-11-06'
--         date('2026-11-06T14:22:31.123456+00:00') -> '2026-11-06'
--         date('2026-11-06T14:22:31.123456+0000')  -> NULL
--
--     The failure mode is worse than an error or an empty result. NULL
--     propagates, so a mis-canonicalized load does not make the
--     sessions-per-day query return nothing -- it makes it return ONE row
--     with a NULL date and the entire row count collapsed into it:
--         SELECT date(ts), COUNT(*) ... GROUP BY date(ts)  ->  [(None, 2)]
--     That is a plausible-looking wrong answer, which is the kind most
--     likely to end up on a resume. The CHECK makes it an insert failure.
--
--  3. No derived data is stored, and no indexes beyond those implied by
--     PRIMARY KEY and UNIQUE exist yet. Phase 5 adds indexes one at a time,
--     each justified by an EXPLAIN QUERY PLAN before/after recorded in
--     docs/INDEXES.md. Starting with none makes that measurement honest.

PRAGMA foreign_keys = ON;   -- must be re-issued on EVERY connection; SQLite
                            -- defaults it OFF for backward compatibility, so
                            -- shadowpot/db.py sets it at connect time.

-- ===========================================================================
-- DIMENSIONS: things that repeat across many events.
-- Each exists to remove a repeating group, and each has a UNIQUE natural key
-- on NOT NULL columns so that INSERT OR IGNORE is a safe no-op on re-ingest.
-- ===========================================================================

-- A honeypot instance. Cowrie derives `sensor` from [honeypot] sensor_name,
-- defaulting to the hostname.
--
-- This table exists for a specific reason, not for symmetry: Cowrie session ids
-- are generated per process as uuid.uuid4().hex[:12], so they are unique within
-- one sensor and NOT globally unique. Two honeypots can mint the same id
-- independently. The correct natural key for a connection is therefore
-- (sensor, session), which is what sessions.UNIQUE enforces below.
CREATE TABLE IF NOT EXISTS sensors (
    sensor_id   INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE
                        CHECK (length(name) BETWEEN 1 AND 255)
) STRICT;

-- An attacker IP address.
--
-- Surrogate integer key rather than the IP as PRIMARY KEY: every fact table
-- joins back to here, and a 4-8 byte integer FK keeps those indexes far
-- narrower than a 45-character IPv6 string. The cost is one extra join, which
-- is cheap and indexed.
--
-- The loader canonicalizes through Python's ipaddress module before insert, so
-- ::1 and 0:0:0:0:0:0:0:1 cannot become two rows for one host.
--
-- first_seen/last_seen deliberately do NOT live here. They are derivable from
-- sessions, so storing them would be a maintained aggregate rather than a
-- fact: exactly the redundancy normalization exists to remove. See
-- v_source_activity below.
CREATE TABLE IF NOT EXISTS sources (
    source_id   INTEGER PRIMARY KEY,
    ip          TEXT    NOT NULL UNIQUE
                        CHECK (length(ip) BETWEEN 3 AND 45),
    ip_version  INTEGER NOT NULL
                        CHECK (ip_version IN (4, 6))
) STRICT;

-- The SSH client identification banner, from cowrie.client.version.
--
-- The Cowrie field is `version`, not `client_version`. One botnet produces
-- thousands of sessions carrying one byte-identical banner string, which is
-- the whole argument for a dimension table: store the string once, join by
-- integer.
CREATE TABLE IF NOT EXISTS clients (
    client_id   INTEGER PRIMARY KEY,
    version     TEXT    NOT NULL UNIQUE
                        CHECK (length(version) BETWEEN 1 AND 512)
) STRICT;

-- A HASSH client fingerprint, from cowrie.client.kex.
--
-- This table is the single most interesting normalization step in the schema,
-- so the reasoning is worth stating precisely.
--
-- HASSH is the MD5 of four semicolon-joined algorithm lists the client offers:
--     kex_algorithms ; encryption_c2s ; mac_c2s ; compression_c2s
-- Cowrie hands us that exact joined string as `hasshAlgorithms`. Therefore:
--
--     hassh -> hassh_algorithms          (a true functional dependency)
--
-- If hassh and hassh_algorithms both sat on `sessions`, hassh_algorithms would
-- depend on hassh rather than on the session: a transitive dependency, and a
-- 3NF violation. Worse, if they sat in a `clients` table keyed on
-- (version, hassh), hassh_algorithms would depend on only PART of that key: a
-- partial dependency, and a 2NF violation. Splitting it out fixes both.
--
-- Note which fields are NOT here. cowrie.client.kex also reports `keyAlgs`
-- (host key algorithms) and `langCS` (languages), and those are NOT inputs to
-- the HASSH digest, so hassh does NOT determine them. They are properties of
-- the session's KEXINIT and live on `sessions`. Getting this wrong is the
-- easy mistake: it looks like all eight kex fields belong together.
--
-- The four component lists are not stored separately because they are
-- recoverable by splitting hassh_algorithms on ';'. Storing them too would be
-- straightforward redundancy.
CREATE TABLE IF NOT EXISTS kex_fingerprints (
    hassh               TEXT PRIMARY KEY
                             -- HASSH is an MD5 digest: 32 lowercase hex chars.
                             CHECK (length(hassh) = 32
                                    AND hassh NOT GLOB '*[^0-9a-f]*'),
    hassh_algorithms    TEXT NOT NULL
) STRICT;

-- A (username, password) pair that was tried. Password auth only.
--
-- This is the table the brief asks about: "why is credentials its own table?"
-- Answer: without it, every login_attempts row repeats the username and
-- password strings. 50,000 attempts of root/123456 store that pair 50,000
-- times, and correcting a mis-parsed password would mean an UPDATE across
-- 50,000 rows instead of one -- the classic update anomaly.
--
-- Both columns are NOT NULL, and that is load-bearing. Cowrie omits `password`
-- entirely for public-key attempts, so the obvious design -- one credentials
-- table with a nullable password -- breaks silently: SQL treats NULLs as
-- DISTINCT inside a UNIQUE constraint, so UNIQUE(username, password) does not
-- deduplicate NULL-password rows at all. Measured on SQLite 3.51.0: inserting
-- ('root', NULL) three times into a table with UNIQUE(u,p) yields three rows.
--
-- Public-key attempts are therefore modelled separately, in ssh_keys and
-- key_credentials, and login_attempts points at exactly one of the two.
CREATE TABLE IF NOT EXISTS credentials (
    cred_id     INTEGER PRIMARY KEY,
    username    TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    UNIQUE (username, password)
) STRICT;

-- An SSH public key Cowrie was offered, from the fingerprint/key/type fields
-- on cowrie.login.* and cowrie.client.fingerprint.
--
-- A fingerprint is a hash of the key, so fingerprint -> key_type, key_blob.
-- That dependency is why this is its own table rather than three more columns
-- on key_credentials, where key_type and key_blob would depend on only part of
-- the (username, fingerprint) key.
CREATE TABLE IF NOT EXISTS ssh_keys (
    fingerprint TEXT PRIMARY KEY
                     CHECK (length(fingerprint) BETWEEN 1 AND 255),
    key_type    TEXT,        -- e.g. 'ssh-rsa'; absent in some Cowrie versions
    key_blob    TEXT         -- OpenSSH base64 form; can be several KB
) STRICT;

-- A (username, public key) pair that was tried. The public-key counterpart of
-- `credentials`, and the other half of login_attempts' exclusive arc.
CREATE TABLE IF NOT EXISTS key_credentials (
    keycred_id  INTEGER PRIMARY KEY,
    username    TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL REFERENCES ssh_keys(fingerprint),
    UNIQUE (username, fingerprint)
) STRICT;

-- A file that entered or left the honeypot, identified by content hash.
--
-- Cowrie stores a captured file at a path named after its checksum, which
-- means sha256 -> outfile. Keeping `outfile` on file_transfers would make it
-- transitively dependent on the hash rather than on the transfer, so it lives
-- here with the hash that determines it.
--
-- Caveat recorded honestly: outfile is {download_path}/{shasum}, and
-- download_path is per-deployment configuration. The dependency holds within
-- one sensor's data, which is ShadowPot's stated scope. Merging two sensors
-- with different download_path settings would break it.
--
-- outfile is retained rather than dropped as pure redundancy because it is the
-- real path on the honeypot box: it is what you type to go inspect the
-- captured sample during a Part B deployment.
CREATE TABLE IF NOT EXISTS artifacts (
    sha256      TEXT PRIMARY KEY
                     CHECK (length(sha256) = 64
                            AND sha256 NOT GLOB '*[^0-9a-f]*'),
    outfile     TEXT
) STRICT;

-- ===========================================================================
-- THE HUB: one row per connection.
-- ===========================================================================

-- A single attacker connection, from cowrie.session.connect onward.
--
-- Columns are filled in by several different events over the life of the
-- session: connect supplies the addressing, cowrie.client.version supplies
-- client_id, cowrie.client.kex supplies hassh/key_algs/lang_cs, and
-- cowrie.session.closed supplies end_ts/duration_ms. The loader therefore
-- UPSERTs this row rather than inserting it once, and every one of those
-- UPDATEs is idempotent.
--
-- A session row may legitimately be created by an event OTHER than connect:
-- with daily log rotation a session that spans midnight has its connect in
-- yesterday's file, which may have been rotated away before we ever ingested
-- it. Such a session gets a row with NULL start_ts and a source resolved from
-- the event's own src_ip. That is a normal data condition, not an error.
CREATE TABLE IF NOT EXISTS sessions (
    session_pk          INTEGER PRIMARY KEY,

    sensor_id           INTEGER NOT NULL REFERENCES sensors(sensor_id),

    -- Cowrie's own id: uuid.uuid4().hex[:12], so 12 lowercase hex chars today.
    -- The CHECK is deliberately loose (hex, 8-64 chars) rather than
    -- length = 12, because older Cowrie releases used a different width and
    -- uppercase hex, and this schema must be able to load archived logs.
    -- Cowrie's own docs/sql/mysql.sql still declares char(32), which the
    -- current code has not produced for years: a cautionary example of a
    -- constraint that outlived its fact.
    cowrie_session_id   TEXT    NOT NULL
                                CHECK (length(cowrie_session_id) BETWEEN 8 AND 64
                                       AND cowrie_session_id NOT GLOB '*[^0-9a-fA-F]*'),

    source_id           INTEGER NOT NULL REFERENCES sources(source_id),
    protocol            TEXT             CHECK (protocol IS NULL
                                                OR protocol IN ('ssh', 'telnet')),
    src_port            INTEGER          CHECK (src_port IS NULL
                                                OR src_port BETWEEN 0 AND 65535),
    dst_ip              TEXT,
    dst_port            INTEGER          CHECK (dst_port IS NULL
                                                OR dst_port BETWEEN 0 AND 65535),

    client_id           INTEGER          REFERENCES clients(client_id),
    hassh               TEXT             REFERENCES kex_fingerprints(hassh),

    -- From cowrie.client.kex, and NOT determined by hassh (they are not inputs
    -- to the HASSH digest). See the kex_fingerprints comment.
    key_algs            TEXT,
    lang_cs             TEXT,

    -- Canonical UTC ISO-8601 with microseconds and a literal Z.
    start_ts            TEXT             CHECK (start_ts IS NULL OR start_ts GLOB
                                  '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    end_ts              TEXT             CHECK (end_ts IS NULL OR end_ts GLOB
                                  '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),

    -- Integer milliseconds, as reported by Cowrie:
    --     duration_ms = round((time.time() - self.startTime) * 1000)
    -- The old `duration` field (string for some transports, float for others)
    -- was removed upstream in release 3.0.4. The loader accepts both and
    -- normalizes to this column.
    --
    -- end_ts and duration_ms are two INDEPENDENT observations, not a stored
    -- derivation: end_ts is the session.closed event's timestamp, while
    -- duration_ms is measured from Cowrie's own connection start. They will
    -- differ by a few milliseconds. Analytics use duration_ms, because it is
    -- the honeypot's own measurement; end_ts IS NULL is the useful signal that
    -- a session never closed within the data we hold.
    duration_ms         INTEGER          CHECK (duration_ms IS NULL
                                                OR duration_ms >= 0),

    -- Marks a session loaded from tools/gen_sample_logs.py output.
    --
    -- The intended workflow keeps synthetic and real data in separate database
    -- files, but a per-session flag means a database that mixes them is
    -- DETECTABLE. Without it, one careless `make load` would turn the numbers
    -- on a resume into fiction with no way to tell. report.py refuses to print
    -- a clean report when any synthetic session is present.
    is_synthetic        INTEGER NOT NULL DEFAULT 0
                                CHECK (is_synthetic IN (0, 1)),

    -- The real natural key. See the sensors comment for why it is not
    -- cowrie_session_id alone.
    UNIQUE (sensor_id, cowrie_session_id)
) STRICT;

-- ===========================================================================
-- FACTS: one row per logged event.
--
-- Every fact table carries UNIQUE (session_pk, ts). That is the natural key
-- that makes re-ingestion a no-op under INSERT OR IGNORE, and it rests on one
-- stated assumption: no two events in the same session share a microsecond.
-- Cowrie timestamps have microsecond resolution and each event costs a write
-- and a flush, so a collision is not realistically reachable -- but it is an
-- assumption, not a guarantee, which is why ingested_lines exists as a second,
-- assumption-free layer of defence.
-- ===========================================================================

-- One authentication attempt.
--
-- The exclusive arc: exactly one of cred_id (password attempt) or keycred_id
-- (public-key attempt) is non-NULL, enforced by CHECK. This is what replaces
-- the brief's single credentials FK, and it is the structural answer to
-- Cowrie's optional `password` field.
--
-- Why not one nullable-password credentials table? Because UNIQUE would stop
-- deduplicating (NULLs are distinct). Why not a sentinel like ''? Because the
-- empty password is itself one of the most commonly attempted passwords, so ''
-- would be ambiguous between "no password offered" and "empty password
-- offered". The arc keeps both sides NOT NULL and keeps the meaning exact.
CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id  INTEGER PRIMARY KEY,
    session_pk  INTEGER NOT NULL REFERENCES sessions(session_pk),
    ts          TEXT    NOT NULL CHECK (ts GLOB
                                  '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    success     INTEGER NOT NULL CHECK (success IN (0, 1)),

    cred_id     INTEGER          REFERENCES credentials(cred_id),
    keycred_id  INTEGER          REFERENCES key_credentials(keycred_id),

    -- Exactly one arc populated. '<>' on two IS NULL tests is XOR.
    CHECK ((cred_id IS NULL) <> (keycred_id IS NULL)),

    UNIQUE (session_pk, ts)
) STRICT;

-- One command line the attacker submitted.
--
-- The Cowrie field is `input`, not `command`. There is deliberately NO stored
-- `seq` column, although the brief suggests one. Nothing in the Cowrie event
-- carries a sequence number, so seq would be data ShadowPot derives from
-- arrival order -- i.e. stored derived data, the same thing rejected for
-- sources.first_seen. It is computed instead by
--     ROW_NUMBER() OVER (PARTITION BY session_pk ORDER BY ts, command_id)
-- and exposed under the name `seq` by v_session_commands below. command_id
-- breaks ties in file arrival order.
--
-- The trade-off is real and will be measured, not assumed: "most common first
-- command" is an index seek against a stored seq but a windowed scan against
-- the view. If Phase 5's EXPLAIN QUERY PLAN shows the window function is too
-- slow at the data sizes we actually reach, seq gets materialized and the
-- measurement that justified it goes in docs/INDEXES.md.
CREATE TABLE IF NOT EXISTS commands (
    command_id  INTEGER PRIMARY KEY,
    session_pk  INTEGER NOT NULL REFERENCES sessions(session_pk),
    ts          TEXT    NOT NULL CHECK (ts GLOB
                                  '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    input       TEXT    NOT NULL,

    -- Present only when the line was fed to a running command's stdin;
    -- absent (NULL) for an ordinary shell command line.
    realm       TEXT,

    -- 1 for cowrie.command.input, 0 for cowrie.command.failed.
    -- Named `implemented`, not `success`: cowrie.command.failed means the
    -- emulated shell does not implement that command, which is not the same
    -- as a command that ran and returned non-zero. Cowrie's own schema calls
    -- this column `success` and it misleads every reader.
    implemented INTEGER NOT NULL CHECK (implemented IN (0, 1)),

    UNIQUE (session_pk, ts)
) STRICT;

-- One file movement into or out of the honeypot.
--
-- One table with a `direction` discriminator rather than separate downloads
-- and uploads tables. cowrie.session.file_download and
-- cowrie.session.file_upload are the same shape and differ in exactly two
-- fields; two tables would force a UNION into every "what files moved" query
-- for no modelling benefit.
--
-- url is NULLABLE, and that is a correction to the brief, which has it
-- NOT NULL. Cowrie fires file_download for stdin captures and shell
-- redirects too, and those have no URL at all. file_upload never has one.
CREATE TABLE IF NOT EXISTS file_transfers (
    transfer_id  INTEGER PRIMARY KEY,
    session_pk   INTEGER NOT NULL REFERENCES sessions(session_pk),
    ts           TEXT    NOT NULL CHECK (ts GLOB
                                  '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    direction    TEXT    NOT NULL CHECK (direction IN ('download', 'upload')),

    url          TEXT,        -- download only, and absent for stdin/redirect
    filename     TEXT,        -- upload only
    destfile     TEXT,        -- path the attacker wrote to, where applicable
    sha256       TEXT             REFERENCES artifacts(sha256),
    is_duplicate INTEGER          CHECK (is_duplicate IS NULL
                                         OR is_duplicate IN (0, 1)),

    UNIQUE (session_pk, ts)
) STRICT;

-- ===========================================================================
-- OPERATIONAL: bookkeeping, not attacker data.
-- Kept in the same database so that one file is the whole state of the
-- pipeline and a cron run has nowhere else to look.
-- ===========================================================================

-- Schema version and database-level flags.
-- NOTE: the columns are meta_key/meta_value, not key/value. `key` is a
-- reserved word in MySQL, and keeping one column name across both dialects is
-- worth more than the nicer spelling.
CREATE TABLE IF NOT EXISTS db_meta (
    meta_key    TEXT PRIMARY KEY,
    meta_value  TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO db_meta(meta_key, meta_value) VALUES ('schema_version', '2');

-- The idempotency ledger: the SHA-256 of every raw log line already applied.
--
-- The fact tables' UNIQUE (session_pk, ts) keys would already make
-- re-ingestion correct, so this table is deliberate defence in depth: it is
-- the only layer that does not rest on the "no two events share a microsecond"
-- assumption. It is also what lets the loader skip a line before parsing it.
--
-- Cost, stated honestly: one row per log line, roughly 100 bytes. A 7-day
-- deployment taking 100k events costs about 10 MB. A file recorded as complete
-- in ingest_state can have its ledger rows pruned, since offset tracking
-- already prevents re-reading it; the loader does not do this yet and it is
-- listed under future work.
CREATE TABLE IF NOT EXISTS ingested_lines (
    line_sha256  TEXT PRIMARY KEY
                      CHECK (length(line_sha256) = 64
                             AND line_sha256 NOT GLOB '*[^0-9a-f]*'),
    source_file  TEXT NOT NULL,
    ingested_at  TEXT NOT NULL
) STRICT;

-- Resumable-read state, one row per log file.
--
-- Four distinct failure modes have to be distinguished, which is why this
-- holds more than the brief's (file, inode, offset):
--
--   inode changed            -> the file was rotated; this path is a new file,
--                               read from offset 0.
--   first line changed       -> the file was rewritten in place. See below.
--   size_bytes < offset      -> truncated in place (logrotate copytruncate);
--                               re-read from offset 0.
--   size_bytes == offset     -> nothing new; skip.
--   is_compressed            -> a .gz cannot be cheaply seeked, so it is
--                               treated as immutable: read once, marked
--                               complete, never re-read.
--
-- Storing only an offset -- the obvious design -- silently loses data on
-- rotation and re-reads everything on truncation.
--
-- head_line_sha256 exists because inode, size and offset together STILL
-- cannot detect one real case: a file truncated in place and rewritten to
-- the same length. The inode is unchanged, the size equals the stored
-- offset, so every other check says "nothing new" and the replacement
-- content is skipped silently and for ever. A test in tests/test_ingest.py
-- constructs exactly that, and it failed before this column existed.
--
-- The first line is hashed rather than the whole file: it never changes
-- under append (so an incremental run stays cheap) and always changes under
-- rewrite, because a new first line means a different session at a different
-- microsecond. Residual limitation, stated rather than hidden: a rewrite
-- whose first line is byte-identical to the old one is still undetectable.
CREATE TABLE IF NOT EXISTS ingest_state (
    source_file      TEXT    PRIMARY KEY,
    inode            INTEGER NOT NULL,
    size_bytes       INTEGER NOT NULL CHECK (size_bytes >= 0),
    offset_bytes     INTEGER NOT NULL CHECK (offset_bytes >= 0),
    head_line_sha256 TEXT             CHECK (head_line_sha256 IS NULL
                                             OR (length(head_line_sha256) = 64
                                                 AND head_line_sha256
                                                     NOT GLOB '*[^0-9a-f]*')),
    is_compressed    INTEGER NOT NULL DEFAULT 0 CHECK (is_compressed IN (0, 1)),
    is_complete      INTEGER NOT NULL DEFAULT 0 CHECK (is_complete IN (0, 1)),
    last_ingest_at   TEXT    NOT NULL
) STRICT;

-- One row per loader run. This is the audit trail behind every number that
-- reaches the README: it records what was read and what was thrown away, so a
-- claim like "ingested N events" is checkable rather than asserted.
CREATE TABLE IF NOT EXISTS ingest_runs (
    run_id             INTEGER PRIMARY KEY,
    started_at         TEXT    NOT NULL,
    finished_at        TEXT,
    files_scanned      INTEGER NOT NULL DEFAULT 0,
    lines_read         INTEGER NOT NULL DEFAULT 0,
    lines_applied      INTEGER NOT NULL DEFAULT 0,
    lines_duplicate    INTEGER NOT NULL DEFAULT 0,
    lines_malformed    INTEGER NOT NULL DEFAULT 0,
    events_unknown     INTEGER NOT NULL DEFAULT 0,
    events_incomplete  INTEGER NOT NULL DEFAULT 0
) STRICT;

-- ===========================================================================
-- VIEWS
-- ===========================================================================

-- Replaces the sources.first_seen / sources.last_seen columns the brief
-- suggests. Those are aggregates over sessions, so computing them here keeps
-- exactly one copy of the truth.
CREATE VIEW IF NOT EXISTS v_source_activity AS
SELECT  s.source_id,
        s.ip,
        s.ip_version,
        COUNT(*)                                   AS session_count,
        MIN(ses.start_ts)                          AS first_seen,
        MAX(COALESCE(ses.end_ts, ses.start_ts))    AS last_seen,
        COUNT(DISTINCT substr(ses.start_ts, 1, 10)) AS active_days
FROM        sources  AS s
JOIN        sessions AS ses ON ses.source_id = s.source_id
GROUP BY    s.source_id, s.ip, s.ip_version;

-- Supplies the `seq` the commands table deliberately does not store.
-- substr(ts,1,10) is the UTC date: valid only because ts is canonical
-- ISO-8601, which the CHECK constraints guarantee.
CREATE VIEW IF NOT EXISTS v_session_commands AS
SELECT  c.command_id,
        c.session_pk,
        ROW_NUMBER() OVER (PARTITION BY c.session_pk
                           ORDER BY c.ts, c.command_id) AS seq,
        c.ts,
        c.input,
        c.realm,
        c.implemented
FROM    commands AS c;

-- Flattens login_attempts' exclusive arc back into one readable shape, so
-- credential analytics do not each have to repeat the double LEFT JOIN.
-- `secret` is the password for password attempts and the key fingerprint for
-- public-key attempts; auth_method says which, so the two are never confused.
CREATE VIEW IF NOT EXISTS v_login_attempts AS
SELECT  la.attempt_id,
        la.session_pk,
        la.ts,
        la.success,
        CASE WHEN la.cred_id IS NOT NULL THEN 'password' ELSE 'publickey' END
                                                  AS auth_method,
        COALESCE(cr.username, kc.username)        AS username,
        COALESCE(cr.password, kc.fingerprint)     AS secret
FROM        login_attempts  AS la
LEFT JOIN   credentials     AS cr ON cr.cred_id    = la.cred_id
LEFT JOIN   key_credentials AS kc ON kc.keycred_id = la.keycred_id;

-- ShadowPot schema (MySQL dialect) -- schema_version 2
--
-- SQLite is ShadowPot's default and canonical engine, because it needs no
-- server and ships in Python's standard library, so anyone can clone the repo
-- and run the whole pipeline. This file is the same logical model for MySQL.
--
-- Read schema/schema.sqlite.sql first. The design reasoning -- why credentials
-- is its own table, why hassh_algorithms is split out, why login_attempts has
-- an exclusive arc, why there is no stored `seq` -- is documented there and in
-- docs/NORMALIZATION.md, and is NOT repeated here. This file documents only
-- what had to change for MySQL and why.
--
-- VERIFICATION STATUS: not verified against a live server. MySQL 9.5.0 is
-- installed on the development machine but rejects connections without
-- credentials, and this project does not store database passwords. Apply and
-- check it yourself with:
--
--     mysql -u <user> -p -e "CREATE DATABASE shadowpot_test"
--     mysql -u <user> -p shadowpot_test < schema/schema.mysql.sql
--     python3 -m unittest tests.test_schema -v   # with SHADOWPOT_MYSQL_DSN set
--
-- Until that has been run, treat this file as unproven. The SQLite schema is
-- verified by tests/test_schema.py on every run.
--
-- ===========================================================================
-- Dialect differences, and the reason for each
-- ===========================================================================
--
-- 1. TIMESTAMPS. SQLite stores canonical ISO-8601 TEXT because it has no date
--    type. MySQL has DATETIME(6), which is the right type here: it is 8 bytes
--    instead of 27, it compares numerically, and MySQL's date functions take
--    it directly. The consequence is that the canonical-format CHECK
--    constraints disappear -- the column type now enforces what the CHECK used
--    to -- and the date-bucketing queries differ between dialects
--    (substr(ts,1,10) vs DATE(ts)). Those are the queries that get a
--    queries/mysql/ override.
--
--    DATETIME carries no time zone. Everything stored here is UTC, as Cowrie
--    emits it, and the loader converts before insert.
--
-- 2. COLLATION. This one changes query RESULTS, not just syntax, and it is the
--    single most important line in this file.
--
--    MySQL's default collation (utf8mb4_0900_ai_ci) is case-insensitive and
--    accent-insensitive. SQLite's default is byte-exact. Under the MySQL
--    default, UNIQUE(username, password) would treat 'root', 'Root' and 'ROOT'
--    as ONE credential, silently merging three genuinely different attacker
--    guesses -- and COUNT(DISTINCT username) would disagree between the two
--    engines for the same input data.
--
--    Attacker-supplied strings are bytes, not prose, and must never be folded.
--    Every table holding them is therefore declared COLLATE utf8mb4_bin. This
--    is not a style choice; omit it and the credential analytics are wrong.
--
-- 3. KEY LENGTHS. InnoDB caps an index key at 3072 bytes, and utf8mb4 costs
--    4 bytes per character, so any column inside a UNIQUE or PRIMARY KEY must
--    be a bounded VARCHAR rather than TEXT. The widths below are chosen to
--    stay under that cap:
--        credentials UNIQUE(username(255), password(255)) = 2040 bytes
--        clients     UNIQUE(version(512))                 = 2048 bytes
--        ingest_state PRIMARY KEY(source_file(512))       = 2048 bytes
--
--    This introduces a real limitation SQLite does not have: an attacker can
--    send a username longer than 255 characters. MySQL's default sql_mode
--    includes STRICT_TRANS_TABLES, so such a row is REJECTED with an error
--    rather than silently truncated -- which is the behaviour we want, but it
--    means the loader must catch it. In MySQL mode the loader counts those as
--    ingest_runs.events_incomplete rather than aborting the run. Columns that
--    are never indexed (commands.input, hassh_algorithms, key_blob) stay TEXT
--    and have no such limit.
--
-- 4. CHECK CONSTRAINTS. Enforced from MySQL 8.0.16 onward; silently ignored
--    before that. Hex validation uses REGEXP_LIKE where SQLite uses GLOB.
--
-- 5. No PRAGMA foreign_keys. InnoDB enforces foreign keys by default; the
--    SQLite PRAGMA exists only because SQLite defaults it off.

SET NAMES utf8mb4;

-- ===========================================================================
-- DIMENSIONS
-- ===========================================================================

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(255) NOT NULL,
    PRIMARY KEY (sensor_id),
    UNIQUE KEY uq_sensors_name (name),
    CONSTRAINT ck_sensors_name CHECK (CHAR_LENGTH(name) BETWEEN 1 AND 255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS sources (
    source_id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip          VARCHAR(45)  NOT NULL,   -- 45 = longest IPv6 text form
    ip_version  TINYINT      NOT NULL,
    PRIMARY KEY (source_id),
    UNIQUE KEY uq_sources_ip (ip),
    CONSTRAINT ck_sources_version CHECK (ip_version IN (4, 6))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS clients (
    client_id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
    version     VARCHAR(512) NOT NULL,
    PRIMARY KEY (client_id),
    UNIQUE KEY uq_clients_version (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS kex_fingerprints (
    hassh             CHAR(32) NOT NULL,   -- MD5 digest, 32 lowercase hex
    hassh_algorithms  TEXT     NOT NULL,
    PRIMARY KEY (hassh),
    CONSTRAINT ck_kex_hassh_hex CHECK (REGEXP_LIKE(hassh, '^[0-9a-f]{32}$'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS credentials (
    cred_id     INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username    VARCHAR(255) NOT NULL,
    password    VARCHAR(255) NOT NULL,
    PRIMARY KEY (cred_id),
    UNIQUE KEY uq_credentials_pair (username, password)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS ssh_keys (
    fingerprint VARCHAR(255) NOT NULL,
    key_type    VARCHAR(64),
    key_blob    TEXT,
    PRIMARY KEY (fingerprint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS key_credentials (
    keycred_id  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username    VARCHAR(255) NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,
    PRIMARY KEY (keycred_id),
    UNIQUE KEY uq_key_credentials_pair (username, fingerprint),
    CONSTRAINT fk_keycred_key FOREIGN KEY (fingerprint)
        REFERENCES ssh_keys (fingerprint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS artifacts (
    sha256      CHAR(64) NOT NULL,
    outfile     TEXT,
    PRIMARY KEY (sha256),
    CONSTRAINT ck_artifacts_sha256 CHECK (REGEXP_LIKE(sha256, '^[0-9a-f]{64}$'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- ===========================================================================
-- THE HUB
-- ===========================================================================

CREATE TABLE IF NOT EXISTS sessions (
    session_pk        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    sensor_id         INT UNSIGNED    NOT NULL,
    cowrie_session_id VARCHAR(64)     NOT NULL,
    source_id         INT UNSIGNED    NOT NULL,
    protocol          VARCHAR(8),
    src_port          INT,
    dst_ip            VARCHAR(45),
    dst_port          INT,
    client_id         INT UNSIGNED,
    hassh             CHAR(32),
    key_algs          TEXT,
    lang_cs           TEXT,
    start_ts          DATETIME(6),
    end_ts            DATETIME(6),
    duration_ms       BIGINT,
    is_synthetic      TINYINT         NOT NULL DEFAULT 0,

    PRIMARY KEY (session_pk),
    UNIQUE KEY uq_sessions_natural (sensor_id, cowrie_session_id),

    CONSTRAINT fk_sessions_sensor FOREIGN KEY (sensor_id)
        REFERENCES sensors (sensor_id),
    CONSTRAINT fk_sessions_source FOREIGN KEY (source_id)
        REFERENCES sources (source_id),
    CONSTRAINT fk_sessions_client FOREIGN KEY (client_id)
        REFERENCES clients (client_id),
    CONSTRAINT fk_sessions_hassh  FOREIGN KEY (hassh)
        REFERENCES kex_fingerprints (hassh),

    CONSTRAINT ck_sessions_sid CHECK (
        REGEXP_LIKE(cowrie_session_id, '^[0-9a-fA-F]{8,64}$')),
    CONSTRAINT ck_sessions_protocol CHECK (
        protocol IS NULL OR protocol IN ('ssh', 'telnet')),
    CONSTRAINT ck_sessions_srcport CHECK (
        src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    CONSTRAINT ck_sessions_dstport CHECK (
        dst_port IS NULL OR dst_port BETWEEN 0 AND 65535),
    CONSTRAINT ck_sessions_duration CHECK (
        duration_ms IS NULL OR duration_ms >= 0),
    CONSTRAINT ck_sessions_synthetic CHECK (is_synthetic IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- ===========================================================================
-- FACTS
-- ===========================================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_pk  BIGINT UNSIGNED NOT NULL,
    ts          DATETIME(6)     NOT NULL,
    success     TINYINT         NOT NULL,
    cred_id     INT UNSIGNED,
    keycred_id  INT UNSIGNED,

    PRIMARY KEY (attempt_id),
    UNIQUE KEY uq_login_natural (session_pk, ts),

    CONSTRAINT fk_login_session FOREIGN KEY (session_pk)
        REFERENCES sessions (session_pk),
    CONSTRAINT fk_login_cred    FOREIGN KEY (cred_id)
        REFERENCES credentials (cred_id),
    CONSTRAINT fk_login_keycred FOREIGN KEY (keycred_id)
        REFERENCES key_credentials (keycred_id),

    CONSTRAINT ck_login_success CHECK (success IN (0, 1)),
    -- The exclusive arc: exactly one of the two credential kinds.
    CONSTRAINT ck_login_arc CHECK ((cred_id IS NULL) <> (keycred_id IS NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS commands (
    command_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_pk  BIGINT UNSIGNED NOT NULL,
    ts          DATETIME(6)     NOT NULL,
    input       TEXT            NOT NULL,
    realm       VARCHAR(64),
    implemented TINYINT         NOT NULL,

    PRIMARY KEY (command_id),
    UNIQUE KEY uq_commands_natural (session_pk, ts),

    CONSTRAINT fk_commands_session FOREIGN KEY (session_pk)
        REFERENCES sessions (session_pk),
    CONSTRAINT ck_commands_implemented CHECK (implemented IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS file_transfers (
    transfer_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_pk   BIGINT UNSIGNED NOT NULL,
    ts           DATETIME(6)     NOT NULL,
    direction    VARCHAR(8)      NOT NULL,
    url          TEXT,
    filename     TEXT,
    destfile     TEXT,
    sha256       CHAR(64),
    is_duplicate TINYINT,

    PRIMARY KEY (transfer_id),
    UNIQUE KEY uq_transfers_natural (session_pk, ts),

    CONSTRAINT fk_transfers_session FOREIGN KEY (session_pk)
        REFERENCES sessions (session_pk),
    CONSTRAINT fk_transfers_artifact FOREIGN KEY (sha256)
        REFERENCES artifacts (sha256),

    CONSTRAINT ck_transfers_direction CHECK (direction IN ('download', 'upload')),
    CONSTRAINT ck_transfers_duplicate CHECK (
        is_duplicate IS NULL OR is_duplicate IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- ===========================================================================
-- OPERATIONAL
-- ===========================================================================

-- meta_key, not key: `key` is a reserved word in MySQL. The SQLite schema
-- uses the same spelling so one loader serves both.
CREATE TABLE IF NOT EXISTS db_meta (
    meta_key    VARCHAR(128) NOT NULL,
    meta_value  TEXT         NOT NULL,
    PRIMARY KEY (meta_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT IGNORE INTO db_meta (meta_key, meta_value) VALUES ('schema_version', '2');

CREATE TABLE IF NOT EXISTS ingested_lines (
    line_sha256  CHAR(64)     NOT NULL,
    source_file  VARCHAR(512) NOT NULL,
    ingested_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (line_sha256),
    CONSTRAINT ck_ingested_sha CHECK (REGEXP_LIKE(line_sha256, '^[0-9a-f]{64}$'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS ingest_state (
    source_file      VARCHAR(512) NOT NULL,
    inode            BIGINT       NOT NULL,
    size_bytes       BIGINT       NOT NULL,
    offset_bytes     BIGINT       NOT NULL,
    -- See schema.sqlite.sql for why hashing the first line is necessary:
    -- inode, size and offset cannot detect an in-place rewrite to the same
    -- length.
    head_line_sha256 CHAR(64),
    is_compressed    TINYINT      NOT NULL DEFAULT 0,
    is_complete      TINYINT      NOT NULL DEFAULT 0,
    last_ingest_at   DATETIME(6)  NOT NULL,
    PRIMARY KEY (source_file),
    CONSTRAINT ck_state_head   CHECK (head_line_sha256 IS NULL OR
        REGEXP_LIKE(head_line_sha256, '^[0-9a-f]{64}$')),
    CONSTRAINT ck_state_size   CHECK (size_bytes   >= 0),
    CONSTRAINT ck_state_offset CHECK (offset_bytes >= 0),
    CONSTRAINT ck_state_comp   CHECK (is_compressed IN (0, 1)),
    CONSTRAINT ck_state_done   CHECK (is_complete   IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS ingest_runs (
    run_id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    started_at         DATETIME(6)     NOT NULL,
    finished_at        DATETIME(6),
    files_scanned      BIGINT          NOT NULL DEFAULT 0,
    lines_read         BIGINT          NOT NULL DEFAULT 0,
    lines_applied      BIGINT          NOT NULL DEFAULT 0,
    lines_duplicate    BIGINT          NOT NULL DEFAULT 0,
    lines_malformed    BIGINT          NOT NULL DEFAULT 0,
    events_unknown     BIGINT          NOT NULL DEFAULT 0,
    events_incomplete  BIGINT          NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- ===========================================================================
-- VIEWS
--
-- These are where the dialects genuinely diverge. DATE(ts) replaces
-- substr(ts, 1, 10), because ts is a real DATETIME here rather than ISO text.
-- ===========================================================================

CREATE OR REPLACE VIEW v_source_activity AS
SELECT  s.source_id,
        s.ip,
        s.ip_version,
        COUNT(*)                                AS session_count,
        MIN(ses.start_ts)                       AS first_seen,
        MAX(COALESCE(ses.end_ts, ses.start_ts)) AS last_seen,
        COUNT(DISTINCT DATE(ses.start_ts))      AS active_days
FROM        sources  AS s
JOIN        sessions AS ses ON ses.source_id = s.source_id
GROUP BY    s.source_id, s.ip, s.ip_version;

CREATE OR REPLACE VIEW v_session_commands AS
SELECT  c.command_id,
        c.session_pk,
        ROW_NUMBER() OVER (PARTITION BY c.session_pk
                           ORDER BY c.ts, c.command_id) AS seq,
        c.ts,
        c.input,
        c.realm,
        c.implemented
FROM    commands AS c;

CREATE OR REPLACE VIEW v_login_attempts AS
SELECT  la.attempt_id,
        la.session_pk,
        la.ts,
        la.success,
        CASE WHEN la.cred_id IS NOT NULL THEN 'password' ELSE 'publickey' END
                                              AS auth_method,
        COALESCE(cr.username, kc.username)    AS username,
        COALESCE(cr.password, kc.fingerprint) AS secret
FROM        login_attempts  AS la
LEFT JOIN   credentials     AS cr ON cr.cred_id    = la.cred_id
LEFT JOIN   key_credentials AS kc ON kc.keycred_id = la.keycred_id;

"""Tests for the ShadowPot schema.

These tests are the proof that the design decisions in docs/NORMALIZATION.md
are actually enforced by the database rather than merely written down. Several
of them encode a *counterfactual*: they show that the obvious alternative
design would have been silently wrong. Those are the ones worth reading.

Run:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import pathlib
import re
import sqlite3
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SQLITE_SCHEMA = REPO_ROOT / "schema" / "schema.sqlite.sql"
MYSQL_SCHEMA = REPO_ROOT / "schema" / "schema.mysql.sql"

# A timestamp in the one canonical form the schema accepts:
# ISO-8601, UTC, microsecond precision, literal Z.
TS = "2026-11-06T14:22:31.123456Z"


def canonical(hour: int, minute: int = 0, second: int = 0, micro: int = 0) -> str:
    """Build a canonical timestamp. Keeps the tests readable."""
    return f"2026-11-06T{hour:02d}:{minute:02d}:{second:02d}.{micro:06d}Z"


class SchemaTestCase(unittest.TestCase):
    """Base: a fresh in-memory database with the schema applied."""

    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript(SQLITE_SCHEMA.read_text())
        # PRAGMA foreign_keys is a no-op inside a transaction, and
        # executescript runs inside one, so it must be set on the connection
        # afterwards. shadowpot/db.py does exactly this at connect time. This
        # is the single easiest way to end up with unenforced foreign keys.
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.addCleanup(self.conn.close)

    # -- fixtures ---------------------------------------------------------

    # The dimension fixtures are idempotent on purpose: several tests call
    # a_session() repeatedly, and a fixture that raised on the second call
    # would make a UNIQUE violation on `sensors` masquerade as the failure
    # the test was actually looking for.

    def a_sensor(self, name: str = "honeypot-1") -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO sensors(name) VALUES(?)", (name,)
        )
        return int(self.scalar(
            "SELECT sensor_id FROM sensors WHERE name=?", (name,)
        ))

    def a_source(self, ip: str = "198.51.100.7", version: int = 4) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO sources(ip, ip_version) VALUES(?, ?)",
            (ip, version),
        )
        return int(self.scalar(
            "SELECT source_id FROM sources WHERE ip=?", (ip,)
        ))

    def a_session(self, sid: str = "a1b2c3d4e5f6", **over) -> int:
        fields = {
            "sensor_id": over.pop("sensor_id", None) or self.a_sensor(),
            "cowrie_session_id": sid,
            "source_id": over.pop("source_id", None) or self.a_source(),
            "protocol": "ssh",
            "src_port": 54321,
            "dst_port": 2222,
            "start_ts": TS,
        }
        fields.update(over)
        cols = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        cur = self.conn.execute(
            f"INSERT INTO sessions({cols}) VALUES({marks})", tuple(fields.values())
        )
        return int(cur.lastrowid)

    def a_credential(self, user: str = "root", pw: str = "123456") -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO credentials(username, password) VALUES(?, ?)",
            (user, pw),
        )
        if cur.lastrowid:
            return int(cur.lastrowid)
        row = self.conn.execute(
            "SELECT cred_id FROM credentials WHERE username=? AND password=?",
            (user, pw),
        ).fetchone()
        return int(row[0])

    def scalar(self, sql: str, args: tuple = ()) -> object:
        return self.conn.execute(sql, args).fetchone()[0]


class TestSchemaShape(SchemaTestCase):
    def test_expected_objects_exist(self):
        tables = {
            r[0]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertEqual(
            tables,
            {
                # dimensions
                "sensors", "sources", "clients", "kex_fingerprints",
                "credentials", "ssh_keys", "key_credentials", "artifacts",
                # hub
                "sessions",
                # facts
                "login_attempts", "commands", "file_transfers",
                # operational
                "db_meta", "ingested_lines", "ingest_state", "ingest_runs",
            },
        )

        views = {
            r[0]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='view'"
            )
        }
        self.assertEqual(
            views,
            {"v_source_activity", "v_session_commands", "v_login_attempts"},
        )

    def test_schema_version_recorded(self):
        self.assertEqual(
            self.scalar(
                "SELECT meta_value FROM db_meta WHERE meta_key='schema_version'"
            ),
            "1",
        )

    def test_every_table_is_strict(self):
        """STRICT turns a parser bug into an insert error.

        Without it SQLite accepts '2222' as a port and every numeric
        comparison downstream is quietly wrong.
        """
        for (name, sql) in self.conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ):
            with self.subTest(table=name):
                self.assertRegex(sql, r"\)\s*STRICT\s*$", f"{name} is not STRICT")

    def test_no_handwritten_indexes_yet(self):
        """Phase 2 ships no indexes beyond those implied by PRIMARY KEY/UNIQUE.

        This is asserted, not assumed, so that Phase 5's EXPLAIN QUERY PLAN
        before/after measurements start from a genuinely unindexed baseline.
        Delete this test in Phase 5 when the measured indexes land.
        """
        explicit = [
            r[0]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND sql IS NOT NULL"
            )
        ]
        self.assertEqual(explicit, [], f"unexpected hand-written indexes: {explicit}")


class TestReferentialIntegrity(SchemaTestCase):
    def test_foreign_keys_are_enforced(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO sessions(sensor_id, cowrie_session_id, source_id) "
                "VALUES(999, 'a1b2c3d4e5f6', 1)"
            )

    def test_pragma_off_would_not_enforce(self):
        """The counterfactual: foreign keys are opt-in in SQLite.

        Documents why shadowpot/db.py must set the PRAGMA on every
        connection, not once at schema-creation time.
        """
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.execute(
            "INSERT INTO sessions(sensor_id, cowrie_session_id, source_id) "
            "VALUES(999, 'a1b2c3d4e5f6', 998)"
        )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM sessions"), 1)

    def test_file_transfer_requires_known_artifact(self):
        s = self.a_session()
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO file_transfers(session_pk, ts, direction, sha256) "
                "VALUES(?, ?, 'download', ?)",
                (s, TS, "b" * 64),
            )


class TestTimestampCanonicalForm(SchemaTestCase):
    def test_canonical_form_accepted(self):
        self.a_session(start_ts=TS)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM sessions"), 1)

    def test_cowrie_non_utc_form_is_rejected(self):
        """The measured hazard, turned into an enforced invariant.

        Cowrie emits '...+0000' (no colon) whenever TZ is not UTC, and
        SQLite's date() returns EMPTY STRING for that form while happily
        storing it as text. A load that forgot to canonicalize would make
        every sessions-per-day query return nothing, with no error anywhere.
        The CHECK constraint makes it an insert failure instead.
        """
        # First, demonstrate the hazard itself is real on this SQLite build.
        # date() yields NULL, not an error and not an empty string.
        self.assertIsNone(
            self.scalar("SELECT date('2026-11-06T14:22:31.123456+0000')")
        )
        self.assertEqual(
            self.scalar("SELECT date('2026-11-06T14:22:31.123456Z')"), "2026-11-06"
        )
        self.assertEqual(
            self.scalar("SELECT date('2026-11-06T14:22:31.123456+00:00')"),
            "2026-11-06",
            "the colon form works, which is what makes the no-colon form such "
            "an easy mistake to miss",
        )
        # And the NULL propagates into a plausible-looking wrong answer rather
        # than an empty result: one bucket, holding everything.
        self.conn.execute("CREATE TABLE demo(ts TEXT)")
        self.conn.executemany(
            "INSERT INTO demo VALUES(?)",
            [("2026-11-06T01:00:00.000000+0000",),
             ("2026-11-07T02:00:00.000000+0000",)],
        )
        self.assertEqual(
            list(self.conn.execute(
                "SELECT date(ts), COUNT(*) FROM demo GROUP BY date(ts)"
            )),
            [(None, 2)],
            "two sessions on two different days collapsed into one NULL day",
        )
        # Now: the schema refuses to store the dangerous form.
        with self.assertRaises(sqlite3.IntegrityError):
            self.a_session(start_ts="2026-11-06T14:22:31.123456+0000")

    def test_other_non_canonical_forms_rejected(self):
        for bad in (
            "2026-11-06T14:22:31Z",             # no microseconds
            "2026-11-06T14:22:31.123Z",         # milliseconds only
            "2026-11-06 14:22:31.123456Z",      # space instead of T
            "2026-11-06T14:22:31.123456",       # no zone marker
            "2026-11-06T14:22:31.123456+00:00",  # offset form, not Z
            "not a timestamp",
        ):
            with self.subTest(bad=bad), self.assertRaises(sqlite3.IntegrityError):
                self.a_session(sid="a1b2c3d4e5f6", start_ts=bad)

    def test_text_ordering_is_chronological(self):
        """Why TEXT is an acceptable timestamp type in SQLite at all."""
        s = self.a_session()
        for h in (10, 9, 11):
            self.conn.execute(
                "INSERT INTO commands(session_pk, ts, input, implemented) "
                "VALUES(?, ?, ?, 1)",
                (s, canonical(h), f"cmd at {h}"),
            )
        got = [
            r[0]
            for r in self.conn.execute(
                "SELECT input FROM commands ORDER BY ts"
            )
        ]
        self.assertEqual(got, ["cmd at 9", "cmd at 10", "cmd at 11"])


class TestCheckConstraints(SchemaTestCase):
    def test_session_id_must_be_hex(self):
        for bad in ("zzzzzzzzzzzz", "a1b2-c3d4-e5f6", "short", "a" * 65):
            with self.subTest(bad=bad), self.assertRaises(sqlite3.IntegrityError):
                self.a_session(sid=bad)

    def test_session_id_accepts_legacy_widths(self):
        """Deliberately loose: archived logs from older Cowrie used a
        different width and uppercase hex. Cowrie's own schema still
        declares char(32), which its code has not produced for years.
        """
        self.a_session(sid="A1B2C3D4E5F6A1B2C3D4C3D4E5F6A1B2")  # 32, uppercase
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM sessions"), 1)

    def test_protocol_restricted(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.a_session(protocol="gopher")

    def test_ports_in_range(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.a_session(src_port=70000)

    def test_duration_cannot_be_negative(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.a_session(duration_ms=-1)

    def test_sha256_must_be_64_lowercase_hex(self):
        for bad in ("abc", "A" * 64, "g" * 64):
            with self.subTest(bad=bad), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(
                    "INSERT INTO artifacts(sha256) VALUES(?)", (bad,)
                )

    def test_hassh_must_be_32_lowercase_hex(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO kex_fingerprints(hassh, hassh_algorithms) "
                "VALUES(?, ?)",
                ("not-an-md5", "a;b;c;d"),
            )
        self.conn.execute(
            "INSERT INTO kex_fingerprints(hassh, hassh_algorithms) VALUES(?, ?)",
            ("0" * 32, "curve25519-sha256;aes128-ctr;hmac-sha2-256;none"),
        )

    def test_transfer_direction_restricted(self):
        s = self.a_session()
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO file_transfers(session_pk, ts, direction) "
                "VALUES(?, ?, 'sideways')",
                (s, TS),
            )

    def test_strict_coerces_losslessly_and_rejects_the_rest(self):
        """Characterizes what STRICT actually does, so the schema comment
        cannot drift back into overstating it.

        STRICT is lossless-conversion-or-error, not exact-type-required.
        Numeric-looking text IS accepted and stored as an integer; anything
        that cannot convert without loss is rejected.
        """
        # Accepted, and genuinely stored as an integer.
        pk = self.a_session(src_port="2222")
        self.assertEqual(
            list(self.conn.execute(
                "SELECT src_port, typeof(src_port) FROM sessions "
                "WHERE session_pk=?", (pk,)
            )),
            [(2222, "integer")],
        )
        # Rejected: no lossless conversion exists.
        sensor, source = self.a_sensor(), self.a_source()
        for bad in ("notaport", "", "22.5", 2222.5):
            with self.subTest(bad=bad), self.assertRaisesRegex(
                sqlite3.Error, "INTEGER column"
            ):
                self.a_session(
                    sid="b2c3d4e5f6a1", sensor_id=sensor, source_id=source,
                    src_port=bad,
                )


class TestUniquenessAndIdempotence(SchemaTestCase):
    def test_credentials_deduplicate(self):
        for _ in range(3):
            self.conn.execute(
                "INSERT OR IGNORE INTO credentials(username, password) "
                "VALUES('root', '123456')"
            )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM credentials"), 1)

    def test_credentials_are_case_sensitive(self):
        """'root' and 'Root' are different guesses, not the same one.

        SQLite is byte-exact by default. MySQL's default collation is NOT,
        which is why schema.mysql.sql pins COLLATE utf8mb4_bin -- otherwise
        the two engines disagree on COUNT(DISTINCT username) for identical
        input.
        """
        for user in ("root", "Root", "ROOT"):
            self.conn.execute(
                "INSERT OR IGNORE INTO credentials(username, password) "
                "VALUES(?, 'x')",
                (user,),
            )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM credentials"), 3)

    def test_session_natural_key_is_per_sensor(self):
        """Cowrie ids are uuid4().hex[:12] generated per process, so they are
        unique within a sensor and NOT globally. Two sensors may mint the
        same id; that must be two sessions, not a collision.
        """
        s1 = self.a_sensor("honeypot-1")
        s2 = self.a_sensor("honeypot-2")
        src = self.a_source()
        for sensor in (s1, s2):
            self.conn.execute(
                "INSERT INTO sessions(sensor_id, cowrie_session_id, source_id) "
                "VALUES(?, 'a1b2c3d4e5f6', ?)",
                (sensor, src),
            )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM sessions"), 2)

        # ...but the same id twice on ONE sensor is the same session.
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO sessions(sensor_id, cowrie_session_id, source_id) "
                "VALUES(?, 'a1b2c3d4e5f6', ?)",
                (s1, src),
            )

    def test_fact_tables_reject_duplicate_session_timestamp(self):
        s = self.a_session()
        c = self.a_credential()
        self.conn.execute(
            "INSERT INTO login_attempts(session_pk, ts, success, cred_id) "
            "VALUES(?, ?, 0, ?)",
            (s, TS, c),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO login_attempts(session_pk, ts, success, cred_id) "
                "VALUES(?, ?, 0, ?)",
                (s, TS, c),
            )
        # INSERT OR IGNORE is therefore a safe no-op on re-ingest.
        self.conn.execute(
            "INSERT OR IGNORE INTO login_attempts"
            "(session_pk, ts, success, cred_id) VALUES(?, ?, 0, ?)",
            (s, TS, c),
        )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM login_attempts"), 1)


class TestExclusiveArc(SchemaTestCase):
    """login_attempts points at exactly one kind of credential.

    This is the structural answer to Cowrie's optional `password` field.
    """

    def setUp(self) -> None:
        super().setUp()
        self.session_pk = self.a_session()
        self.cred_id = self.a_credential()
        self.conn.execute(
            "INSERT INTO ssh_keys(fingerprint, key_type) "
            "VALUES('aa:bb:cc:dd:ee:ff', 'ssh-rsa')"
        )
        cur = self.conn.execute(
            "INSERT INTO key_credentials(username, fingerprint) "
            "VALUES('root', 'aa:bb:cc:dd:ee:ff')"
        )
        self.keycred_id = int(cur.lastrowid)

    def _insert(self, cred, keycred, ts=TS):
        self.conn.execute(
            "INSERT INTO login_attempts"
            "(session_pk, ts, success, cred_id, keycred_id) "
            "VALUES(?, ?, 0, ?, ?)",
            (self.session_pk, ts, cred, keycred),
        )

    def test_password_arc_accepted(self):
        self._insert(self.cred_id, None)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM login_attempts"), 1)

    def test_publickey_arc_accepted(self):
        self._insert(None, self.keycred_id)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM login_attempts"), 1)

    def test_neither_arc_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert(None, None)

    def test_both_arcs_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert(self.cred_id, self.keycred_id)

    def test_publickey_attempts_deduplicate(self):
        """The design pays off here.

        Three public-key attempts with the same username and fingerprint
        collapse to ONE key_credentials row, because both of its columns are
        NOT NULL and the UNIQUE constraint therefore works.
        """
        for _ in range(3):
            self.conn.execute(
                "INSERT OR IGNORE INTO key_credentials(username, fingerprint) "
                "VALUES('root', 'aa:bb:cc:dd:ee:ff')"
            )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM key_credentials"), 1)

    def test_counterfactual_nullable_password_does_not_deduplicate(self):
        """Why the arc exists at all.

        The obvious design -- one credentials table with a nullable password
        -- fails silently, because SQL treats NULLs as DISTINCT inside a
        UNIQUE constraint. Three identical public-key attempts would become
        three credential rows and every "top credentials" count would be
        inflated by the key-based traffic.

        This test asserts the broken behaviour of the rejected design, so
        the reason for the real one cannot be forgotten.
        """
        self.conn.execute(
            "CREATE TABLE naive_credentials ("
            "  username TEXT NOT NULL, password TEXT, UNIQUE(username, password))"
        )
        for _ in range(3):
            self.conn.execute(
                "INSERT OR IGNORE INTO naive_credentials(username, password) "
                "VALUES('root', NULL)"
            )
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM naive_credentials"),
            3,
            "if this is 1, SQLite changed its NULL/UNIQUE semantics and the "
            "exclusive arc may no longer be necessary",
        )
        # And the sentinel alternative is ambiguous rather than merely
        # redundant: '' is itself one of the most-tried passwords.
        self.conn.execute(
            "INSERT OR IGNORE INTO credentials(username, password) "
            "VALUES('root', '')"
        )
        self.assertEqual(
            self.scalar(
                "SELECT COUNT(*) FROM credentials WHERE username='root' "
                "AND password=''"
            ),
            1,
            "the empty password is real data, so it cannot double as a "
            "'no password offered' sentinel",
        )


class TestNullableByDesign(SchemaTestCase):
    def test_download_without_url_is_allowed(self):
        """Cowrie fires file_download for stdin and shell-redirect captures,
        which have no URL. The brief had this column NOT NULL.
        """
        s = self.a_session()
        self.conn.execute(
            "INSERT INTO artifacts(sha256, outfile) VALUES(?, ?)",
            ("a" * 64, "/var/lib/cowrie/downloads/" + "a" * 64),
        )
        self.conn.execute(
            "INSERT INTO file_transfers"
            "(session_pk, ts, direction, url, sha256) "
            "VALUES(?, ?, 'download', NULL, ?)",
            (s, TS, "a" * 64),
        )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM file_transfers"), 1)

    def test_session_without_connect_event_is_allowed(self):
        """Daily rotation cuts sessions in half: a session that spans
        midnight has its connect in a file that may have been rotated away
        before we ever ingested it. That is a data condition, not an error.
        """
        self.a_session(start_ts=None, protocol=None, src_port=None)
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM sessions WHERE start_ts IS NULL"), 1
        )


class TestViews(SchemaTestCase):
    def test_session_commands_seq_is_arrival_order(self):
        """v_session_commands supplies the `seq` the commands table
        deliberately does not store.
        """
        s = self.a_session()
        for h, cmd in ((11, "wget http://example.invalid/x"),
                       (9, "uname -a"),
                       (10, "cat /proc/cpuinfo")):
            self.conn.execute(
                "INSERT INTO commands(session_pk, ts, input, implemented) "
                "VALUES(?, ?, ?, 1)",
                (s, canonical(h), cmd),
            )
        rows = list(
            self.conn.execute(
                "SELECT seq, input FROM v_session_commands "
                "WHERE session_pk=? ORDER BY seq",
                (s,),
            )
        )
        self.assertEqual(
            rows,
            [
                (1, "uname -a"),
                (2, "cat /proc/cpuinfo"),
                (3, "wget http://example.invalid/x"),
            ],
        )

    def test_seq_restarts_per_session(self):
        src = self.a_source()
        sensor = self.a_sensor()
        pks = []
        for sid in ("a1b2c3d4e5f6", "b2c3d4e5f6a1"):
            cur = self.conn.execute(
                "INSERT INTO sessions(sensor_id, cowrie_session_id, source_id, "
                "start_ts) VALUES(?, ?, ?, ?)",
                (sensor, sid, src, TS),
            )
            pks.append(int(cur.lastrowid))
        for pk in pks:
            for h in (9, 10):
                self.conn.execute(
                    "INSERT INTO commands(session_pk, ts, input, implemented) "
                    "VALUES(?, ?, 'ls', 1)",
                    (pk, canonical(h)),
                )
        got = sorted(
            self.conn.execute(
                "SELECT session_pk, seq FROM v_session_commands"
            )
        )
        self.assertEqual(got, [(pks[0], 1), (pks[0], 2), (pks[1], 1), (pks[1], 2)])

    def test_login_attempts_view_flattens_both_arcs(self):
        s = self.a_session()
        c = self.a_credential("root", "123456")
        self.conn.execute(
            "INSERT INTO ssh_keys(fingerprint, key_type) VALUES('ff:ee', 'ssh-rsa')"
        )
        cur = self.conn.execute(
            "INSERT INTO key_credentials(username, fingerprint) "
            "VALUES('admin', 'ff:ee')"
        )
        k = int(cur.lastrowid)
        self.conn.execute(
            "INSERT INTO login_attempts(session_pk, ts, success, cred_id) "
            "VALUES(?, ?, 0, ?)",
            (s, canonical(9), c),
        )
        self.conn.execute(
            "INSERT INTO login_attempts(session_pk, ts, success, keycred_id) "
            "VALUES(?, ?, 1, ?)",
            (s, canonical(10), k),
        )
        rows = list(
            self.conn.execute(
                "SELECT auth_method, username, secret, success "
                "FROM v_login_attempts ORDER BY ts"
            )
        )
        self.assertEqual(
            rows,
            [
                ("password", "root", "123456", 0),
                ("publickey", "admin", "ff:ee", 1),
            ],
        )

    def test_source_activity_replaces_stored_first_last_seen(self):
        """These were columns on `sources` in the brief. They are aggregates
        over sessions, so the view keeps exactly one copy of the truth.
        """
        sensor = self.a_sensor()
        src = self.a_source("203.0.113.9")
        for sid, start, end in (
            ("aaaaaaaaaaaa", "2026-11-05T01:00:00.000000Z",
             "2026-11-05T01:05:00.000000Z"),
            ("bbbbbbbbbbbb", "2026-11-06T02:00:00.000000Z",
             "2026-11-06T02:10:00.000000Z"),
            ("cccccccccccc", "2026-11-06T23:00:00.000000Z", None),
        ):
            self.conn.execute(
                "INSERT INTO sessions(sensor_id, cowrie_session_id, source_id, "
                "start_ts, end_ts) VALUES(?, ?, ?, ?, ?)",
                (sensor, sid, src, start, end),
            )
        row = self.conn.execute(
            "SELECT ip, session_count, first_seen, last_seen, active_days "
            "FROM v_source_activity"
        ).fetchone()
        self.assertEqual(row[0], "203.0.113.9")
        self.assertEqual(row[1], 3)
        self.assertEqual(row[2], "2026-11-05T01:00:00.000000Z")
        # last_seen falls back to start_ts for the session that never closed.
        self.assertEqual(row[3], "2026-11-06T23:00:00.000000Z")
        self.assertEqual(row[4], 2, "two distinct UTC days")


class TestDialectParity(unittest.TestCase):
    """Offline checks that the two schema files stay the same model.

    These run without a MySQL server, which is the point: the MySQL file
    cannot be applied here, so drift between the dialects has to be caught
    structurally instead.
    """

    @staticmethod
    def _names(path: pathlib.Path, pattern: str) -> set[str]:
        return set(re.findall(pattern, path.read_text()))

    def test_same_tables(self):
        pat = r"CREATE TABLE IF NOT EXISTS (\w+)"
        self.assertEqual(
            self._names(SQLITE_SCHEMA, pat), self._names(MYSQL_SCHEMA, pat)
        )

    def test_same_views(self):
        self.assertEqual(
            self._names(SQLITE_SCHEMA, r"CREATE VIEW IF NOT EXISTS (\w+)"),
            self._names(MYSQL_SCHEMA, r"CREATE OR REPLACE VIEW (\w+)"),
        )

    def test_mysql_pins_binary_collation(self):
        """Without this, MySQL folds 'root' and 'ROOT' into one credential
        and the two engines disagree on identical input.
        """
        text = MYSQL_SCHEMA.read_text()
        tables = re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)(.*?);", text, re.S)
        self.assertTrue(tables, "no tables parsed out of the MySQL schema")
        for name, body in tables:
            with self.subTest(table=name):
                self.assertIn(
                    "COLLATE=utf8mb4_bin", body,
                    f"{name} does not pin a binary collation",
                )

    def test_mysql_declares_no_unverified_claim(self):
        """The MySQL file must keep saying it is unproven until someone has
        actually applied it. Delete this test when the DSN-backed test below
        has been run successfully.
        """
        self.assertIn("VERIFICATION STATUS: not verified", MYSQL_SCHEMA.read_text())


@unittest.skipUnless(
    os.environ.get("SHADOWPOT_MYSQL_DSN"),
    "set SHADOWPOT_MYSQL_DSN to verify the MySQL schema against a live server",
)
class TestMySQLSchemaApplies(unittest.TestCase):
    def test_applies(self):
        try:
            import mysql.connector as drv  # type: ignore
        except ImportError:  # pragma: no cover
            self.skipTest("mysql-connector-python is not installed")
        dsn = os.environ["SHADOWPOT_MYSQL_DSN"]
        conn = drv.connect(**dict(p.split("=", 1) for p in dsn.split(";") if p))
        self.addCleanup(conn.close)
        cur = conn.cursor()
        for stmt in MYSQL_SCHEMA.read_text().split(";\n"):
            if stmt.strip():
                cur.execute(stmt)
        cur.execute(
            "SELECT meta_value FROM db_meta WHERE meta_key='schema_version'"
        )
        self.assertEqual(cur.fetchone()[0], "1")


if __name__ == "__main__":
    unittest.main()

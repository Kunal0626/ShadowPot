"""Tests for shadowpot.db.

The MySQL path cannot be executed here -- the development machine's MySQL
rejects connections without credentials and this project stores no database
passwords -- so these tests verify everything about it that CAN be verified
without a server: DSN parsing, the SQL it generates, and the timestamp
conversion. What is NOT verified is the round trip, and the last test in this
file says so out loud rather than leaving the gap to be discovered.
"""

from __future__ import annotations

import pathlib
import sqlite3
import tempfile
import unittest

from shadowpot import db as dbmod


class TestDsnParsing(unittest.TestCase):
    def test_bare_path_is_sqlite(self):
        """`--db data/shadowpot.db` is what anyone actually types. Demanding
        a URL scheme for the default engine would be friction for nothing."""
        target = dbmod.parse_dsn("data/shadowpot.db")
        self.assertEqual(target.dialect.name, "sqlite")
        self.assertEqual(target.sqlite_path, pathlib.Path("data/shadowpot.db"))

    def test_sqlite_url(self):
        self.assertEqual(
            dbmod.parse_dsn("sqlite:///tmp/x.db").sqlite_path,
            pathlib.Path("tmp/x.db"),
        )

    def test_mysql_url_full(self):
        target = dbmod.parse_dsn("mysql://kunal:pw@127.0.0.1:3306/shadowpot")
        self.assertEqual(target.dialect.name, "mysql")
        self.assertEqual(target.mysql_kwargs, {
            "host": "127.0.0.1", "port": 3306, "user": "kunal",
            "password": "pw", "database": "shadowpot",
        })

    def test_mysql_url_minimal(self):
        target = dbmod.parse_dsn("mysql://localhost/shadowpot")
        self.assertEqual(target.mysql_kwargs,
                         {"host": "localhost", "database": "shadowpot"})

    def test_mysql_url_empty_password_is_kept(self):
        """An empty password is a real configuration, distinct from no
        password being supplied at all."""
        target = dbmod.parse_dsn("mysql://root:@localhost/db")
        self.assertEqual(target.mysql_kwargs["password"], "")

    def test_malformed_mysql_url_is_rejected_with_guidance(self):
        for bad in ("mysql://", "mysql://host", "mysql://host/"):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as caught:
                dbmod.parse_dsn(bad)
            self.assertIn("mysql://user:password@host", str(caught.exception))

    def test_empty_dsn_is_rejected(self):
        with self.assertRaises(ValueError):
            dbmod.parse_dsn("")


class TestGeneratedSql(unittest.TestCase):
    """The dialect differences are small and unforgiving, so they are asserted
    literally rather than trusted."""

    def setUp(self) -> None:
        self.sqlite = dbmod.DIALECTS["sqlite"]
        self.mysql = dbmod.DIALECTS["mysql"]

    def test_placeholders_differ(self):
        self.assertEqual(self.sqlite.placeholder, "?")
        self.assertEqual(self.mysql.placeholder, "%s")

    def test_insert_or_ignore(self):
        cols = ["username", "password"]
        self.assertEqual(
            self.sqlite.insert_or_ignore("credentials", cols),
            "INSERT OR IGNORE INTO credentials (username, password) "
            "VALUES (?, ?)",
        )
        self.assertEqual(
            self.mysql.insert_or_ignore("credentials", cols),
            "INSERT IGNORE INTO credentials (username, password) "
            "VALUES (%s, %s)",
        )

    def test_update(self):
        self.assertEqual(
            self.sqlite.update("sessions", ["end_ts"], ["session_pk"]),
            "UPDATE sessions SET end_ts = ? WHERE session_pk = ?",
        )
        self.assertEqual(
            self.mysql.update("sessions", ["end_ts"], ["session_pk"]),
            "UPDATE sessions SET end_ts = %s WHERE session_pk = %s",
        )

    def test_select_one_with_composite_key(self):
        self.assertEqual(
            self.sqlite.select_one("sessions", "session_pk",
                                   ["sensor_id", "cowrie_session_id"]),
            "SELECT session_pk FROM sessions WHERE sensor_id = ? "
            "AND cowrie_session_id = ?",
        )

    def test_sqlite_stores_the_canonical_timestamp_verbatim(self):
        value = "2026-11-06T14:22:31.123456Z"
        self.assertEqual(self.sqlite.timestamp(value), value)

    def test_mysql_strips_what_datetime_rejects(self):
        """MySQL's DATETIME(6) accepts neither the 'T' separator nor the
        trailing 'Z'. The value is already UTC and DATETIME carries no zone,
        so dropping the marker loses nothing."""
        self.assertEqual(
            self.mysql.timestamp("2026-11-06T14:22:31.123456Z"),
            "2026-11-06 14:22:31.123456",
        )

    def test_both_dialects_pass_none_through(self):
        for dialect in (self.sqlite, self.mysql):
            with self.subTest(dialect=dialect.name):
                self.assertIsNone(dialect.timestamp(None))

    def test_each_dialect_points_at_its_own_schema_file(self):
        for dialect in (self.sqlite, self.mysql):
            with self.subTest(dialect=dialect.name):
                self.assertTrue(
                    (dbmod.SCHEMA_DIR / dialect.schema_file).is_file()
                )


class TestConnect(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def test_connect_creates_the_schema_and_enables_foreign_keys(self):
        database = dbmod.connect(str(self.tmp / "a.db"))
        self.addCleanup(database.close)
        self.assertEqual(database.scalar("PRAGMA foreign_keys"), 1)
        self.assertEqual(
            database.scalar("SELECT COUNT(*) FROM sqlite_master "
                            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"),
            16,
        )

    def test_connect_creates_missing_parent_directories(self):
        database = dbmod.connect(str(self.tmp / "nested" / "deep" / "b.db"))
        self.addCleanup(database.close)
        self.assertTrue((self.tmp / "nested" / "deep" / "b.db").exists())

    def test_reconnecting_is_harmless(self):
        path = str(self.tmp / "c.db")
        dbmod.connect(path).close()
        database = dbmod.connect(path)
        self.addCleanup(database.close)
        self.assertEqual(database.scalar("SELECT COUNT(*) FROM sessions"), 0)

    def test_schema_version_mismatch_is_refused(self):
        """Loading a database built by a different schema version would write
        rows the current code cannot read back correctly. Better to refuse."""
        path = self.tmp / "d.db"
        dbmod.connect(str(path)).close()
        conn = sqlite3.connect(path)
        conn.execute("UPDATE db_meta SET meta_value = '99' "
                     "WHERE meta_key = 'schema_version'")
        conn.commit()
        conn.close()
        with self.assertRaises(dbmod.SchemaMismatch) as caught:
            dbmod.connect(str(path))
        self.assertIn("99", str(caught.exception))

    def test_a_database_that_is_not_shadowpot_is_refused(self):
        path = self.tmp / "stranger.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE db_meta(meta_key TEXT, meta_value TEXT)")
        conn.commit()
        conn.close()
        with self.assertRaises(dbmod.SchemaMismatch):
            dbmod.connect(str(path), apply_schema=False)

    def test_get_or_create_is_idempotent_and_returns_the_existing_key(self):
        """Why not cursor.lastrowid? Because when the INSERT is ignored,
        lastrowid holds whatever was last inserted on that connection -- a
        different row entirely. Reading the key back is the only correct
        answer."""
        database = dbmod.connect(str(self.tmp / "e.db"))
        self.addCleanup(database.close)
        first = database.get_or_create("sensors", {"name": "h1"}, "sensor_id")
        database.get_or_create("sensors", {"name": "h2"}, "sensor_id")
        again = database.get_or_create("sensors", {"name": "h1"}, "sensor_id")
        self.assertEqual(first, again)
        self.assertEqual(database.scalar("SELECT COUNT(*) FROM sensors"), 2)

    def test_insert_or_ignore_reports_whether_it_inserted(self):
        database = dbmod.connect(str(self.tmp / "f.db"))
        self.addCleanup(database.close)
        values = {"meta_key": "x", "meta_value": "1"}
        self.assertEqual(database.insert_or_ignore("db_meta", values), 1)
        self.assertEqual(database.insert_or_ignore("db_meta", values), 0)


class TestMySQLStatementSplitting(unittest.TestCase):
    def test_the_real_schema_splits_into_runnable_statements(self):
        statements = list(dbmod._split_statements(
            (dbmod.SCHEMA_DIR / "schema.mysql.sql").read_text()
        ))
        creates = [s for s in statements if s.upper().startswith("CREATE TABLE")]
        views = [s for s in statements if "VIEW" in s.upper()]
        self.assertEqual(len(creates), 16)
        self.assertEqual(len(views), 3)
        for statement in statements:
            with self.subTest(statement=statement[:40]):
                self.assertFalse(statement.startswith("--"),
                                 "comments must be stripped, not executed")

    def test_comment_only_chunks_are_dropped(self):
        self.assertEqual(
            list(dbmod._split_statements("-- just a comment\n-- another\n")), []
        )


class TestUnverifiedMySQLRoundTrip(unittest.TestCase):
    def test_the_gap_is_recorded_in_the_module_docstring(self):
        """This test exists to stop the MySQL path from quietly being
        described as working.

        Everything checkable without a server is checked above. The round
        trip -- connect, apply schema, insert, read back -- is not, and must
        not be claimed. Delete this test once someone has run:

            mysql -u <user> -p -e "CREATE DATABASE shadowpot_test"
            python3 -m shadowpot.ingest \\
                --db mysql://<user>:<pw>@localhost/shadowpot_test \\
                data/sample-logs
        """
        # Whitespace-normalized: the claim is wrapped across lines in the
        # docstring, and a literal substring match would break on reflow.
        prose = " ".join((dbmod.__doc__ or "").split())
        self.assertIn("never been executed against a live MySQL server", prose)
        self.assertIn("treat it as unproven", prose)

    def test_a_missing_driver_fails_with_an_actionable_message(self):
        try:
            import mysql.connector  # noqa: F401
        except ImportError:
            pass
        else:
            self.skipTest("mysql-connector-python is installed, so the "
                          "missing-driver path cannot be exercised")
        with self.assertRaises(RuntimeError) as caught:
            dbmod.connect("mysql://localhost/shadowpot")
        message = str(caught.exception)
        self.assertIn("pip install mysql-connector-python", message)
        self.assertIn("SQLite is the default", message)


if __name__ == "__main__":
    unittest.main()

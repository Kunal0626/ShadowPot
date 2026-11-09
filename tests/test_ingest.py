"""Tests for shadowpot.ingest.

The three properties the loader promises, each tested directly:

  idempotent  running twice leaves the database unchanged, by two independent
              mechanisms (natural keys, and the line-hash ledger)
  resumable   a daily run reads only new bytes, and survives all four ways a
              log file can change underneath it
  robust      bad input is counted and skipped, never fatal

The resumability tests are the ones worth reading. Each corresponds to a real
operational event -- Cowrie rotating its own log, logrotate renaming it,
logrotate using copytruncate, the honeypot being killed mid-write -- and a
loader that stores only a byte offset gets two of them wrong while appearing
to work.
"""

from __future__ import annotations

import gzip
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from shadowpot import db as dbmod                 # noqa: E402
from shadowpot.ingest import (                    # noqa: E402
    Action, Loader, decide_action, discover, first_line_digest,
    iter_complete_lines, offset_is_still_a_line_boundary,
)
import gen_sample_logs as gen                     # noqa: E402

TS = "2026-11-06T14:22:31.123456Z"


def event(eventid: str, *, session: str = "a1b2c3d4e5f6", ts: str = TS,
          src_ip: str = "198.51.100.7", **extra) -> dict:
    base = {"eventid": eventid, "timestamp": ts, "session": session,
            "src_ip": src_ip, "sensor": "honeypot-1"}
    base.update(extra)
    return base


def session_events(sid: str, *, minute: int = 0, synthetic: bool = False,
                   password: str = "123456") -> list[dict]:
    """A minimal but complete session: connect, one login, close."""
    def stamp(second: int) -> str:
        return f"2026-11-06T14:{minute:02d}:{second:02d}.000000Z"

    extra = {"synthetic": True} if synthetic else {}
    return [
        event("cowrie.session.connect", session=sid, ts=stamp(0),
              protocol="ssh", src_port=1234, dst_ip="203.0.113.1",
              dst_port=2222, **extra),
        event("cowrie.login.failed", session=sid, ts=stamp(1),
              username="root", password=password, **extra),
        event("cowrie.session.closed", session=sid, ts=stamp(2),
              duration_ms=2000, **extra),
    ]


def write_log(path: pathlib.Path, events: list[dict], *,
              mode: str = "w", trailing_newline: bool = True) -> None:
    text = "\n".join(json.dumps(e, separators=(",", ":")) for e in events)
    if trailing_newline and text:
        text += "\n"
    with open(path, mode, encoding="utf-8") as handle:
        handle.write(text)


class LoaderTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.logs = self.tmp / "logs"
        self.logs.mkdir()
        self.db_path = self.tmp / "shadowpot.db"

    def load(self, *paths: pathlib.Path, force: bool = False,
             batch: int = 1000) -> dict:
        targets = [str(p) for p in (paths or (self.logs,))]
        database = dbmod.connect(str(self.db_path))
        try:
            loader = Loader(database, batch_size=batch)
            return loader.run(discover(targets), force=force)
        finally:
            database.close()

    def rows(self) -> dict[str, int]:
        conn = sqlite3.connect(self.db_path)
        try:
            tables = [
                "sessions", "login_attempts", "credentials", "key_credentials",
                "ssh_keys", "commands", "file_transfers", "artifacts",
                "sources", "clients", "kex_fingerprints", "ingested_lines",
            ]
            return {
                t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in tables
            }
        finally:
            conn.close()

    def scalar(self, sql: str, params: tuple = ()) -> object:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestDiscovery(unittest.TestCase):
    def test_orders_oldest_first_with_current_file_last(self):
        """Chronological order matters: cowrie.session.connect carries a
        session's addressing, so reading a later day first would create the
        session row from a mid-session event."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            for name in ("cowrie.json", "cowrie.json.2026-11-03",
                         "cowrie.json.2026-11-01.gz",
                         "cowrie.json.2026-11-02", "not-a-log.txt"):
                (directory / name).write_text("")
            self.assertEqual(
                [p.name for p in discover([str(directory)])],
                ["cowrie.json.2026-11-01.gz", "cowrie.json.2026-11-02",
                 "cowrie.json.2026-11-03", "cowrie.json"],
            )

    def test_unrelated_files_in_the_directory_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "manifest.json").write_text("{}")
            (directory / "SYNTHETIC_DATA.txt").write_text("x")
            (directory / "cowrie.json").write_text("")
            self.assertEqual(
                [p.name for p in discover([str(directory)])], ["cowrie.json"]
            )

    def test_explicit_files_are_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "whatever.json"
            path.write_text("")
            self.assertEqual(discover([str(path)]), [path])

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            discover(["/nonexistent/place"])


class TestCompleteLineIteration(unittest.TestCase):
    def test_offsets_land_just_past_each_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "f"
            path.write_bytes(b"aaa\nbb\ncccc\n")
            with open(path, "rb") as handle:
                got = list(iter_complete_lines(handle, 0))
            self.assertEqual(got, [(b"aaa", 4), (b"bb", 7), (b"cccc", 12)])

    def test_trailing_partial_line_is_reported_but_not_consumed(self):
        """The crux of safe resumption. Recording an offset past a partial
        line would permanently skip the rest of it once it was written."""
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "f"
            path.write_bytes(b"aaa\nbb")
            with open(path, "rb") as handle:
                got = list(iter_complete_lines(handle, 0))
            self.assertEqual(got, [(b"aaa", 4), (b"bb", -1)])

    def test_resuming_from_an_offset_skips_what_was_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "f"
            path.write_bytes(b"aaa\nbb\n")
            with open(path, "rb") as handle:
                self.assertEqual(list(iter_complete_lines(handle, 4)),
                                 [(b"bb", 7)])


class TestDecideAction(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = pathlib.Path(tmp.name) / "cowrie.json"
        self.path.write_bytes(b"a\nb\nc\n")
        self.stat = self.path.stat()

    def state(self, **over) -> dict:
        base = {"inode": self.stat.st_ino, "size_bytes": self.stat.st_size,
                "offset_bytes": self.stat.st_size,
                "head_line_sha256": first_line_digest(self.path),
                "is_compressed": 0, "is_complete": 0}
        base.update(over)
        return base

    def test_unseen_file_is_read_in_full(self):
        self.assertEqual(decide_action(self.path, None).mode, "full")

    def test_nothing_new_is_skipped(self):
        self.assertEqual(decide_action(self.path, self.state()).mode, "skip")

    def test_rewrite_to_the_same_length_is_detected(self):
        """The case inode, size and offset cannot see.

        Same inode, same size, size == offset: every other check says
        "nothing new". Only the first-line fingerprint catches it.
        """
        state = self.state()
        self.path.write_bytes(b"x\ny\nz\n")   # same length, new content
        action = decide_action(self.path, state)
        self.assertEqual(action.mode, "full")
        self.assertIn("rewritten in place", action.reason)

    def test_new_bytes_resume_from_the_offset(self):
        action = decide_action(self.path, self.state(offset_bytes=2))
        self.assertEqual((action.mode, action.offset), ("resume", 2))

    def test_changed_inode_means_rotation(self):
        action = decide_action(self.path, self.state(inode=self.stat.st_ino + 1))
        self.assertEqual(action.mode, "full")
        self.assertIn("rotated", action.reason)

    def test_shrunk_file_means_truncation(self):
        action = decide_action(self.path, self.state(offset_bytes=9999,
                                                    size_bytes=9999))
        self.assertEqual(action.mode, "full")
        self.assertIn("truncated", action.reason)

    def test_force_overrides_everything(self):
        self.assertEqual(
            decide_action(self.path, self.state(), force=True).mode, "full"
        )

    def test_compressed_archive_read_once_then_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "cowrie.json.2026-11-01.gz"
            with open(path, "wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                   mtime=0) as handle:
                    handle.write(b"{}\n")
            stat = path.stat()
            fresh = {"inode": stat.st_ino, "size_bytes": stat.st_size,
                     "offset_bytes": 0,
                     "head_line_sha256": first_line_digest(path),
                     "is_compressed": 1, "is_complete": 0}
            self.assertEqual(decide_action(path, fresh).mode, "full")
            done = {**fresh, "is_complete": 1}
            self.assertEqual(decide_action(path, done).mode, "skip")


class TestLineBoundaryGuard(unittest.TestCase):
    def test_offset_zero_is_always_a_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "f"
            path.write_bytes(b"abc\n")
            with open(path, "rb") as handle:
                self.assertTrue(offset_is_still_a_line_boundary(handle, 0))

    def test_detects_that_the_bytes_underneath_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "f"
            path.write_bytes(b"abc\ndef\n")
            with open(path, "rb") as handle:
                self.assertTrue(offset_is_still_a_line_boundary(handle, 4))
            path.write_bytes(b"xxxxxxxxxxxx\n")
            with open(path, "rb") as handle:
                self.assertFalse(offset_is_still_a_line_boundary(handle, 4))


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------

class TestIdempotence(LoaderTestCase):
    def setUp(self) -> None:
        super().setUp()
        write_log(self.logs / "cowrie.json",
                  session_events("a1b2c3d4e5f6") + session_events("b2c3d4e5f6a1",
                                                                  minute=1))
        self.first = self.load()
        self.baseline = self.rows()

    def test_first_load_applied_everything(self):
        self.assertEqual(self.first["lines_applied"], 6)
        self.assertEqual(self.baseline["sessions"], 2)
        self.assertEqual(self.baseline["login_attempts"], 2)
        # One credential pair shared by both sessions: the whole point of the
        # credentials table.
        self.assertEqual(self.baseline["credentials"], 1)

    def test_plain_rerun_skips_the_file_entirely(self):
        second = self.load()
        self.assertEqual(second["files_skipped"], 1)
        self.assertEqual(second["lines_read"], 0)
        self.assertEqual(self.rows(), self.baseline)

    def test_force_rescan_rereads_but_changes_nothing(self):
        """Exercises the ledger on its own, with offset tracking disabled."""
        second = self.load(force=True)
        self.assertEqual(second["lines_read"], 6)
        self.assertEqual(second["lines_applied"], 0)
        self.assertEqual(second["lines_duplicate"], 6)
        self.assertEqual(self.rows(), self.baseline)

    def test_natural_keys_hold_even_with_the_ledger_emptied(self):
        """The second, independent mechanism.

        Wiping ingested_lines removes the hash-based defence entirely. Every
        row must still be deduplicated, this time by the UNIQUE constraints
        the schema declares over NOT NULL columns.
        """
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM ingested_lines")
        conn.commit()
        conn.close()

        second = self.load(force=True)
        self.assertEqual(second["lines_applied"], 6, "ledger was emptied, so "
                         "every line looks new again")
        after = self.rows()
        del after["ingested_lines"], self.baseline["ingested_lines"]
        self.assertEqual(after, self.baseline,
                         "natural keys alone must prevent duplicate rows")

    def test_a_third_run_still_changes_nothing(self):
        self.load()
        self.load(force=True)
        self.assertEqual(self.rows(), self.baseline)


# ---------------------------------------------------------------------------
# Resumability: the four ways a log file changes
# ---------------------------------------------------------------------------

class TestResumability(LoaderTestCase):
    def test_appended_lines_are_read_incrementally(self):
        path = self.logs / "cowrie.json"
        write_log(path, session_events("a1b2c3d4e5f6"))
        self.load()

        with open(path, "a", encoding="utf-8") as handle:
            for ev in session_events("b2c3d4e5f6a1", minute=1):
                handle.write(json.dumps(ev, separators=(",", ":")) + "\n")

        second = self.load()
        self.assertEqual(second["lines_read"], 3, "only the new lines")
        self.assertEqual(second["lines_applied"], 3)
        self.assertEqual(self.rows()["sessions"], 2)

    def test_stored_offset_matches_the_file_size(self):
        path = self.logs / "cowrie.json"
        write_log(path, session_events("a1b2c3d4e5f6"))
        self.load()
        self.assertEqual(
            self.scalar("SELECT offset_bytes FROM ingest_state WHERE "
                        "source_file = ?", (str(path),)),
            path.stat().st_size,
        )

    def test_cowrie_style_rotation(self):
        """Cowrie renames its log and creates a new one, so the path
        cowrie.json now names a different inode."""
        current = self.logs / "cowrie.json"
        write_log(current, session_events("a1b2c3d4e5f6"))
        self.load()

        os.rename(current, self.logs / "cowrie.json.2026-11-06")
        write_log(current, session_events("b2c3d4e5f6a1", minute=1))

        second = self.load()
        self.assertEqual(second["lines_applied"], 3, "the new file's lines")
        self.assertEqual(second["lines_duplicate"], 3,
                         "the renamed file is re-read under its new name and "
                         "absorbed by the ledger")
        self.assertEqual(self.rows()["sessions"], 2)

    def test_truncation_in_place_rereads_from_zero(self):
        """logrotate copytruncate, where the file keeps its inode but is
        emptied. A loader that only stored an offset would seek past the end
        and read nothing, forever."""
        path = self.logs / "cowrie.json"
        write_log(path, session_events("a1b2c3d4e5f6"))
        inode_before = path.stat().st_ino
        self.load()

        before_size = path.stat().st_size
        write_log(path, session_events("b2c3d4e5f6a1", minute=1), mode="w")
        self.assertEqual(path.stat().st_ino, inode_before,
                         "the test must truncate in place, not replace")
        self.assertEqual(path.stat().st_size, before_size,
                         "this fixture rewrites to the SAME length on "
                         "purpose: that is the case inode, size and offset "
                         "cannot detect, and it is why ingest_state carries "
                         "a first-line fingerprint")

        second = self.load()
        self.assertEqual(second["lines_applied"], 3)
        self.assertEqual(self.rows()["sessions"], 2)

    def test_truncation_to_a_shorter_file(self):
        """The easier variant: size drops below the stored offset."""
        path = self.logs / "cowrie.json"
        write_log(path, [e for i in range(3)
                         for e in session_events(f"aaaaaaaaaa{i:02d}", minute=i)])
        self.load()
        write_log(path, session_events("b2c3d4e5f6a1", minute=9), mode="w")
        second = self.load()
        self.assertEqual(second["lines_applied"], 3)
        self.assertEqual(self.rows()["sessions"], 4)

    def test_copytruncate_then_regrow_past_the_old_offset(self):
        """The nastiest case, and the one every check in decide_action misses.

        The inode is unchanged and the file is now LARGER than the stored
        offset, so every naive test says "resume" -- and the lines written
        below the offset are skipped silently and for ever. The guard is that
        a stored offset always points just past a newline, so if the byte
        before it is not one, the content was rewritten.
        """
        path = self.logs / "cowrie.json"
        write_log(path, session_events("a1b2c3d4e5f6"))
        old_offset = path.stat().st_size
        self.load()

        # Rewrite in place with longer lines, so that the first new line alone
        # extends past the old offset and the byte at old_offset - 1 is
        # certainly inside a line rather than at its end.
        padded = []
        for index, sid in enumerate(("ccccccccccc1", "ddddddddddd2")):
            for ev in session_events(sid, minute=2 + index):
                ev["message"] = "x" * old_offset
                padded.append(ev)
        write_log(path, padded, mode="w")
        self.assertGreater(path.stat().st_size, old_offset)
        self.assertEqual(
            self.scalar("SELECT offset_bytes FROM ingest_state WHERE "
                        "source_file = ?", (str(path),)),
            old_offset,
        )

        second = self.load()
        self.assertEqual(second["lines_applied"], 6,
                         "all six rewritten lines must be read; a stale "
                         "offset would have skipped the first ones")
        self.assertEqual(self.rows()["sessions"], 3)

    def test_truncated_final_line_is_not_consumed(self):
        """The honeypot was killed mid-write. The partial line is counted as
        malformed for this run but must not advance the offset, or the rest of
        it would be skipped once written.
        """
        path = self.logs / "cowrie.json"
        events = session_events("a1b2c3d4e5f6")
        write_log(path, events)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write('{"eventid":"cowrie.session.conn')

        first = self.load()
        self.assertEqual(first["lines_applied"], 3)
        self.assertEqual(first["lines_malformed"], 1)
        complete_bytes = len(
            "\n".join(json.dumps(e, separators=(",", ":")) for e in events)
        ) + 1
        self.assertEqual(
            self.scalar("SELECT offset_bytes FROM ingest_state WHERE "
                        "source_file = ?", (str(path),)),
            complete_bytes,
            "the offset must stop at the end of the last COMPLETE line",
        )

        # Now the writer finishes the line.
        rest = event("cowrie.session.closed", session="b2c3d4e5f6a1",
                     ts="2026-11-06T14:05:00.000000Z", duration_ms=5)
        tail = json.dumps(rest, separators=(",", ":"))
        with open(path, "r+", encoding="utf-8") as handle:
            handle.seek(complete_bytes)
            handle.write(tail + "\n")

        second = self.load()
        self.assertEqual(second["lines_applied"], 1,
                         "the completed line must now be applied in full")

    def test_gzipped_archive_is_read_then_skipped(self):
        path = self.logs / "cowrie.json.2026-11-05"
        write_log(path, session_events("a1b2c3d4e5f6"))
        with open(path, "rb") as src, open(f"{path}.gz", "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                               mtime=0) as dst:
                dst.write(src.read())
        path.unlink()

        first = self.load()
        self.assertEqual(first["lines_applied"], 3)
        second = self.load()
        self.assertEqual(second["files_skipped"], 1)
        self.assertEqual(second["lines_read"], 0)

    def test_a_plain_file_later_gzipped_is_recognised_as_duplicate(self):
        """External logrotate compresses yesterday's file after we read it.

        The path changes, so the ledger is the only thing that can recognise
        the content -- which works only because a line's hash is computed on
        the same bytes whether it came from a plain file or a .gz.
        """
        path = self.logs / "cowrie.json.2026-11-05"
        write_log(path, session_events("a1b2c3d4e5f6"))
        self.load()
        baseline = self.rows()

        with open(path, "rb") as src, open(f"{path}.gz", "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                               mtime=0) as dst:
                dst.write(src.read())
        path.unlink()

        second = self.load()
        self.assertEqual(second["lines_duplicate"], 3)
        self.assertEqual(second["lines_applied"], 0)
        after = self.rows()
        del after["ingested_lines"], baseline["ingested_lines"]
        self.assertEqual(after, baseline)


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

class TestRobustness(LoaderTestCase):
    def test_bad_lines_are_counted_and_skipped_not_fatal(self):
        path = self.logs / "cowrie.json"
        good = session_events("a1b2c3d4e5f6")
        lines = [
            json.dumps(good[0]),
            "{not json at all",
            "[1, 2, 3]",
            "",
            json.dumps({"timestamp": TS, "session": "a1b2c3d4e5f6"}),
            json.dumps(event("cowrie.client.size", width=80, height=24)),
            json.dumps(event("cowrie.command.input")),       # no `input`
            json.dumps(good[1]),
            json.dumps(good[2]),
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        summary = self.load()
        self.assertEqual(summary["lines_read"], 9)
        self.assertEqual(summary["lines_applied"], 3)
        self.assertEqual(summary["lines_malformed"], 4)
        self.assertEqual(summary["events_unknown"], 1)
        self.assertEqual(summary["events_incomplete"], 1)
        # The good events on both sides of the damage still landed.
        self.assertEqual(self.rows()["sessions"], 1)
        self.assertEqual(self.rows()["login_attempts"], 1)
        self.assertIsNotNone(
            self.scalar("SELECT end_ts FROM sessions LIMIT 1")
        )

    def test_a_row_the_database_refuses_is_counted_not_fatal(self):
        """The schema is the last line of validation.

        An unexpected protocol passes the parser deliberately, so that format
        drift surfaces as a counted, explained rejection rather than a silent
        NULL. The run must continue.
        """
        path = self.logs / "cowrie.json"
        write_log(path, [
            event("cowrie.session.connect", protocol="gopher", src_port=1,
                  dst_port=2222),
            event("cowrie.login.failed", ts="2026-11-06T14:22:32.000000Z",
                  username="root", password="x"),
        ])
        summary = self.load()
        self.assertEqual(summary["events_incomplete"], 1)
        self.assertEqual(summary["lines_applied"], 1)
        self.assertTrue(
            any("gopher" in r or "CHECK" in r for r in summary["reasons"]),
            summary["reasons"],
        )
        # The session row still exists, with no protocol recorded.
        self.assertIsNone(self.scalar("SELECT protocol FROM sessions"))

    def test_event_for_a_session_with_no_connect(self):
        """Daily rotation cuts sessions in half, and the earlier file may have
        been deleted before we ever read it. The session gets a row with a
        NULL start_ts; it is not an error."""
        write_log(self.logs / "cowrie.json", [
            event("cowrie.session.closed", session="ffffffffffff",
                  duration_ms=1234),
        ])
        summary = self.load()
        self.assertEqual(summary["lines_applied"], 1)
        self.assertEqual(self.rows()["sessions"], 1)
        self.assertIsNone(self.scalar("SELECT start_ts FROM sessions"))
        self.assertEqual(self.scalar("SELECT duration_ms FROM sessions"), 1234)

    def test_late_event_after_session_closed_is_kept(self):
        """A loader that treated session.closed as a terminator would drop
        exactly these -- completed malware downloads."""
        write_log(self.logs / "cowrie.json", session_events("a1b2c3d4e5f6") + [
            event("cowrie.session.file_download", ts="2026-11-06T14:00:09.000000Z",
                  url="http://late.invalid/x.bin", shasum="a" * 64,
                  outfile="var/lib/cowrie/downloads/" + "a" * 64, late=True),
        ])
        self.load()
        self.assertEqual(self.rows()["file_transfers"], 1)
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM file_transfers ft JOIN sessions s "
                        "ON s.session_pk = ft.session_pk WHERE ft.ts > s.end_ts"),
            1,
        )

    def test_undecodable_bytes_are_counted(self):
        path = self.logs / "cowrie.json"
        with open(path, "wb") as handle:
            handle.write(b'{"eventid":"x","bad":"\xff\xfe"}\n')
        summary = self.load()
        self.assertEqual(summary["lines_malformed"], 1)
        self.assertEqual(summary["lines_applied"], 0)

    def test_empty_file_is_harmless(self):
        (self.logs / "cowrie.json").write_text("")
        summary = self.load()
        self.assertEqual(summary["lines_read"], 0)
        self.assertEqual(summary["lines_applied"], 0)


# ---------------------------------------------------------------------------
# Schema interaction
# ---------------------------------------------------------------------------

class TestSchemaInteraction(LoaderTestCase):
    def test_synthetic_is_sticky_across_a_session(self):
        """One synthetic line taints the whole session, so a database mixing
        real and generated data is always detectable."""
        events = session_events("a1b2c3d4e5f6")
        events[1]["synthetic"] = True     # only the middle event
        write_log(self.logs / "cowrie.json", events)
        self.load()
        self.assertEqual(self.scalar("SELECT is_synthetic FROM sessions"), 1)

    def test_real_data_is_not_marked_synthetic(self):
        write_log(self.logs / "cowrie.json", session_events("a1b2c3d4e5f6"))
        self.load()
        self.assertEqual(self.scalar("SELECT is_synthetic FROM sessions"), 0)

    def test_publickey_and_password_attempts_use_different_arcs(self):
        write_log(self.logs / "cowrie.json", [
            event("cowrie.session.connect", src_port=1, dst_port=2222),
            event("cowrie.login.failed", ts="2026-11-06T14:22:32.000000Z",
                  username="root", password="123456"),
            event("cowrie.login.failed", ts="2026-11-06T14:22:33.000000Z",
                  username="root", fingerprint="aa:bb", type="ssh-rsa",
                  key="AAAA"),
        ])
        self.load()
        rows = self.rows()
        self.assertEqual(rows["credentials"], 1)
        self.assertEqual(rows["key_credentials"], 1)
        self.assertEqual(rows["ssh_keys"], 1)
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM login_attempts "
                        "WHERE cred_id IS NOT NULL"), 1)
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM login_attempts "
                        "WHERE keycred_id IS NOT NULL"), 1)
        self.assertEqual(
            sorted(r[0] for r in sqlite3.connect(self.db_path).execute(
                "SELECT auth_method FROM v_login_attempts")),
            ["password", "publickey"],
        )

    def test_repeated_publickey_attempts_collapse_to_one_credential(self):
        """The payoff for the exclusive arc: both columns are NOT NULL, so the
        UNIQUE constraint actually works. A nullable-password design would
        produce three rows here."""
        rows = [event("cowrie.session.connect", src_port=1, dst_port=2222)]
        for i in range(3):
            rows.append(event("cowrie.login.failed",
                              ts=f"2026-11-06T14:22:3{i + 2}.000000Z",
                              username="root", fingerprint="aa:bb",
                              type="ssh-rsa"))
        write_log(self.logs / "cowrie.json", rows)
        self.load()
        self.assertEqual(self.rows()["key_credentials"], 1)
        self.assertEqual(self.rows()["login_attempts"], 3)

    def test_ingest_run_is_recorded(self):
        write_log(self.logs / "cowrie.json", session_events("a1b2c3d4e5f6"))
        summary = self.load()
        row = sqlite3.connect(self.db_path).execute(
            "SELECT lines_read, lines_applied, finished_at FROM ingest_runs "
            "WHERE run_id = ?", (summary["run_id"],)
        ).fetchone()
        self.assertEqual(row[0], summary["lines_read"])
        self.assertEqual(row[1], summary["lines_applied"])
        self.assertIsNotNone(row[2], "finished_at must be stamped")

    def test_timestamps_land_in_canonical_form(self):
        """The schema's CHECK would reject anything else, so this passing at
        all proves the parser canonicalized. Both input forms are tried."""
        for form, sid in (("Z", "a1b2c3d4e5f6"), ("+0530", "b2c3d4e5f6a1")):
            stamp = ("2026-11-06T14:22:31.123456Z" if form == "Z"
                     else "2026-11-06T19:52:31.123456+0530")
            write_log(self.logs / "cowrie.json", [
                event("cowrie.session.connect", session=sid, ts=stamp,
                      src_port=1, dst_port=2222),
            ], mode="w")
            self.load(force=True)
        stamps = [r[0] for r in sqlite3.connect(self.db_path).execute(
            "SELECT start_ts FROM sessions ORDER BY start_ts")]
        self.assertEqual(stamps,
                         ["2026-11-06T14:22:31.123456Z"] * 2,
                         "both input forms must converge on one stored value")

    def test_batching_does_not_change_the_result(self):
        write_log(self.logs / "cowrie.json",
                  [e for i in range(5)
                   for e in session_events(f"aaaaaaaaaa{i:02d}", minute=i)])
        self.load(batch=2)
        self.assertEqual(self.rows()["sessions"], 5)
        self.assertEqual(self.rows()["login_attempts"], 5)


# ---------------------------------------------------------------------------
# End to end against the generator
# ---------------------------------------------------------------------------

class TestAgainstGeneratedData(LoaderTestCase):
    """The loader's tally must match the generator's manifest.

    The two numbers are produced by completely different code paths -- one
    counts at write time, the other after parsing and inserting -- so
    agreement is real evidence rather than a tautology. This pairing already
    caught a wrong expectation in the manifest: it predicted every written
    event would be applied, but a real-but-unmodelled event id is written as
    an event and then counted as unknown, never applied.
    """

    def setUp(self) -> None:
        super().setUp()
        gen.main(["--out", str(self.logs), "--days", "3",
                  "--sessions-per-day", "30", "--seed", "99", "--quiet"])
        self.manifest = json.loads((self.logs / "manifest.json").read_text())
        self.summary = self.load()

    def test_run_tally_matches_the_manifest(self):
        expected = self.manifest["expected_ingest_run"]
        for key in ("lines_read", "lines_applied", "lines_malformed",
                    "events_unknown"):
            with self.subTest(key=key):
                self.assertEqual(self.summary[key], expected[key])

    def test_nothing_was_incomplete(self):
        self.assertEqual(self.summary["events_incomplete"], 0,
                         f"unexpected rejections: {self.summary['reasons']}")

    def test_domain_counts_match_the_manifest(self):
        tally = self.manifest["tally"]
        checks = {
            "SELECT COUNT(*) FROM sessions": tally["sessions"],
            "SELECT COUNT(*) FROM login_attempts": tally["login_attempts"],
            "SELECT COUNT(*) FROM login_attempts WHERE success = 1":
                tally["login_successes"],
            "SELECT COUNT(*) FROM login_attempts WHERE keycred_id IS NOT NULL":
                tally["publickey_attempts"],
            "SELECT COUNT(*) FROM commands": tally["commands"],
            "SELECT COUNT(*) FROM commands WHERE implemented = 0":
                tally["commands_failed"],
            "SELECT COUNT(*) FROM file_transfers WHERE direction = 'download'":
                tally["downloads"],
            "SELECT COUNT(*) FROM file_transfers WHERE direction = 'download' "
            "AND url IS NULL": tally["downloads_without_url"],
            "SELECT COUNT(*) FROM file_transfers WHERE direction = 'upload'":
                tally["uploads"],
        }
        for sql, expected in checks.items():
            with self.subTest(sql=sql):
                self.assertEqual(self.scalar(sql), expected)

    def test_top_credential_matches_the_manifest(self):
        top = self.manifest["top_credentials"][0]
        got = sqlite3.connect(self.db_path).execute(
            "SELECT cr.username, cr.password, COUNT(*) AS n "
            "FROM login_attempts la JOIN credentials cr "
            "  ON cr.cred_id = la.cred_id "
            "GROUP BY cr.cred_id ORDER BY n DESC, cr.username LIMIT 1"
        ).fetchone()
        self.assertEqual(got, (top["username"], top["password"],
                               top["attempts"]))

    def test_every_session_is_flagged_synthetic(self):
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM sessions WHERE is_synthetic = 0"),
            0,
        )

    def test_hassh_dependency_holds_in_the_database(self):
        self.assertEqual(
            self.scalar(
                "SELECT COUNT(*) FROM (SELECT hassh FROM kex_fingerprints "
                "GROUP BY hassh HAVING COUNT(DISTINCT hassh_algorithms) > 1)"
            ),
            0,
        )

    def test_reloading_the_whole_directory_is_a_no_op(self):
        baseline = self.rows()
        self.load()
        self.load(force=True)
        self.assertEqual(self.rows(), baseline)


if __name__ == "__main__":
    unittest.main()

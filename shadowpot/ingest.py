"""Load Cowrie JSON logs into the ShadowPot schema.

    python3 -m shadowpot.ingest --db data/shadowpot.db data/sample-logs

Three properties matter more than speed here, and each is tested:

IDEMPOTENT. Running this twice over the same data must leave the database
byte-for-byte equivalent. Two independent mechanisms guarantee it. Every
dimension table has a UNIQUE constraint over NOT NULL columns, so
INSERT OR IGNORE is a safe no-op; and every applied line's SHA-256 goes into
`ingested_lines`, which is the only layer that does not rest on the assumption
that no two events in a session share a microsecond.

RESUMABLE. A daily cron run must read only new bytes, and must survive log
rotation. Storing just a byte offset -- the obvious design -- loses data on
rotation and re-reads everything on truncation. See `decide_action` for the
four cases that actually have to be distinguished, and `iter_complete_lines`
for why the offset must point at the end of the last COMPLETE line.

ROBUST. A malformed line, an unknown event id, or an event missing a field
must be counted and skipped, never fatal. One corrupt line in a 10,000-line
file cannot be allowed to cost a day of data.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import gzip
import hashlib
import json
import pathlib
import re
import sqlite3
import sys
from typing import Any, Iterator

from shadowpot import db as dbmod
from shadowpot.parser import Event, Status, parse_line

# cowrie.json.YYYY-MM-DD, optionally gzipped by an external logrotate.
ROTATED = re.compile(r"^cowrie\.json\.(\d{4}-\d{2}-\d{2})(\.gz)?$")

DEFAULT_BATCH = 2000


class Incomplete(Exception):
    """This event cannot be applied; count it and move on."""


# ---------------------------------------------------------------------------
# File discovery and ordering
# ---------------------------------------------------------------------------

def discover(paths: list[str]) -> list[pathlib.Path]:
    """Expand files and directories into the order they should be read.

    Oldest first, with the un-suffixed current file last. Chronological order
    matters: `cowrie.session.connect` carries a session's addressing, so
    reading a later day before an earlier one would create the session row
    from a mid-session event and leave start_ts NULL until the earlier file
    happened to be read. The data still ends up correct -- every write is an
    idempotent upsert -- but it is correct by luck rather than by design.
    """
    found: list[pathlib.Path] = []
    for raw in paths:
        path = pathlib.Path(raw)
        if path.is_dir():
            found.extend(
                child for child in path.iterdir()
                if child.is_file()
                and (child.name == "cowrie.json" or ROTATED.match(child.name))
            )
        elif path.is_file():
            found.append(path)
        else:
            raise FileNotFoundError(f"no such file or directory: {raw}")

    def sort_key(path: pathlib.Path) -> tuple[int, str]:
        match = ROTATED.match(path.name)
        if match:
            return (0, match.group(1))
        # The current file has no date suffix and holds the newest events.
        return (1, path.name)

    return sorted(dict.fromkeys(found), key=sort_key)


# ---------------------------------------------------------------------------
# Resumability
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Action:
    mode: str          # 'skip' | 'full' | 'resume'
    reason: str
    offset: int = 0


def first_line_digest(path: pathlib.Path) -> str | None:
    """SHA-256 of the file's first line, including its newline.

    This is the content fingerprint that makes resumption safe against an
    in-place rewrite. Hashing the first line rather than the whole file keeps
    an incremental run cheap: the first line never changes when a log is
    appended to, and always changes when one is replaced, because a new first
    line means a different session at a different microsecond.

    Returns None for an empty or unreadable file, which the caller treats as
    "no fingerprint available" rather than as a mismatch.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rb") as handle:   # type: ignore[operator]
            line = handle.readline()
    except (OSError, EOFError):
        return None
    return hashlib.sha256(line).hexdigest() if line else None


def decide_action(path: pathlib.Path, state: dict[str, Any] | None,
                  *, force: bool = False) -> Action:
    """Decide how much of a file to read.

    Five distinct conditions have to be told apart. A loader that stores only
    an offset gets three of them wrong while appearing to work.

      inode changed         the path now names a different file; Cowrie
                            rotated and created a new one. Read from 0.
      first line changed    the file was rewritten in place. This is the case
                            inode, size and offset CANNOT catch: a file
                            truncated and rewritten to the same length looks
                            identical to one that has not changed at all, and
                            its replacement content would be skipped silently
                            and for ever.
      size < stored offset  truncated in place (logrotate copytruncate).
                            Read from 0.
      size == stored offset nothing new. Skip after reading only the first
                            line, which is what keeps a daily cron run cheap.
      otherwise             resume at the stored offset.

    Compressed files are a separate case: a .gz cannot be cheaply seeked, and
    a rotated archive is immutable, so it is read once and marked complete.
    """
    stat = path.stat()
    compressed = path.suffix == ".gz"

    if force:
        return Action("full", "forced rescan")
    if state is None:
        return Action("full", "not seen before")
    if int(state["inode"]) != stat.st_ino:
        return Action("full", "inode changed: the file was rotated or replaced")

    stored_head = state.get("head_line_sha256")
    if stored_head is not None and first_line_digest(path) != stored_head:
        return Action("full",
                      "first line changed: the file was rewritten in place")

    if compressed:
        if state["is_complete"] and int(state["size_bytes"]) == stat.st_size:
            return Action("skip", "compressed archive already read in full")
        return Action("full", "compressed archive not yet fully read")

    offset = int(state["offset_bytes"])
    if stat.st_size < offset:
        return Action("full", "file shrank: truncated in place")
    if stat.st_size == offset:
        return Action("skip", "no new bytes")
    return Action("resume", "resuming after the last complete line", offset)


def offset_is_still_a_line_boundary(handle: Any, offset: int) -> bool:
    """Guard against copytruncate-then-regrow.

    If logrotate copies a file and truncates the original in place, and the
    honeypot then writes PAST our stored offset before we next run, the inode
    is unchanged and the size is larger -- so every check in `decide_action`
    says "resume", and we would skip the new lines written below the offset
    and never notice.

    A stored offset always points just past a newline, by construction in
    `iter_complete_lines`. So if the byte before it is not a newline, the
    bytes underneath us changed and the whole file must be re-read.

    This is a cheap heuristic, not a proof: a regrown file could coincidentally
    have a newline at that exact position. Catching that needs a content
    fingerprint in ingest_state, which would be a schema change; it is listed
    under future work rather than claimed as handled.
    """
    if offset == 0:
        return True
    handle.seek(offset - 1)
    return handle.read(1) == b"\n"


def iter_complete_lines(handle: Any, offset: int) -> Iterator[tuple[bytes, int]]:
    """Yield (line without its newline, offset just past that newline).

    Only COMPLETE lines are yielded, and the offset advances only past a
    newline. This is the whole trick to safe resumption: if the honeypot is
    killed mid-write, the file ends with a partial line, and recording an
    offset past it would permanently skip the rest of that line once it was
    eventually written. The partial line is reported by the caller as
    malformed for this run and left unconsumed.
    """
    handle.seek(offset)
    position = offset
    while True:
        raw = handle.readline()
        if not raw:
            return
        if not raw.endswith(b"\n"):
            # An incomplete trailing line. Do not consume it, do not advance.
            yield raw, -1
            return
        position += len(raw)
        yield raw[:-1], position


# ---------------------------------------------------------------------------
# The loader
# ---------------------------------------------------------------------------

class Loader:
    def __init__(self, database: dbmod.Database, *,
                 batch_size: int = DEFAULT_BATCH) -> None:
        self.db = database
        self.batch_size = batch_size
        self.counts: collections.Counter[str] = collections.Counter()
        self.reasons: collections.Counter[str] = collections.Counter()

        # Lookup caches. Without these, loading 8,000 events means ~25,000
        # redundant SELECTs against tables whose contents barely change.
        self._sensors: dict[str, int] = {}
        self._sources: dict[str, int] = {}
        self._clients: dict[str, int] = {}
        self._sessions: dict[tuple[int, str], int] = {}
        self._synthetic_marked: set[int] = set()
        self._artifacts: set[str] = set()

        self._pending = 0
        self._now = _utc_now()

    # -- dimension lookups ---------------------------------------------

    def _sensor_id(self, name: str) -> int:
        if name not in self._sensors:
            self._sensors[name] = self.db.get_or_create(
                "sensors", {"name": name}, "sensor_id"
            )
        return self._sensors[name]

    def _source_id(self, ip: str, version: int) -> int:
        if ip not in self._sources:
            self._sources[ip] = self.db.get_or_create(
                "sources", {"ip": ip}, "source_id",
                extra={"ip_version": version},
            )
        return self._sources[ip]

    def _client_id(self, version: str) -> int:
        if version not in self._clients:
            self._clients[version] = self.db.get_or_create(
                "clients", {"version": version}, "client_id"
            )
        return self._clients[version]

    def _session_pk(self, event: Event) -> int:
        """Get or create the session row for an event.

        The row may be created by an event other than cowrie.session.connect.
        With daily rotation a session spanning midnight has its connect in
        yesterday's file, which may have been rotated away before we ever
        ingested it. docs/LOG_FORMAT.md section 7 records this as a normal
        data condition; the row simply has a NULL start_ts.
        """
        assert event.session is not None
        sensor_id = self._sensor_id(event.sensor)
        key = (sensor_id, event.session)

        if key not in self._sessions:
            if event.src_ip is None:
                raise Incomplete(
                    "no src_ip, so the session cannot be attributed to a source"
                )
            source_id = self._source_id(event.src_ip, event.src_ip_version or 4)
            self._sessions[key] = self.db.get_or_create(
                "sessions",
                {"sensor_id": sensor_id, "cowrie_session_id": event.session},
                "session_pk",
                extra={"source_id": source_id,
                       "is_synthetic": int(event.is_synthetic)},
            )
            if event.is_synthetic:
                self._synthetic_marked.add(self._sessions[key])

        session_pk = self._sessions[key]

        # Synthetic is sticky: one synthetic line taints the whole session, so
        # that a database mixing real and generated data is always detectable.
        # Marked at most once per session rather than on every line.
        if event.is_synthetic and session_pk not in self._synthetic_marked:
            self.db.update("sessions", {"is_synthetic": 1},
                           {"session_pk": session_pk})
            self._synthetic_marked.add(session_pk)

        return session_pk

    def _artifact(self, sha256: str, outfile: str | None) -> None:
        if sha256 not in self._artifacts:
            self.db.get_or_create("artifacts", {"sha256": sha256}, "sha256",
                                  extra={"outfile": outfile})
            self._artifacts.add(sha256)

    # -- event application ---------------------------------------------

    def apply(self, event: Event) -> None:
        session_pk = self._session_pk(event)
        ts = self.db.dialect.timestamp(event.ts)
        data = event.data

        if event.eventid == "cowrie.session.connect":
            changes: dict[str, Any] = {"start_ts": ts}
            for field in ("protocol", "src_port", "dst_ip", "dst_port"):
                if field in data:
                    changes[field] = data[field]
            self.db.update("sessions", changes, {"session_pk": session_pk})

        elif event.eventid == "cowrie.client.version":
            self.db.update(
                "sessions",
                {"client_id": self._client_id(data["version"])},
                {"session_pk": session_pk},
            )

        elif event.eventid == "cowrie.client.kex":
            self.db.get_or_create(
                "kex_fingerprints", {"hassh": data["hassh"]}, "hassh",
                extra={"hassh_algorithms": data["hassh_algorithms"]},
            )
            self.db.update(
                "sessions",
                {"hassh": data["hassh"],
                 "key_algs": data["key_algs"],
                 "lang_cs": data["lang_cs"]},
                {"session_pk": session_pk},
            )

        elif event.eventid in ("cowrie.login.failed", "cowrie.login.success"):
            row: dict[str, Any] = {
                "session_pk": session_pk, "ts": ts, "success": data["success"],
            }
            if data["auth_method"] == "password":
                row["cred_id"] = self.db.get_or_create(
                    "credentials",
                    {"username": data["username"], "password": data["password"]},
                    "cred_id",
                )
            else:
                self.db.get_or_create(
                    "ssh_keys", {"fingerprint": data["fingerprint"]},
                    "fingerprint",
                    extra={"key_type": data["key_type"],
                           "key_blob": data["key_blob"]},
                )
                row["keycred_id"] = self.db.get_or_create(
                    "key_credentials",
                    {"username": data["username"],
                     "fingerprint": data["fingerprint"]},
                    "keycred_id",
                )
            self.db.insert_or_ignore("login_attempts", row)

        elif event.eventid in ("cowrie.command.input", "cowrie.command.failed"):
            self.db.insert_or_ignore("commands", {
                "session_pk": session_pk, "ts": ts,
                "input": data["input"], "realm": data["realm"],
                "implemented": data["implemented"],
            })

        elif event.eventid in ("cowrie.session.file_download",
                               "cowrie.session.file_upload"):
            if data["sha256"]:
                self._artifact(data["sha256"], data["outfile"])
            self.db.insert_or_ignore("file_transfers", {
                "session_pk": session_pk, "ts": ts,
                "direction": data["direction"], "url": data["url"],
                "filename": data["filename"], "destfile": data["destfile"],
                "sha256": data["sha256"], "is_duplicate": data["is_duplicate"],
            })

        elif event.eventid == "cowrie.session.closed":
            self.db.update(
                "sessions",
                {"end_ts": ts, "duration_ms": data["duration_ms"]},
                {"session_pk": session_pk},
            )

        else:  # pragma: no cover - parser guarantees this cannot happen
            raise AssertionError(f"no handler for {event.eventid}")

    # -- line and file processing ---------------------------------------

    def _record_line(self, digest: str, source_file: str) -> None:
        self.db.insert_or_ignore("ingested_lines", {
            "line_sha256": digest,
            "source_file": source_file,
            "ingested_at": self.db.dialect.timestamp(self._now),
        })

    def _seen(self, digest: str) -> bool:
        return self.db.scalar(
            self.db.dialect.select_one("ingested_lines", "1", ["line_sha256"]),
            [digest],
        ) is not None

    def process_line(self, raw: bytes, source_file: str) -> None:
        self.counts["lines_read"] += 1

        digest = hashlib.sha256(raw).hexdigest()
        if self._seen(digest):
            self.counts["lines_duplicate"] += 1
            return

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.counts["lines_malformed"] += 1
            self.reasons[f"undecodable bytes: {exc.reason}"] += 1
            return

        parsed = parse_line(text)

        if parsed.status is Status.MALFORMED:
            self.counts["lines_malformed"] += 1
            self.reasons[parsed.reason or "malformed"] += 1
            return
        if parsed.status is Status.UNKNOWN:
            self.counts["events_unknown"] += 1
            self.reasons[parsed.reason or "unknown event"] += 1
            return
        if parsed.status is Status.INCOMPLETE:
            self.counts["events_incomplete"] += 1
            self.reasons[parsed.reason or "incomplete event"] += 1
            return

        assert parsed.event is not None
        try:
            self.apply(parsed.event)
        except Incomplete as exc:
            self.counts["events_incomplete"] += 1
            self.reasons[f"{parsed.event.eventid}: {exc}"] += 1
            return
        except sqlite3.IntegrityError as exc:
            # The database is the last line of validation -- that is what the
            # CHECK constraints and STRICT tables are for. A row it refuses is
            # counted and skipped rather than aborting the file, and the
            # reason is reported so format drift is visible instead of silent.
            #
            # Deliberately NOT a bare `except Exception`: an unexpected error
            # is a bug in this loader and should crash loudly rather than be
            # tallied as bad input.
            self.counts["events_incomplete"] += 1
            self.reasons[f"{parsed.event.eventid} rejected: {exc}"] += 1
            return

        self._record_line(digest, source_file)
        self.counts["lines_applied"] += 1

    def _save_state(self, path: pathlib.Path, offset: int, *,
                    complete: bool) -> None:
        stat = path.stat()
        values = {
            "source_file": str(path),
            "inode": stat.st_ino,
            "size_bytes": stat.st_size,
            "offset_bytes": offset,
            "head_line_sha256": first_line_digest(path),
            "is_compressed": int(path.suffix == ".gz"),
            "is_complete": int(complete),
            "last_ingest_at": self.db.dialect.timestamp(self._now),
        }
        if self.db.insert_or_ignore("ingest_state", values) == 0:
            where = {"source_file": values.pop("source_file")}
            self.db.update("ingest_state", values, where)

    def _maybe_commit(self, path: pathlib.Path, offset: int, *,
                      complete: bool) -> None:
        """Commit the rows and the resume point TOGETHER.

        Order matters for crash safety. If the offset were committed first and
        the process died, the rows it accounted for would be lost forever. In
        one transaction, a crash simply means the batch is replayed, and the
        ingested_lines ledger makes the replay a no-op.
        """
        self._pending += 1
        if self._pending >= self.batch_size:
            self._save_state(path, offset, complete=complete)
            self.db.commit()
            self._pending = 0

    def process_file(self, path: pathlib.Path, *, force: bool = False) -> Action:
        state = self._load_state(path)
        action = decide_action(path, state, force=force)
        self.counts["files_scanned"] += 1

        if action.mode == "skip":
            self.counts["files_skipped"] += 1
            return action

        if path.suffix == ".gz":
            self._read_compressed(path)
            self._save_state(path, 0, complete=True)
            self.db.commit()
            return action

        offset = action.offset
        with open(path, "rb") as handle:
            if action.mode == "resume" and not offset_is_still_a_line_boundary(
                handle, offset
            ):
                action = Action("full", "stored offset is no longer a line "
                                        "boundary: the file was rewritten")
                offset = 0

            last_complete = offset
            for raw, new_offset in iter_complete_lines(handle, offset):
                if new_offset == -1:
                    # The incomplete trailing line. Counted as malformed for
                    # THIS run -- it was unusable now -- but not consumed, so
                    # it will be read again, and applied, once completed.
                    self.counts["lines_read"] += 1
                    self.counts["lines_malformed"] += 1
                    self.reasons["incomplete trailing line, not consumed"] += 1
                    break
                self.process_line(raw, str(path))
                last_complete = new_offset
                self._maybe_commit(path, last_complete, complete=False)

        self._save_state(path, last_complete, complete=False)
        self.db.commit()
        self._pending = 0
        return action

    def _read_compressed(self, path: pathlib.Path) -> None:
        """A .gz is immutable once rotated, so it is read whole.

        Cowrie never compresses; a .gz can only come from an external
        logrotate. A truncated archive raises rather than returning short, so
        it is caught here and counted instead of losing the whole file.
        """
        try:
            with gzip.open(path, "rb") as handle:
                for raw in handle:
                    # Strip exactly one trailing newline, matching what the
                    # plain-file path does, so a line's SHA-256 is identical
                    # whether it is read from cowrie.json or from the .gz that
                    # file later became. Without that, gzipping an
                    # already-ingested file would make every one of its lines
                    # look new.
                    body = raw[:-1] if raw.endswith(b"\n") else raw
                    self.process_line(body, str(path))
        except (OSError, EOFError) as exc:
            self.counts["lines_malformed"] += 1
            self.reasons[f"truncated or corrupt gzip archive: {exc}"] += 1

    def _load_state(self, path: pathlib.Path) -> dict[str, Any] | None:
        ph = self.db.dialect.placeholder
        columns = ("inode", "size_bytes", "offset_bytes", "head_line_sha256",
                   "is_compressed", "is_complete")
        cur = self.db.execute(
            f"SELECT {', '.join(columns)} FROM ingest_state "
            f"WHERE source_file = {ph}",
            [str(path)],
        )
        row = cur.fetchone()
        return None if row is None else dict(zip(columns, row))

    # -- run bookkeeping -------------------------------------------------

    def run(self, paths: list[pathlib.Path], *,
            force: bool = False) -> dict[str, Any]:
        cur = self.db.execute(
            self.db.dialect.insert("ingest_runs", ["started_at"]),
            [self.db.dialect.timestamp(self._now)],
        )
        run_id = cur.lastrowid
        decisions: list[tuple[str, Action]] = []

        for path in paths:
            decisions.append((str(path), self.process_file(path, force=force)))

        totals = {
            "files_scanned": self.counts["files_scanned"],
            "lines_read": self.counts["lines_read"],
            "lines_applied": self.counts["lines_applied"],
            "lines_duplicate": self.counts["lines_duplicate"],
            "lines_malformed": self.counts["lines_malformed"],
            "events_unknown": self.counts["events_unknown"],
            "events_incomplete": self.counts["events_incomplete"],
        }
        self.db.update(
            "ingest_runs",
            {**totals, "finished_at": self.db.dialect.timestamp(_utc_now())},
            {"run_id": run_id},
        )
        self.db.commit()

        return {
            "run_id": run_id,
            **totals,
            "files_skipped": self.counts["files_skipped"],
            "decisions": [{"file": name, "mode": a.mode, "reason": a.reason}
                          for name, a in decisions],
            "reasons": dict(self.reasons.most_common()),
        }


def _utc_now() -> str:
    moment = dt.datetime.now(dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}Z"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m shadowpot.ingest",
        description="Load Cowrie JSON logs into the ShadowPot schema.",
    )
    p.add_argument("paths", nargs="+", metavar="PATH",
                   help="log files, or directories holding cowrie.json*")
    p.add_argument("--db", default="data/shadowpot.db", metavar="DSN",
                   help="a SQLite path, sqlite:///path, or "
                        "mysql://user:password@host/database "
                        "(default: %(default)s)")
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH, metavar="N",
                   help="rows per transaction (default: %(default)s)")
    p.add_argument("--force-rescan", action="store_true",
                   help="ignore stored offsets and re-read every file. The "
                        "ingested_lines ledger still prevents duplicate rows, "
                        "so this is safe -- it is how the two idempotence "
                        "mechanisms are exercised independently.")
    p.add_argument("--json", action="store_true",
                   help="print the run summary as JSON")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = discover(args.paths)
    if not paths:
        print("no cowrie.json* files found in the given paths",
              file=sys.stderr)
        return 1

    database = dbmod.connect(args.db)
    try:
        loader = Loader(database, batch_size=args.batch)
        summary = loader.run(paths, force=args.force_rescan)
        synthetic = database.scalar(
            "SELECT COUNT(*) FROM sessions WHERE is_synthetic = 1"
        )
        sessions = database.scalar("SELECT COUNT(*) FROM sessions")
    finally:
        database.close()

    summary["sessions_total"] = sessions
    summary["sessions_synthetic"] = synthetic

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if not args.quiet:
        _print_summary(summary)
    return 0


def _print_summary(summary: dict[str, Any]) -> None:
    out = sys.stderr
    print("", file=out)
    for decision in summary["decisions"]:
        print(f"  {decision['mode']:7s} {decision['file']}"
              f"   ({decision['reason']})", file=out)
    print(
        f"\n  files {summary['files_scanned']} scanned, "
        f"{summary['files_skipped']} skipped\n"
        f"  lines {summary['lines_read']} read, "
        f"{summary['lines_applied']} applied, "
        f"{summary['lines_duplicate']} already ingested\n"
        f"  skipped {summary['lines_malformed']} malformed, "
        f"{summary['events_unknown']} unknown events, "
        f"{summary['events_incomplete']} incomplete events",
        file=out,
    )
    if summary["reasons"]:
        print("\n  why lines were skipped:", file=out)
        for reason, count in list(summary["reasons"].items())[:8]:
            print(f"    {count:6d}  {reason}", file=out)
    if summary["sessions_synthetic"]:
        print(
            f"\n  {'=' * 60}\n"
            f"   WARNING: {summary['sessions_synthetic']} of "
            f"{summary['sessions_total']} sessions are SYNTHETIC.\n"
            f"   No number from this database may be published as a\n"
            f"   measurement of real attacker behaviour.\n"
            f"  {'=' * 60}",
            file=out,
        )
    print("", file=out)


if __name__ == "__main__":
    raise SystemExit(main())

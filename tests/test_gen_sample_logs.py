"""Tests for the synthetic log generator.

Two kinds of test live here:

  * Fidelity: the generated events match docs/LOG_FORMAT.md exactly, including
    the awkward cases (absent `password`, absent `url`, `late: true`,
    `duration_ms`, sessions split across a rotation boundary). If these drift,
    the Phase 4 loader is being developed against a format Cowrie does not
    produce, and it will fail on the first real log file.

  * Safety: no generated address or URL can refer to anything real, and the
    generator refuses to overwrite data that might be a real capture. These
    are assertions about blast radius, not about correctness.

Run:
    python3 -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import pathlib
import re
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import gen_sample_logs as gen  # noqa: E402

# Reserved ranges the generator is restricted to. Duplicated here on purpose:
# a test that imported the constant from the module under test would pass even
# if someone widened it to the whole internet.
RESERVED = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
              "2001:db8::/32")
)

# Every eventid the generator is allowed to emit. A new one appearing here
# without a corresponding entry in docs/LOG_FORMAT.md is a documentation bug.
ALLOWED_EVENTS = {
    "cowrie.session.connect", "cowrie.client.version", "cowrie.client.kex",
    "cowrie.login.failed", "cowrie.login.success",
    "cowrie.command.input", "cowrie.command.failed",
    "cowrie.session.file_download", "cowrie.session.file_upload",
    "cowrie.session.closed",
    # real Cowrie events ShadowPot does not model
    "cowrie.client.size", "cowrie.session.params", "cowrie.log.closed",
    # the deliberate unknown-id fixture
    "cowrie.not.a.real.event",
}

_FIXTURE: dict | None = None


def _read(directory: pathlib.Path) -> dict:
    """Parse a generated directory into something tests can assert on."""
    events: list[dict] = []
    malformed: list[str] = []
    per_file_sessions: dict[str, set[str]] = {}
    lines_total = 0

    for path in sorted(directory.glob("cowrie.json*")):
        opener = gzip.open if path.suffix == ".gz" else open
        seen: set[str] = set()
        with opener(path, "rt", encoding="utf-8") as handle:
            for line in handle:
                lines_total += 1
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    malformed.append(line)
                    continue
                if not isinstance(obj, dict) or not isinstance(
                    obj.get("eventid"), str
                ):
                    malformed.append(line)
                    continue
                obj["_file"] = path.name
                events.append(obj)
                if "session" in obj:
                    seen.add(obj["session"])
        per_file_sessions[path.name] = seen

    return {
        "dir": directory,
        "events": events,
        "malformed": malformed,
        "lines_total": lines_total,
        "per_file_sessions": per_file_sessions,
        "manifest": json.loads((directory / "manifest.json").read_text()),
    }


def setUpModule() -> None:
    """Generate one fixture for the whole module.

    Deliberately larger than the minimum: the interesting cases (public-key
    attempts, `late` events, midnight-spanning sessions) are probabilistic, and
    a four-session fixture would usually contain none of them and pass
    vacuously.
    """
    global _FIXTURE
    tmp = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(tmp.cleanup)
    out = pathlib.Path(tmp.name) / "logs"
    gen.main(["--out", str(out), "--days", "4", "--sessions-per-day", "50",
              "--seed", "1337", "--quiet"])
    _FIXTURE = _read(out)


class GeneratedDataTestCase(unittest.TestCase):
    @property
    def fx(self) -> dict:
        assert _FIXTURE is not None
        return _FIXTURE

    def events(self, eventid: str) -> list[dict]:
        return [e for e in self.fx["events"] if e["eventid"] == eventid]


class TestSafety(GeneratedDataTestCase):
    """The generated data must be incapable of pointing at anything real."""

    def test_every_address_is_in_a_reserved_range(self):
        offenders = set()
        for event in self.fx["events"]:
            for key in ("src_ip", "dst_ip"):
                value = event.get(key)
                if not value:
                    continue
                addr = ipaddress.ip_address(value)
                if not any(addr in net for net in RESERVED):
                    offenders.add(value)
        self.assertEqual(
            offenders, set(),
            "synthetic logs must only contain RFC 5737 / RFC 3849 addresses, "
            "so that nobody blocks, reports or retaliates against a real host",
        )

    def test_every_url_uses_the_invalid_tld(self):
        urls = [e["url"] for e in self.fx["events"] if "url" in e]
        self.assertGreater(len(urls), 0, "no URLs generated at all")
        for url in urls:
            with self.subTest(url=url):
                host = re.sub(r"^[a-z]+://", "", url).split("/")[0]
                self.assertTrue(
                    host.endswith(".invalid"),
                    f"{host!r} is not under the reserved .invalid TLD",
                )

    def test_every_event_line_is_marked_synthetic(self):
        for event in self.fx["events"]:
            with self.subTest(eventid=event["eventid"]):
                self.assertIs(event.get("synthetic"), True)

    def test_marker_file_and_manifest_shout_about_it(self):
        marker = (self.fx["dir"] / "SYNTHETIC_DATA.txt").read_text()
        self.assertIn("SYNTHETIC SAMPLE DATA", marker)
        self.assertIn("MAY APPEAR ON A RESUME", marker.upper())
        self.assertIs(self.fx["manifest"]["synthetic"], True)

    def test_refuses_to_overwrite_data_without_a_synthetic_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            # Something that looks like a real capture: no synthetic marker.
            (target / "cowrie.json").write_text(
                '{"eventid":"cowrie.session.connect","src_ip":"8.8.8.8"}\n'
            )
            with self.assertRaises(SystemExit) as caught:
                gen.main(["--out", str(target), "--days", "1",
                          "--sessions-per-day", "2", "--quiet"])
            self.assertIn("refusing to overwrite", str(caught.exception))
            # The original file is untouched.
            self.assertIn("8.8.8.8", (target / "cowrie.json").read_text())

    def test_force_overrides_the_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "cowrie.json").write_text('{"eventid":"x"}\n')
            gen.main(["--out", str(target), "--days", "1",
                      "--sessions-per-day", "2", "--quiet", "--force"])
            self.assertIn("synthetic", (target / "cowrie.json").read_text())


class TestDeterminism(unittest.TestCase):
    def _generate(self, **over) -> pathlib.Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = pathlib.Path(tmp.name) / "logs"
        argv = ["--out", str(out), "--days", "2", "--sessions-per-day", "8",
                "--quiet"]
        for key, value in over.items():
            argv += [f"--{key.replace('_', '-')}", str(value)]
        gen.main(argv)
        return out

    @staticmethod
    def _digest(directory: pathlib.Path) -> str:
        h = hashlib.sha256()
        for path in sorted(directory.iterdir()):
            h.update(path.name.encode())
            h.update(path.read_bytes())
        return h.hexdigest()

    def test_same_seed_is_byte_identical(self):
        """Including the gzip member.

        gzip stamps an mtime into its header by default, which would make
        output differ run to run even with identical content. The generator
        pins mtime=0 and an empty filename field for exactly this reason.
        """
        self.assertEqual(
            self._digest(self._generate(seed=42)),
            self._digest(self._generate(seed=42)),
        )

    def test_different_seed_differs(self):
        self.assertNotEqual(
            self._digest(self._generate(seed=42)),
            self._digest(self._generate(seed=43)),
        )

    def test_start_date_is_fixed_not_today(self):
        """Output must be reproducible years from now, so the date range comes
        from an argument with a fixed default rather than the system clock."""
        self.assertEqual(gen.parse_args([]).start_date, "2026-11-01")
        out = self._generate()
        days = {
            e["timestamp"][:10]
            for e in _read(out)["events"]
            if e["eventid"] == "cowrie.session.connect"
        }
        self.assertTrue(
            all(d.startswith("2026-11-0") for d in days), sorted(days)
        )


class TestFormatFidelity(GeneratedDataTestCase):
    """Everything here mirrors a specific claim in docs/LOG_FORMAT.md."""

    def test_only_documented_event_ids_appear(self):
        seen = {e["eventid"] for e in self.fx["events"]}
        self.assertTrue(
            seen <= ALLOWED_EVENTS, f"undocumented event ids: {seen - ALLOWED_EVENTS}"
        )

    def test_shared_attributes_on_every_event(self):
        for event in self.fx["events"]:
            with self.subTest(eventid=event["eventid"]):
                for key in ("eventid", "timestamp", "session", "sensor"):
                    self.assertIn(key, event)

    def test_time_key_is_never_present(self):
        """cowrie.json strips `time` and `system`; only `timestamp` survives.
        A loader that falls back to a numeric epoch has nothing to fall back
        to, so the generator must not supply one.
        """
        for event in self.fx["events"]:
            self.assertNotIn("time", event)
            self.assertNotIn("system", event)

    def test_timestamps_are_canonical_z_by_default(self):
        pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
        for event in self.fx["events"]:
            with self.subTest(ts=event["timestamp"]):
                self.assertRegex(event["timestamp"], pattern)

    def test_offset_form_is_available(self):
        """Cowrie emits ...+0000 (no colon) whenever TZ is not UTC. The loader
        must canonicalize it, so a fixture has to exist."""
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "logs"
            gen.main(["--out", str(out), "--days", "1",
                      "--sessions-per-day", "4", "--quiet",
                      "--timestamp-form", "offset"])
            stamps = [e["timestamp"] for e in _read(out)["events"]]
        self.assertTrue(stamps)
        for stamp in stamps:
            with self.subTest(ts=stamp):
                self.assertTrue(stamp.endswith("+0000"))
                self.assertNotIn("+00:00", stamp)

    def test_client_version_field_is_named_version(self):
        events = self.events("cowrie.client.version")
        self.assertTrue(events)
        for event in events:
            self.assertIn("version", event)
            self.assertNotIn("client_version", event)

    def test_hassh_really_is_the_md5_of_hassh_algorithms(self):
        """Makes the functional dependency hassh -> hassh_algorithms true in
        the fixtures, so Phase 2's kex_fingerprints table is exercised with
        real data rather than arbitrary 32-character strings.
        """
        events = self.events("cowrie.client.kex")
        self.assertTrue(events)
        for event in events:
            with self.subTest(hassh=event["hassh"]):
                self.assertEqual(
                    event["hassh"],
                    hashlib.md5(event["hasshAlgorithms"].encode()).hexdigest(),
                )

    def test_kex_algorithm_fields_are_lists_not_strings(self):
        for event in self.events("cowrie.client.kex"):
            for key in ("kexAlgs", "keyAlgs", "encCS", "macCS", "compCS",
                        "langCS"):
                with self.subTest(key=key):
                    self.assertIsInstance(event[key], list)

    def test_hassh_does_not_cover_key_algs(self):
        """keyAlgs is not an input to the HASSH digest, so one fingerprint must
        be able to appear with different host-key algorithm offers. If this
        ever becomes false the generator is accidentally asserting a
        dependency that Cowrie does not have."""
        by_hassh: dict[str, set[str]] = {}
        for event in self.events("cowrie.client.kex"):
            by_hassh.setdefault(event["hassh"], set()).add(
                ",".join(event["keyAlgs"])
            )
        self.assertTrue(
            any(len(v) > 1 for v in by_hassh.values()),
            "no HASSH value appeared with two different keyAlgs offers; the "
            "fixture no longer exercises the N1 non-dependency",
        )

    def test_password_logins_carry_a_password(self):
        events = [
            e for e in self.fx["events"]
            if e["eventid"].startswith("cowrie.login.")
            and "fingerprint" not in e
        ]
        self.assertTrue(events)
        for event in events:
            self.assertIn("password", event)
            self.assertIn("username", event)

    def test_publickey_logins_carry_no_password_at_all(self):
        """The case that breaks a nullable-password credentials table."""
        events = [
            e for e in self.fx["events"]
            if e["eventid"].startswith("cowrie.login.") and "fingerprint" in e
        ]
        self.assertTrue(
            events, "fixture contains no public-key attempts to test with"
        )
        for event in events:
            with self.subTest(session=event["session"]):
                self.assertNotIn("password", event)
                self.assertIn("username", event)
                self.assertIn("type", event)

    def test_empty_password_is_generated_as_real_data(self):
        """'' is one of the most-tried passwords, which is why it cannot
        double as a 'no password offered' sentinel."""
        self.assertTrue(
            any(e.get("password") == ""
                for e in self.fx["events"]
                if e["eventid"].startswith("cowrie.login.")),
            "no empty-password attempt generated",
        )

    def test_command_field_is_named_input(self):
        events = self.events("cowrie.command.input")
        self.assertTrue(events)
        for event in events:
            self.assertIn("input", event)
            self.assertNotIn("command", event)

    def test_no_event_carries_a_sequence_number(self):
        """Nothing in a Cowrie event says which command came first. That is why
        commands.seq is derived rather than stored."""
        for event in self.fx["events"]:
            for key in ("seq", "sequence", "index"):
                self.assertNotIn(key, event)

    def test_session_closed_reports_integer_duration_ms(self):
        events = self.events("cowrie.session.closed")
        self.assertTrue(events)
        for event in events:
            with self.subTest(session=event["session"]):
                self.assertIsInstance(event["duration_ms"], int)
                self.assertGreaterEqual(event["duration_ms"], 0)
                self.assertNotIn(
                    "duration", event,
                    "the legacy `duration` field was removed upstream in "
                    "Cowrie 3.0.4 and must never be emitted",
                )

    def test_some_downloads_have_no_url(self):
        downloads = self.events("cowrie.session.file_download")
        self.assertTrue(downloads)
        without = [e for e in downloads if "url" not in e]
        self.assertTrue(
            without,
            "stdin and shell-redirect captures have no url; the brief had "
            "this column NOT NULL",
        )
        for event in without:
            self.assertIn("shasum", event)

    def test_uploads_use_filename_and_never_a_url(self):
        for event in self.events("cowrie.session.file_upload"):
            self.assertIn("filename", event)
            self.assertNotIn("url", event)

    def test_shasum_is_64_lowercase_hex(self):
        values = [e["shasum"] for e in self.fx["events"] if "shasum" in e]
        self.assertTrue(values)
        for value in values:
            with self.subTest(shasum=value):
                self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_session_ids_are_twelve_lowercase_hex(self):
        for event in self.events("cowrie.session.connect"):
            with self.subTest(session=event["session"]):
                self.assertRegex(event["session"], r"^[0-9a-f]{12}$")

    def test_session_ids_are_unique(self):
        ids = [e["session"] for e in self.events("cowrie.session.connect")]
        self.assertEqual(len(ids), len(set(ids)))


class TestOrderingAndRotation(GeneratedDataTestCase):
    def test_late_events_arrive_after_session_closed(self):
        """A loader that treats session.closed as a terminator drops exactly
        these rows -- completed malware downloads."""
        late = [e for e in self.fx["events"] if e.get("late") is True]
        self.assertTrue(late, "fixture contains no late events")
        closed_at = {
            e["session"]: e["timestamp"]
            for e in self.events("cowrie.session.closed")
        }
        for event in late:
            with self.subTest(session=event["session"]):
                self.assertIn(event["session"], closed_at)
                self.assertGreater(event["timestamp"], closed_at[event["session"]])

    def test_a_session_spans_the_rotation_boundary(self):
        """With daily rotation, a session running over midnight has its connect
        in one file and its closed in the next."""
        files_by_session: dict[str, set[str]] = {}
        for event in self.fx["events"]:
            if event["eventid"] == "cowrie.not.a.real.event":
                continue  # the orphan fixture, not a real session
            files_by_session.setdefault(event["session"], set()).add(
                event["_file"]
            )
        split = {s: f for s, f in files_by_session.items() if len(f) > 1}
        self.assertTrue(split, "no session spans two files")
        for session, files in split.items():
            with self.subTest(session=session):
                self.assertEqual(len(files), 2, "a session spans at most 2 days")

    def test_rotated_filenames_match_cowrie_daily_rotation(self):
        names = sorted(p.name for p in self.fx["dir"].glob("cowrie.json*"))
        self.assertIn("cowrie.json", names, "the current day has no suffix")
        for name in names:
            if name == "cowrie.json":
                continue
            with self.subTest(name=name):
                self.assertRegex(name, r"^cowrie\.json\.\d{4}-\d{2}-\d{2}(\.gz)?$")

    def test_a_gzipped_file_exists_and_is_readable(self):
        """Cowrie never gzips; a .gz can only come from external logrotate, so
        the loader's compressed path needs a fixture."""
        archives = list(self.fx["dir"].glob("cowrie.json.*.gz"))
        self.assertTrue(archives)
        with gzip.open(archives[0], "rt", encoding="utf-8") as handle:
            first = json.loads(handle.readline())
        self.assertIs(first["synthetic"], True)

    def test_events_within_a_file_are_time_ordered(self):
        """A real Cowrie file is append-only, so its event stream is monotonic.

        The deliberately injected fixtures are excluded: the unknown-event
        line carries a fixed midnight timestamp but is inserted mid-file on
        purpose, so that a loader which assumes monotonic input is exercised
        rather than accommodated.
        """
        by_file: dict[str, list[str]] = {}
        for event in self.fx["events"]:
            if event["eventid"] == "cowrie.not.a.real.event":
                continue
            by_file.setdefault(event["_file"], []).append(event["timestamp"])
        self.assertTrue(by_file)
        for name, stamps in by_file.items():
            with self.subTest(file=name):
                self.assertEqual(stamps, sorted(stamps))


class TestEdgeCaseFixtures(GeneratedDataTestCase):
    def test_malformed_lines_are_present_and_counted(self):
        self.assertTrue(self.fx["malformed"])
        self.assertEqual(
            len(self.fx["malformed"]),
            self.fx["manifest"]["tally"]["malformed_lines"],
        )

    def test_malformed_lines_are_not_only_at_the_edges(self):
        """A parser that guards only its first and last line must still fail
        these fixtures.

        Damage at the edges of a file is the easy case and the one a naive
        loader survives by accident. These fixtures sit in the interior.
        """
        for path in sorted(self.fx["dir"].glob("cowrie.json*")):
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as handle:
                text = handle.read()
            lines = text.split("\n")
            # A trailing newline yields a final empty element that is an
            # artefact of splitting, not a line in the file.
            if lines and lines[-1] == "":
                lines.pop()
            bad_at = [i for i, line in enumerate(lines) if _unparseable(line)]
            with self.subTest(file=path.name):
                self.assertTrue(bad_at, f"{path.name} has no malformed line")
                interior = [i for i in bad_at if 0 < i < len(lines) - 1]
                self.assertTrue(
                    interior,
                    f"{path.name}: malformed lines only at the edges "
                    f"(indices {bad_at} of {len(lines)} lines)",
                )

    def test_unknown_event_ids_are_counted_separately_from_malformed(self):
        """An invented event id is a well-formed event we do not model, which
        is a different ingest_runs column from an unparseable line."""
        tally = self.fx["manifest"]["tally"]
        invented = [
            e for e in self.fx["events"]
            if e["eventid"] == "cowrie.not.a.real.event"
        ]
        self.assertEqual(len(invented), tally["unknown_event_lines"])
        self.assertGreater(tally["unmodelled_events"], 0)
        self.assertEqual(
            self.fx["manifest"]["expected_ingest_run"]["events_unknown"],
            tally["unmodelled_events"] + tally["unknown_event_lines"],
        )

    def test_orphan_sessions_have_no_connect_event(self):
        """An event may arrive for a session whose connect was rotated away
        before ingestion. That is a data condition, not an error."""
        orphans = set(self.fx["manifest"]["orphan_session_ids"])
        self.assertTrue(orphans)
        connected = {e["session"] for e in self.events("cowrie.session.connect")}
        self.assertEqual(orphans & connected, set())

    def test_current_file_ends_with_a_truncated_line(self):
        text = (self.fx["dir"] / "cowrie.json").read_text()
        self.assertFalse(
            text.endswith("\n"),
            "the truncated-final-line fixture requires no trailing newline",
        )
        self.assertTrue(_unparseable(text.rsplit("\n", 1)[-1]))

    def test_no_edge_cases_flag_produces_a_clean_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "logs"
            gen.main(["--out", str(out), "--days", "2",
                      "--sessions-per-day", "6", "--quiet",
                      "--no-edge-cases", "--gzip-oldest", "0"])
            parsed = _read(out)
        self.assertEqual(parsed["malformed"], [])
        self.assertEqual(parsed["manifest"]["tally"]["malformed_lines"], 0)
        self.assertEqual(parsed["manifest"]["orphan_session_ids"], [])
        self.assertEqual(len(parsed["events"]), parsed["lines_total"])


class TestManifestAccuracy(GeneratedDataTestCase):
    """The manifest is what Phase 4 and 5 tests assert against, so it has to
    agree with the bytes on disk rather than with the generator's intentions.
    """

    def test_line_counts_match_disk(self):
        expected = self.fx["manifest"]["expected_ingest_run"]
        self.assertEqual(expected["lines_read"], self.fx["lines_total"])
        self.assertEqual(expected["lines_malformed"], len(self.fx["malformed"]))

        # lines_applied counts only events the loader MODELS. A real Cowrie
        # event we do not model is written as an event and then skipped as
        # events_unknown, so it must not be counted here.
        unmodelled = set(gen.UNMODELLED_EVENTS) | {"cowrie.not.a.real.event"}
        applicable = [
            e for e in self.fx["events"] if e["eventid"] not in unmodelled
        ]
        self.assertEqual(expected["lines_applied"], len(applicable))
        self.assertEqual(
            expected["events_unknown"],
            len(self.fx["events"]) - len(applicable),
        )

    def test_per_file_counts_match_disk(self):
        for name, counts in self.fx["manifest"]["files"].items():
            path = self.fx["dir"] / name
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as handle:
                actual = sum(1 for _ in handle)
            with self.subTest(file=name):
                self.assertEqual(counts["lines"], actual)

    def test_session_and_login_tallies_match_disk(self):
        tally = self.fx["manifest"]["tally"]
        self.assertEqual(
            tally["sessions"], len(self.events("cowrie.session.connect"))
        )
        self.assertEqual(
            tally["login_successes"], len(self.events("cowrie.login.success"))
        )
        self.assertEqual(
            tally["commands"],
            len(self.events("cowrie.command.input"))
            + len(self.events("cowrie.command.failed")),
        )
        self.assertEqual(
            tally["uploads"], len(self.events("cowrie.session.file_upload"))
        )

    def test_top_credentials_match_a_recount(self):
        counts: dict[tuple[str, str], int] = {}
        for event in self.fx["events"]:
            if event["eventid"].startswith("cowrie.login.") and "password" in event:
                key = (event["username"], event["password"])
                counts[key] = counts.get(key, 0) + 1
        recounted = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        from_manifest = [
            ((c["username"], c["password"]), c["attempts"])
            for c in self.fx["manifest"]["top_credentials"]
        ]
        self.assertEqual(from_manifest, recounted)

    def test_only_the_accepted_credential_ever_succeeds(self):
        accepted = tuple(self.fx["manifest"]["accepted_credential"])
        for event in self.events("cowrie.login.success"):
            with self.subTest(session=event["session"]):
                self.assertEqual(
                    (event["username"], event["password"]), accepted
                )


def _unparseable(line: str) -> bool:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return True
    return not isinstance(obj, dict) or not isinstance(obj.get("eventid"), str)


if __name__ == "__main__":
    unittest.main()

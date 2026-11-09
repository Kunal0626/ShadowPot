"""Tests for shadowpot.report.

The report is the only part of ShadowPot that a stranger reads, so it gets
tested for two things that have nothing to do with arithmetic.

HONESTY. A synthetic database must produce a report that says so, in the first
few lines, and must keep saying so. A database that MIXES real and generated
sessions must produce a louder warning still, because that is the one state in
which a generated figure could be mistaken for a measurement. A successful
login must never be described as a compromise.

ESCAPING. Every username, password, command and URL in this report came from
whoever connected to the honeypot. They are rendered into Markdown tables, and
from there into terminals and browsers. `cat /proc/cpuinfo | grep name` would
split its table row into extra columns; an ANSI escape sequence in a username
would be interpreted by whatever `cat`s the file. The crafted-input tests at
the bottom are the ones worth reading.
"""

from __future__ import annotations

import json
import pathlib
import re
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from shadowpot import db as dbmod                  # noqa: E402
from shadowpot import report as rp                 # noqa: E402
from shadowpot.ingest import Loader, discover      # noqa: E402
import gen_sample_logs as gen                       # noqa: E402


def strip_synthetic_markers(directory: pathlib.Path) -> None:
    """Rewrite generated logs so they look like a real capture.

    The only difference between a real Cowrie line and one of ours is the
    "synthetic" key, so removing it is enough to exercise the real-data path
    without needing a real honeypot.
    """
    for path in directory.glob("cowrie.json*"):
        if path.suffix == ".gz":
            path.unlink()
            continue
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                out.append(line)
                continue
            if isinstance(obj, dict):
                obj.pop("synthetic", None)
                out.append(json.dumps(obj, separators=(",", ":")))
            else:
                out.append(line)
        path.write_text("\n".join(out) + "\n", encoding="utf-8")


def load(db_path: pathlib.Path, *log_dirs: pathlib.Path) -> None:
    database = dbmod.connect(str(db_path))
    try:
        Loader(database).run(discover([str(d) for d in log_dirs]))
    finally:
        database.close()


def scalar(db_path: pathlib.Path, sql: str) -> object:
    """Query and close. An unclosed sqlite3.Connection surfaces as a
    ResourceWarning from whatever unrelated code triggers garbage collection,
    which is a miserable thing to track down later -- so no test opens one
    without a finally."""
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(sql).fetchone()[0]
    finally:
        conn.close()


def report_for(db_path: pathlib.Path, **kwargs) -> str:
    database = dbmod.connect(str(db_path), apply_schema=False,
                             apply_indexes=False)
    try:
        data = rp.collect(database)
        data.db_path = str(db_path)
        return rp.build(data, **kwargs)
    finally:
        database.close()


def table_cell_counts(markdown: str) -> list[tuple[int, int, int]]:
    """Parse the Markdown's tables the way a renderer would.

    Returns (line number, expected cells, actual cells) for every row whose
    count does not match its header -- which is exactly what an unescaped
    pipe in attacker content produces.
    """
    lines = markdown.splitlines()

    def cells(line: str) -> int:
        inner = line.strip()
        return len(re.split(r"(?<!\\)\|", inner[1:-1]))

    problems: list[tuple[int, int, int]] = []
    index, in_code = 0, False
    while index < len(lines):
        if lines[index].strip().startswith("```"):
            in_code = not in_code
            index += 1
            continue
        if (not in_code and lines[index].strip().startswith("|")
                and index + 1 < len(lines)
                and re.fullmatch(r"\|[\s\-:|]+\|", lines[index + 1].strip())):
            width = cells(lines[index])
            cursor = index + 2
            while cursor < len(lines) and lines[cursor].strip().startswith("|"):
                got = cells(lines[cursor])
                if got != width:
                    problems.append((cursor + 1, width, got))
                cursor += 1
            index = cursor
            continue
        index += 1
    return problems


_FIXTURE: dict = {}


def setUpModule() -> None:
    tmp = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(tmp.cleanup)
    root = pathlib.Path(tmp.name)

    synthetic_logs = root / "synthetic"
    gen.main(["--out", str(synthetic_logs), "--days", "3",
              "--sessions-per-day", "40", "--seed", "77", "--quiet"])

    real_logs = root / "real"
    gen.main(["--out", str(real_logs), "--days", "3", "--sessions-per-day", "40",
              "--seed", "99", "--quiet"])
    strip_synthetic_markers(real_logs)

    _FIXTURE["synthetic_db"] = root / "synthetic.db"
    load(_FIXTURE["synthetic_db"], synthetic_logs)

    _FIXTURE["real_db"] = root / "real.db"
    load(_FIXTURE["real_db"], real_logs)

    _FIXTURE["mixed_db"] = root / "mixed.db"
    load(_FIXTURE["mixed_db"], real_logs, synthetic_logs)

    _FIXTURE["empty_db"] = root / "empty.db"
    dbmod.connect(str(_FIXTURE["empty_db"])).close()

    _FIXTURE["root"] = root
    _FIXTURE["synthetic_report"] = report_for(_FIXTURE["synthetic_db"])
    _FIXTURE["real_report"] = report_for(_FIXTURE["real_db"])
    _FIXTURE["mixed_report"] = report_for(_FIXTURE["mixed_db"])
    _FIXTURE["empty_report"] = report_for(_FIXTURE["empty_db"])


class TestMarkdownCell(unittest.TestCase):
    def test_pipes_are_escaped(self):
        """`cat x | grep y` would otherwise split its row into extra cells."""
        rendered = rp.md_cell("cat /proc/cpuinfo | grep name", code=True)
        self.assertIn("\\|", rendered)
        self.assertNotRegex(rendered, r"(?<!\\)\|")

    def test_pipes_escaped_in_plain_cells_too(self):
        self.assertNotRegex(rp.md_cell("a|b"), r"(?<!\\)\|")

    def test_control_characters_are_made_visible(self):
        """An ANSI escape in a username must not be interpreted by whatever
        terminal displays this file."""
        rendered = rp.md_cell("\x1b[31mred\x00\x07", code=True)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x00", rendered)
        self.assertIn("\\x1b", rendered)
        self.assertIn("\\x00", rendered)

    def test_newlines_cannot_break_out_of_a_row(self):
        rendered = rp.md_cell("line one\nline two", code=True)
        self.assertNotIn("\n", rendered)

    def test_backtick_fence_grows_to_fit_the_content(self):
        """A code span cannot contain a backtick run as long as its fence."""
        rendered = rp.md_cell("echo `id`", code=True)
        self.assertTrue(rendered.startswith("``"), rendered)
        self.assertIn("`id`", rendered)
        longer = rp.md_cell("a ``` b", code=True)
        self.assertTrue(longer.startswith("````"), longer)

    def test_long_values_are_truncated_visibly(self):
        rendered = rp.md_cell("x" * 500, max_len=40)
        self.assertEqual(len(rendered), 40)
        self.assertTrue(rendered.endswith("…"))

    def test_none_and_empty_string_are_distinguishable(self):
        """An empty password is real data; a missing one is not. The report
        must not render them identically."""
        self.assertEqual(rp.md_cell(None), "n/a")
        self.assertEqual(rp.md_cell(""), "*(empty string)*")
        self.assertEqual(rp.md_cell("", code=True), "*(empty string)*")

    def test_numbers_get_thousands_separators(self):
        self.assertEqual(rp.md_cell(1234567), "1,234,567")
        self.assertEqual(rp.md_cell(12.3456), "12.35")

    def test_booleans_render_as_words(self):
        self.assertEqual(rp.md_cell(True), "yes")
        self.assertEqual(rp.md_cell(False), "no")


class TestAsciiBars(unittest.TestCase):
    def test_bars_scale_to_the_peak(self):
        lines = rp.ascii_bars(["a", "b"], [10, 5], width=10)
        self.assertEqual(lines[0], "```")
        self.assertIn("#" * 10, lines[1])
        self.assertIn("#" * 5, lines[2])

    def test_all_zero_values_do_not_divide_by_zero(self):
        self.assertIn("*Nothing to plot.*", rp.ascii_bars(["a"], [0]))

    def test_no_data_is_handled(self):
        self.assertIn("*Nothing to plot.*", rp.ascii_bars([], []))


class TestSyntheticLabelling(unittest.TestCase):
    def test_synthetic_report_leads_with_the_banner(self):
        text = _FIXTURE["synthetic_report"]
        head = "\n".join(text.splitlines()[:8])
        self.assertIn(rp.BANNER_SYNTHETIC, head)
        self.assertIn("may be published as a measurement", text)

    def test_synthetic_report_repeats_the_warning_in_the_narrative(self):
        text = _FIXTURE["synthetic_report"]
        narrative = text.split("## What attackers did")[1].split("##")[0]
        self.assertIn("generated data, not real attackers", narrative)

    def test_synthetic_report_repeats_the_warning_in_limitations(self):
        limitations = _FIXTURE["synthetic_report"].split("## Limitations")[1]
        self.assertIn(rp.BANNER_SYNTHETIC, limitations)

    def test_real_report_has_no_synthetic_banner(self):
        """The guard must not fire on real data, or it becomes noise that
        people learn to ignore."""
        text = _FIXTURE["real_report"]
        self.assertNotIn(rp.BANNER_SYNTHETIC, text)
        self.assertNotIn("generated data, not real attackers", text)

    def test_real_fixture_really_is_flagged_as_real(self):
        self.assertEqual(
            scalar(_FIXTURE["real_db"],
                   "SELECT COUNT(*) FROM sessions WHERE is_synthetic = 1"),
            0,
        )

    def test_mixed_database_gets_the_loudest_warning(self):
        """The dangerous case: the report cannot tell you which rows fed which
        total, so every aggregate is unusable as evidence."""
        text = _FIXTURE["mixed_report"]
        self.assertIn("MIXED WITH REAL DATA", text)
        self.assertIn("unusable as evidence", text)

    def test_mixed_state_is_detected_rather_than_assumed(self):
        database = dbmod.connect(str(_FIXTURE["mixed_db"]), apply_schema=False,
                                 apply_indexes=False)
        try:
            data = rp.collect(database)
            self.assertEqual(data.synthetic_state, "mixed")
            total = data.summary["sessions"]
            synthetic = data.summary["synthetic_sessions"]
            self.assertGreater(synthetic, 0)
            self.assertLess(synthetic, total)
        finally:
            database.close()

    def test_the_three_states_are_distinguished(self):
        for key, expected in (("synthetic_db", "all"), ("real_db", "none"),
                              ("mixed_db", "mixed")):
            database = dbmod.connect(str(_FIXTURE[key]), apply_schema=False,
                                     apply_indexes=False)
            try:
                with self.subTest(db=key):
                    self.assertEqual(rp.collect(database).synthetic_state,
                                     expected)
            finally:
                database.close()


class TestNarrativeHonesty(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _FIXTURE["real_report"]
        self.narrative = (self.text.split("## What attackers did")[1]
                          .split("## Provenance")[0])

    def test_numbers_in_the_narrative_come_from_the_data(self):
        database = dbmod.connect(str(_FIXTURE["real_db"]), apply_schema=False,
                                 apply_indexes=False)
        try:
            data = rp.collect(database)
            summary = data.summary
        finally:
            database.close()
        for key in ("sessions", "distinct_ips", "login_attempts"):
            with self.subTest(key=key):
                self.assertIn(f"{summary[key]:,}", self.narrative)

    def test_a_successful_login_is_not_called_a_compromise(self):
        """A honeypot accepts whatever it is configured to accept. Reporting
        that as a breach would be the single most misleading sentence this
        tool could produce."""
        self.assertIn("not evidence of a compromise", self.narrative)
        for word in ("breach", "compromised", "owned", "pwned"):
            with self.subTest(word=word):
                self.assertNotIn(word, self.narrative.lower())

    def test_the_heuristic_is_named_as_one(self):
        self.assertIn("heuristic", self.narrative)
        self.assertIn("queries/13_bot_vs_human.sql", self.narrative)

    def test_unmeasured_things_say_so(self):
        self.assertIn("not measured", self.narrative)
        self.assertIn("GeoIP", self.narrative)

    def test_dropped_lines_are_disclosed_in_the_narrative(self):
        self.assertIn("could not be used", self.narrative)

    def test_limitations_section_lists_the_known_caveats(self):
        limitations = self.text.split("## Limitations")[1]
        for expected in ("Geolocation", "heuristic", "not a compromise",
                         "unique per sensor"):
            with self.subTest(expected=expected):
                self.assertIn(expected, limitations)


class TestReportStructure(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _FIXTURE["synthetic_report"]

    def test_tables_are_well_formed(self):
        problems = table_cell_counts(self.text)
        self.assertEqual(problems, [],
                         f"{len(problems)} table rows have the wrong cell "
                         "count, which means attacker content broke out of a "
                         "cell")

    def test_report_contains_a_table_for_every_analytic(self):
        for heading in ("Credentials", "Source addresses", "Shell activity",
                        "Files", "Clients", "Timeline", "Session durations",
                        "Data quality", "Limitations", "Provenance"):
            with self.subTest(heading=heading):
                self.assertIn(f"## {heading}", self.text)

    def test_every_table_states_the_question_it_answers(self):
        from shadowpot import analytics
        for query in analytics.load_queries():
            if query.name in ("dataset_summary",):
                continue
            with self.subTest(query=query.name):
                self.assertIn(query.question, self.text,
                              f"{query.name}'s question is missing, so a "
                              "reader cannot tell what the table means")

    def test_provenance_records_versions_and_the_regeneration_command(self):
        provenance = self.text.split("## Provenance")[1].split("##")[0]
        for expected in ("SQLite", "Python", "Machine", "schema version",
                         "python3 -m shadowpot.report"):
            with self.subTest(expected=expected):
                self.assertIn(expected, provenance)

    def test_top_n_is_respected_and_disclosed(self):
        small = report_for(_FIXTURE["synthetic_db"], top=3)
        self.assertIn("(top 3 of", small)
        section = small.split("### Most-run commands")[1].split("###")[0]
        rows = [l for l in section.splitlines()
                if l.startswith("|") and not re.fullmatch(r"\|[\s\-:|]+\|", l)]
        self.assertEqual(len(rows), 4, "one header row plus three data rows")

    def test_empty_database_produces_a_usable_report(self):
        """A report must not crash or divide by zero on a database with no
        sessions -- that is the state every new deployment starts in."""
        text = _FIXTURE["empty_report"]
        self.assertIn("No sessions are recorded", text)
        self.assertIn("python3 -m shadowpot.ingest", text)
        self.assertEqual(table_cell_counts(text), [])
        self.assertNotIn(rp.BANNER_SYNTHETIC, text)


class TestAttackerControlledContent(unittest.TestCase):
    """End to end with deliberately hostile strings in the log.

    Everything here is something a real attacker can put on the wire: a
    command with pipes, a username with an ANSI escape, a password with
    backticks and a newline, a URL with a pipe in its query string.
    """

    HOSTILE = {
        "username": "ro|ot\x1b[31m",
        "password": "p`a``ss\nword|",
        "command": "cat /etc/passwd | grep root | wc -l",
        "url": "http://evil.invalid/a|b?x=`id`",
    }

    @classmethod
    def setUpClass(cls) -> None:
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        logs = root / "logs"
        logs.mkdir()

        def event(eventid, ts, **extra):
            base = {"eventid": eventid, "timestamp": ts,
                    "session": "a1b2c3d4e5f6", "src_ip": "198.51.100.7",
                    "sensor": "h1"}
            base.update(extra)
            return json.dumps(base)

        (logs / "cowrie.json").write_text("\n".join([
            event("cowrie.session.connect", "2026-11-06T14:00:00.000000Z",
                  protocol="ssh", src_port=1, dst_port=2222),
            event("cowrie.login.success", "2026-11-06T14:00:01.000000Z",
                  username=cls.HOSTILE["username"],
                  password=cls.HOSTILE["password"]),
            event("cowrie.command.input", "2026-11-06T14:00:02.000000Z",
                  input=cls.HOSTILE["command"]),
            event("cowrie.command.input", "2026-11-06T14:00:03.000000Z",
                  input="x" * 400),
            event("cowrie.session.file_download",
                  "2026-11-06T14:00:04.000000Z", url=cls.HOSTILE["url"],
                  shasum="a" * 64, outfile="var/lib/cowrie/downloads/" + "a" * 64),
            event("cowrie.session.closed", "2026-11-06T14:00:05.000000Z",
                  duration_ms=5000),
        ]) + "\n", encoding="utf-8")

        cls.db = root / "hostile.db"
        load(cls.db, logs)
        cls.text = report_for(cls.db)

    def test_the_hostile_data_actually_loaded(self):
        """The strings must survive the round trip intact. Escaping is for
        presentation; the database holds what the attacker actually sent."""
        self.assertEqual(
            scalar(self.db, "SELECT username FROM credentials"),
            self.HOSTILE["username"],
        )
        self.assertEqual(scalar(self.db, "SELECT COUNT(*) FROM commands"), 2)

    def test_no_table_row_is_broken_by_the_hostile_strings(self):
        problems = table_cell_counts(self.text)
        self.assertEqual(problems, [], f"broken rows: {problems}")

    def test_no_raw_control_characters_reach_the_report(self):
        """A report is a file people `cat`. An unescaped ESC would be
        interpreted by the terminal."""
        for char in ("\x1b", "\x00", "\x07"):
            with self.subTest(char=repr(char)):
                self.assertNotIn(char, self.text)

    def test_the_escape_is_shown_rather_than_dropped(self):
        """Escaping must not silently delete evidence: the analyst needs to
        know the username contained an escape sequence."""
        self.assertIn("\\x1b", self.text)

    def test_oversized_command_is_truncated_not_omitted(self):
        self.assertIn("…", self.text)
        self.assertNotIn("x" * 300, self.text)
        commands = self.text.split("### Most-run commands")[1].split("###")[0]
        self.assertIn("x" * 50, commands, "the long command is still listed")

    def test_pipes_in_a_url_survive_as_data(self):
        self.assertIn("evil.invalid", self.text)
        self.assertIn("a\\|b", self.text)


class TestCharts(unittest.TestCase):
    def test_charts_fail_with_an_actionable_message_without_matplotlib(self):
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            pass
        else:
            self.skipTest("matplotlib is installed, so the missing-dependency "
                          "path cannot be exercised")
        database = dbmod.connect(str(_FIXTURE["synthetic_db"]),
                                 apply_schema=False, apply_indexes=False)
        try:
            data = rp.collect(database)
        finally:
            database.close()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError) as caught:
                rp.write_charts(data, pathlib.Path(tmp) / "charts")
        message = str(caught.exception)
        self.assertIn("pip install matplotlib", message)
        self.assertIn("omit --charts", message)

    def test_the_default_report_needs_no_optional_dependency(self):
        """The point of the ASCII bars: the report renders from a clean clone
        with nothing installed."""
        self.assertIn("```", _FIXTURE["synthetic_report"])
        self.assertNotIn("![", _FIXTURE["synthetic_report"])


class TestCli(unittest.TestCase):
    def test_main_writes_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "nested" / "report.md"
            code = rp.main(["--db", str(_FIXTURE["synthetic_db"]),
                            "--out", str(out), "--quiet"])
            self.assertEqual(code, 0)
            self.assertTrue(out.is_file())
            self.assertIn(rp.BANNER_SYNTHETIC, out.read_text())

    def test_committed_sample_report_exists_and_is_labelled(self):
        """A stranger cloning the repo should be able to see what the output
        looks like without running anything."""
        sample = REPO_ROOT / "reports" / "sample-report.md"
        self.assertTrue(sample.is_file(), "reports/sample-report.md is missing")
        text = sample.read_text()
        self.assertIn(rp.BANNER_SYNTHETIC, text)
        self.assertEqual(table_cell_counts(text), [])


if __name__ == "__main__":
    unittest.main()

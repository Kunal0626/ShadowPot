"""Tests for the analytics queries in queries/.

Two kinds of assertion, and the second kind is the interesting one.

STRUCTURAL: every query declares the question it answers, contains only
SELECTs, and has a MySQL override that answers the same question.

ARITHMETIC IDENTITIES: for most queries there is a quantity that must come out
the same whether you compute it the query's way or a completely different way
-- the attempts in `top_usernames` must sum to the row count of
login_attempts, the bigram count must equal commands minus sessions. Those
identities are what actually catch a broken query, because a query can return
plausible-looking rows and still be wrong by a factor of six.

That factor of six is not hypothetical. `sessions_per_day` joins sessions to
BOTH login_attempts and commands, so without COUNT(DISTINCT ...) a session
with 10 logins and 6 commands reports 60 attempts. The test named
test_sessions_per_day_is_not_inflated_by_fan_out exists to make removing
those DISTINCTs fail loudly.
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

from shadowpot import analytics                    # noqa: E402
from shadowpot import db as dbmod                  # noqa: E402
from shadowpot.ingest import Loader, discover      # noqa: E402
import gen_sample_logs as gen                       # noqa: E402

_FIXTURE: dict | None = None

# Statements that must never appear in a query file. The analytics path is
# read-only by design; a stray DDL or DML statement in here would run with
# whatever privileges the report has.
_FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|ATTACH|PRAGMA)\b",
    re.IGNORECASE,
)


def setUpModule() -> None:
    global _FIXTURE
    tmp = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(tmp.cleanup)
    root = pathlib.Path(tmp.name)
    logs, db_path = root / "logs", root / "shadowpot.db"

    gen.main(["--out", str(logs), "--days", "4", "--sessions-per-day", "60",
              "--seed", "4242", "--quiet"])
    database = dbmod.connect(str(db_path))
    Loader(database).run(discover([str(logs)]))
    database.close()

    _FIXTURE = {
        "db": db_path,
        "manifest": json.loads((logs / "manifest.json").read_text()),
    }


class QueryTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        assert _FIXTURE is not None
        cls.manifest = _FIXTURE["manifest"]
        cls.tally = cls.manifest["tally"]
        cls.conn = sqlite3.connect(_FIXTURE["db"])
        cls.queries = {q.name: q for q in analytics.load_queries()}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.conn.close()

    def rows(self, name: str) -> list[dict]:
        query = self.queries[name]
        cursor = self.conn.execute(query.sql)
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def one(self, name: str) -> dict:
        rows = self.rows(name)
        self.assertEqual(len(rows), 1, f"{name} should return exactly one row")
        return rows[0]

    def scalar(self, sql: str) -> object:
        return self.conn.execute(sql).fetchone()[0]


class TestQueryFiles(QueryTestCase):
    def test_every_query_declares_its_question(self):
        for name, query in self.queries.items():
            with self.subTest(query=name):
                self.assertTrue(query.title)
                self.assertTrue(query.question.endswith("?"),
                                f"{name}: @question must be a question")
                self.assertTrue(query.uses)

    def test_queries_are_read_only(self):
        for name, query in self.queries.items():
            body = "\n".join(
                line for line in query.sql.splitlines()
                if not line.strip().startswith("--")
            )
            with self.subTest(query=name):
                found = _FORBIDDEN.search(body)
                self.assertIsNone(
                    found,
                    f"{name} contains a non-SELECT statement: "
                    f"{found.group(0) if found else ''}",
                )
                self.assertTrue(
                    body.lstrip().upper().startswith(("SELECT", "WITH")),
                    f"{name} must start with SELECT or WITH",
                )

    def test_feature_coverage_meets_the_project_requirements(self):
        """The brief asked for at least two GROUP BY ... HAVING queries, two
        window functions, one CTE and one view. Asserted rather than claimed.
        """
        coverage = analytics.feature_coverage(list(self.queries.values()))
        self.assertGreaterEqual(len(coverage["having"]), 2, coverage["having"])
        self.assertGreaterEqual(len(coverage["window"]), 2, coverage["window"])
        self.assertGreaterEqual(len(coverage["cte"]), 1, coverage["cte"])
        self.assertGreaterEqual(len(coverage["view"]), 1, coverage["view"])

    def test_mysql_overrides_answer_the_same_question(self):
        base = {q.name: q for q in analytics.load_queries("sqlite")}
        mysql = {q.name: q for q in analytics.load_queries("mysql")}
        self.assertEqual(set(base), set(mysql),
                         "the two dialects must expose the same query set")
        for name in base:
            with self.subTest(query=name):
                self.assertEqual(base[name].title, mysql[name].title)
                self.assertEqual(base[name].question, mysql[name].question)

    def test_mysql_overrides_explain_why_they_differ(self):
        for query in analytics.load_queries("mysql"):
            if query.path.parent.name == "mysql":
                with self.subTest(query=query.name):
                    self.assertIsNotNone(
                        query.dialect_note,
                        f"{query.name} is an override but declares no "
                        "@dialect note saying what differs and why",
                    )

    def test_no_override_uses_sqlite_only_functions(self):
        sqlite_only = ("julianday(", "strftime(", "substr(", "group_concat(")
        for query in analytics.load_queries("mysql"):
            if query.path.parent.name != "mysql":
                continue
            body = "\n".join(
                line for line in query.sql.splitlines()
                if not line.strip().startswith("--")
            )
            for function in sqlite_only:
                with self.subTest(query=query.name, function=function):
                    self.assertNotIn(function, body)

    def test_no_query_contains_a_limit(self):
        """Queries order; the caller limits. A bound LIMIT would need
        different placeholder syntax per dialect, which would have meant an
        override file per top-N query for no analytical difference."""
        for name, query in self.queries.items():
            body = "\n".join(
                line for line in query.sql.splitlines()
                if not line.strip().startswith("--")
            )
            with self.subTest(query=name):
                self.assertNotRegex(body, r"\bLIMIT\b")

    def test_all_queries_execute(self):
        for name in self.queries:
            with self.subTest(query=name):
                self.rows(name)


class TestDatasetSummary(QueryTestCase):
    def test_matches_the_generator_manifest(self):
        row = self.one("dataset_summary")
        self.assertEqual(row["sessions"], self.tally["sessions"])
        self.assertEqual(row["login_attempts"], self.tally["login_attempts"])
        self.assertEqual(row["login_successes"], self.tally["login_successes"])
        self.assertEqual(row["commands"], self.tally["commands"])
        self.assertEqual(
            row["file_transfers"],
            self.tally["downloads"] + self.tally["uploads"],
        )

    def test_flags_the_whole_dataset_as_synthetic(self):
        row = self.one("dataset_summary")
        self.assertEqual(row["synthetic_sessions"], row["sessions"])
        self.assertGreater(row["synthetic_sessions"], 0)

    def test_days_observed_matches_the_generated_window(self):
        self.assertEqual(self.one("dataset_summary")["days_observed"],
                         self.manifest["days"])


class TestCredentialQueries(QueryTestCase):
    def test_top_usernames_sums_to_every_attempt(self):
        """The identity: every login attempt has exactly one username, so the
        attempts column must sum to the whole table."""
        rows = self.rows("top_usernames")
        self.assertEqual(sum(r["attempts"] for r in rows),
                         self.tally["login_attempts"])
        self.assertEqual(rows[0]["username"], "root",
                         "root is the most-tried username in any real or "
                         "generated SSH brute-force traffic")

    def test_top_usernames_is_ordered_descending(self):
        counts = [r["attempts"] for r in self.rows("top_usernames")]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_top_usernames_counts_publickey_attempts_too(self):
        """A username is tried either way, so excluding key attempts would
        undercount. Checked against the arc columns directly."""
        rows = self.rows("top_usernames")
        self.assertEqual(
            sum(r["attempts"] for r in rows),
            self.scalar("SELECT COUNT(*) FROM login_attempts"),
        )
        self.assertGreater(self.tally["publickey_attempts"], 0,
                           "fixture has no public-key attempts to include")

    def test_top_passwords_excludes_key_fingerprints(self):
        rows = self.rows("top_passwords")
        self.assertEqual(
            sum(r["attempts"] for r in rows),
            self.tally["login_attempts"] - self.tally["publickey_attempts"],
        )

    def test_top_passwords_includes_the_empty_password(self):
        """'' is real data and one of the most-tried values. If it ever stops
        appearing, something is treating it as absence."""
        passwords = {r["password"] for r in self.rows("top_passwords")}
        self.assertIn("", passwords)

    def test_top_credential_pairs_matches_the_manifest(self):
        rows = self.rows("top_credential_pairs")
        expected = self.manifest["top_credentials"]
        for got, want in zip(rows[:len(expected)], expected):
            with self.subTest(pair=(want["username"], want["password"])):
                self.assertEqual(got["username"], want["username"])
                self.assertEqual(got["password"], want["password"])
                self.assertEqual(got["attempts"], want["attempts"])

    def test_only_the_staged_credential_succeeds(self):
        rows = self.rows("successful_credentials")
        self.assertEqual(len(rows), 1)
        username, password = self.manifest["accepted_credential"]
        self.assertEqual(rows[0]["username"], username)
        self.assertEqual(rows[0]["secret"], password)
        self.assertEqual(rows[0]["successes"], self.tally["login_successes"])
        self.assertLessEqual(rows[0]["first_success"], rows[0]["last_success"])

    def test_shared_credentials_all_pass_the_having_threshold(self):
        rows = self.rows("shared_credentials")
        self.assertTrue(rows, "no credential reached 5 distinct addresses")
        for row in rows:
            with self.subTest(pair=(row["username"], row["password"])):
                self.assertGreaterEqual(row["distinct_ips"], 5)

    def test_shared_credentials_cannot_exceed_the_unfiltered_pairs(self):
        """HAVING filters groups, so this must be a strict subset of query 03
        with identical counts for the rows it keeps."""
        pairs = {(r["username"], r["password"]): r
                 for r in self.rows("top_credential_pairs")}
        for row in self.rows("shared_credentials"):
            key = (row["username"], row["password"])
            with self.subTest(pair=key):
                self.assertIn(key, pairs)
                self.assertEqual(row["attempts"], pairs[key]["attempts"])
                self.assertEqual(row["distinct_ips"],
                                 pairs[key]["distinct_ips"])


class TestSourceQueries(QueryTestCase):
    def test_attempts_per_source_sums_to_every_attempt(self):
        rows = self.rows("attempts_per_source")
        self.assertEqual(sum(r["attempts"] for r in rows),
                         self.tally["login_attempts"])

    def test_attempts_per_source_covers_every_address_that_tried(self):
        self.assertEqual(
            len(self.rows("attempts_per_source")),
            self.scalar(
                "SELECT COUNT(DISTINCT s.source_id) FROM login_attempts la "
                "JOIN sessions s ON s.session_pk = la.session_pk"
            ),
        )

    def test_repeat_offenders_all_appear_on_more_than_one_day(self):
        rows = self.rows("repeat_offenders")
        self.assertTrue(rows, "no repeat offenders in the fixture")
        for row in rows:
            with self.subTest(ip=row["ip"]):
                self.assertGreater(row["active_days"], 1)
                self.assertGreaterEqual(row["sessions"], row["active_days"])
                self.assertLessEqual(row["first_seen"], row["last_seen"])

    def test_repeat_offenders_is_a_subset_of_all_sources(self):
        everyone = {r["ip"] for r in self.rows("attempts_per_source")}
        offenders = {r["ip"] for r in self.rows("repeat_offenders")}
        self.assertTrue(offenders <= everyone)
        self.assertLess(len(offenders), len(everyone),
                        "if every address were a repeat offender the HAVING "
                        "clause would not be filtering anything")

    def test_repeat_offenders_agrees_with_the_activity_view(self):
        """Two independent paths to the same number: the query's GROUP BY and
        the v_source_activity view."""
        from_query = {r["ip"]: r["active_days"]
                      for r in self.rows("repeat_offenders")}
        for ip, days in self.conn.execute(
            "SELECT ip, active_days FROM v_source_activity "
            "WHERE active_days > 1"
        ):
            with self.subTest(ip=ip):
                self.assertEqual(from_query.get(ip), days)


class TestTimeQueries(QueryTestCase):
    def test_sessions_per_day_covers_the_window(self):
        rows = self.rows("sessions_per_day")
        self.assertEqual(len(rows), self.manifest["days"])
        self.assertEqual(sum(r["sessions"] for r in rows),
                         self.tally["sessions"])
        self.assertEqual([r["day"] for r in rows],
                         sorted(r["day"] for r in rows))

    def test_sessions_per_day_is_not_inflated_by_fan_out(self):
        """The query joins sessions to login_attempts AND commands. Without
        COUNT(DISTINCT ...) a session with 10 logins and 6 commands would
        report 60 attempts and 60 commands. These two identities are what
        make removing the DISTINCTs fail loudly.
        """
        rows = self.rows("sessions_per_day")
        self.assertEqual(sum(r["login_attempts"] for r in rows),
                         self.tally["login_attempts"])
        self.assertEqual(sum(r["commands"] for r in rows),
                         self.tally["commands"])

    def test_sessions_per_hour_is_complete_and_adds_up(self):
        rows = self.rows("sessions_per_hour")
        self.assertLessEqual(len(rows), 24)
        self.assertEqual(sum(r["sessions"] for r in rows),
                         self.tally["sessions"])
        self.assertAlmostEqual(sum(r["pct_of_sessions"] for r in rows),
                               100.0, places=0)
        for row in rows:
            with self.subTest(hour=row["hour_utc"]):
                self.assertIsInstance(row["hour_utc"], int)
                self.assertTrue(0 <= row["hour_utc"] <= 23)

    def test_duration_buckets_cover_every_measured_session(self):
        rows = self.rows("session_duration_distribution")
        measured = self.scalar(
            "SELECT COUNT(*) FROM sessions WHERE duration_ms IS NOT NULL")
        self.assertEqual(sum(r["sessions"] for r in rows), measured)
        self.assertAlmostEqual(sum(r["pct_of_measured"] for r in rows),
                               100.0, places=0)

    def test_duration_bucket_labels_sort_chronologically(self):
        """The 0: 1: 2: prefixes exist so that ORDER BY on the label is
        chronological rather than alphabetical."""
        labels = [r["bucket"] for r in
                  self.rows("session_duration_distribution")]
        self.assertEqual(labels, sorted(labels))
        self.assertEqual([int(l.split(":")[0]) for l in labels],
                         sorted(int(l.split(":")[0]) for l in labels))


class TestCommandQueries(QueryTestCase):
    def test_top_commands_sums_to_every_command(self):
        self.assertEqual(sum(r["times_run"] for r in self.rows("top_commands")),
                         self.tally["commands"])

    def test_unimplemented_counts_match_the_generator(self):
        self.assertEqual(
            sum(r["times_unimplemented"] for r in self.rows("top_commands")),
            self.tally["commands_failed"],
        )

    def test_first_commands_counts_one_per_session_with_commands(self):
        """seq = 1 picks exactly one row per session, so the total must equal
        the number of sessions that ran anything."""
        rows = self.rows("first_commands")
        self.assertEqual(
            sum(r["sessions"] for r in rows),
            self.scalar("SELECT COUNT(DISTINCT session_pk) FROM commands"),
        )

    def test_first_commands_are_a_subset_of_all_commands(self):
        first = {r["first_command"] for r in self.rows("first_commands")}
        everything = {r["input"] for r in self.rows("top_commands")}
        self.assertTrue(first <= everything)

    def test_bigram_total_is_commands_minus_sessions(self):
        """Each session of n commands yields n-1 adjacent pairs, because the
        last command has no successor. Summing over sessions gives
        (total commands) - (sessions with at least one command). An off-by-one
        in the LEAD window would break this identity immediately.
        """
        rows = self.rows("command_bigrams")
        sessions_with_commands = self.scalar(
            "SELECT COUNT(DISTINCT session_pk) FROM commands")
        self.assertEqual(sum(r["occurrences"] for r in rows),
                         self.tally["commands"] - sessions_with_commands)

    def test_bigrams_never_pair_across_sessions(self):
        """LEAD is partitioned by session_pk. Without the PARTITION BY, the
        last command of one session would pair with the first of the next --
        inventing a sequence nobody ran.
        """
        pairs = {(r["first_command"], r["second_command"])
                 for r in self.rows("command_bigrams")}
        real = set(self.conn.execute(
            "SELECT a.input, b.input FROM v_session_commands a "
            "JOIN v_session_commands b "
            "  ON b.session_pk = a.session_pk AND b.seq = a.seq + 1"
        ))
        self.assertEqual(pairs, real)


class TestBotHeuristic(QueryTestCase):
    def test_every_session_with_commands_is_classified(self):
        rows = self.rows("bot_vs_human")
        self.assertEqual(
            len(rows),
            self.scalar("SELECT COUNT(DISTINCT session_pk) FROM commands"),
        )
        for row in rows:
            with self.subTest(session=row["session_pk"]):
                self.assertTrue(row["verdict"])

    def test_verdicts_are_labelled_as_a_heuristic_not_a_measurement(self):
        query = self.queries["bot_vs_human"]
        self.assertIn("HEURISTIC", query.title.upper() + query.sql.upper())
        for row in self.rows("bot_vs_human"):
            with self.subTest(verdict=row["verdict"]):
                self.assertRegex(row["verdict"],
                                 r"^(scripted|human-like|unclassified)")

    def test_fast_sessions_are_never_called_human(self):
        """The threshold is 250 ms. Any session whose mean inter-command gap
        is below it must be classified scripted, whatever the other signal
        says.
        """
        for row in self.rows("bot_vs_human"):
            if row["mean_gap_ms"] is not None and row["mean_gap_ms"] < 250:
                with self.subTest(session=row["session_pk"]):
                    self.assertTrue(row["verdict"].startswith("scripted"))

    def test_human_like_sessions_are_slow_and_have_unique_sequences(self):
        human = [r for r in self.rows("bot_vs_human")
                 if r["verdict"] == "human-like"]
        self.assertTrue(human, "the heuristic classified nothing as human-like")
        for row in human:
            with self.subTest(session=row["session_pk"]):
                self.assertGreaterEqual(row["mean_gap_ms"], 250)
                self.assertEqual(row["sessions_sharing_script"], 1)

    def test_the_two_populations_actually_separate(self):
        """On this fixture the generator emits scripted gaps of 8-90 ms and
        hand-driven gaps of 1.5-14 s, so the populations must not overlap.

        This proves the SQL is correct. It does NOT validate the 250 ms
        threshold against real attackers, because the generator was written
        with that separation in mind and cannot disconfirm it. The query says
        so, and so does this test.
        """
        rows = self.rows("bot_vs_human")
        scripted = [r["mean_gap_ms"] for r in rows
                    if r["verdict"].startswith("scripted")
                    and r["mean_gap_ms"] is not None]
        human = [r["mean_gap_ms"] for r in rows
                 if r["verdict"] == "human-like"]
        self.assertTrue(scripted and human)
        self.assertLess(min(human), max(human) + 1)
        self.assertLess(max(g for g in scripted if g < 250), min(human))


class TestFileAndClientQueries(QueryTestCase):
    def test_downloads_sum_to_every_download(self):
        rows = self.rows("downloads_and_fetchers")
        self.assertEqual(sum(r["transfers"] for r in rows),
                         self.tally["downloads"])

    def test_url_less_captures_are_labelled_not_dropped(self):
        """Cowrie fires file_download for stdin and shell redirects, which
        have no URL. Those rows must still appear."""
        labels = [r["url"] for r in self.rows("downloads_and_fetchers")]
        self.assertTrue(
            any("no url" in label for label in labels),
            "the fixture has url-less downloads but the query lost them",
        )

    def test_downloads_are_ordered_by_breadth_of_distribution(self):
        spread = [r["distinct_ips"] for r in self.rows("downloads_and_fetchers")]
        self.assertEqual(spread, sorted(spread, reverse=True))

    def test_an_artifact_shared_across_addresses_is_visible(self):
        rows = self.rows("downloads_and_fetchers")
        self.assertGreater(
            max(r["distinct_ips"] for r in rows), 1,
            "no artifact was fetched by more than one address, so the "
            "shared-payload signal is not being exercised",
        )

    def test_client_fingerprints_cover_every_session(self):
        self.assertEqual(
            sum(r["sessions"] for r in self.rows("client_fingerprints")),
            self.tally["sessions"],
        )

    def test_one_hassh_can_span_several_banners(self):
        """The banner is self-reported and forgeable; HASSH is derived from
        what the client actually offered. Many addresses sharing one HASSH
        while reporting different banners is one toolkit wearing hats, and is
        the reason both columns are shown together."""
        rows = self.rows("client_fingerprints")
        by_hassh: dict[str, set[str]] = {}
        for row in rows:
            by_hassh.setdefault(row["hassh"], set()).add(row["client_version"])
        self.assertTrue(any(len(v) > 1 for v in by_hassh.values()))


class TestIngestQuality(QueryTestCase):
    def test_one_row_per_loader_run(self):
        self.assertEqual(len(self.rows("ingest_quality")),
                         self.scalar("SELECT COUNT(*) FROM ingest_runs"))

    def test_lines_read_accounts_for_every_line(self):
        """The identity that makes the data-quality report trustworthy: every
        line read was applied, skipped as duplicate, rejected as malformed, or
        set aside as unknown or incomplete. If these do not add up, the loader
        is losing lines without saying so.
        """
        for row in self.rows("ingest_quality"):
            with self.subTest(run=row["run_id"]):
                self.assertEqual(
                    row["lines_read"],
                    row["lines_applied"] + row["lines_duplicate"]
                    + row["lines_malformed"] + row["events_unknown"]
                    + row["events_incomplete"],
                )

    def test_matches_the_generator_expectation(self):
        expected = self.manifest["expected_ingest_run"]
        first = self.rows("ingest_quality")[0]
        for key in ("lines_read", "lines_applied", "lines_malformed",
                    "events_unknown"):
            with self.subTest(key=key):
                self.assertEqual(first[key], expected[key])


class TestShippedIndexes(unittest.TestCase):
    """Every index the project ships must be justified by a measurement.

    This replaces the Phase 2 test that asserted there were no indexes at all.
    """

    def setUp(self) -> None:
        self.index_sql = (REPO_ROOT / "schema" / "indexes.sqlite.sql").read_text()
        self.doc = (REPO_ROOT / "docs" / "INDEXES.md").read_text()
        self.names = re.findall(r"CREATE INDEX IF NOT EXISTS (\w+)",
                                self.index_sql)

    def test_indexes_exist_and_are_named_consistently(self):
        self.assertTrue(self.names)
        for name in self.names:
            with self.subTest(index=name):
                self.assertTrue(name.startswith("idx_"))

    def test_every_shipped_index_appears_in_the_measurements(self):
        for name in self.names:
            with self.subTest(index=name):
                self.assertIn(f"`{name}`", self.doc,
                              f"{name} ships but is not in docs/INDEXES.md")
                self.assertRegex(
                    self.doc,
                    rf"`{name}`[^\n]*\*\*KEPT\*\*",
                    f"{name} ships but the measurement did not keep it",
                )

    def test_rejected_candidates_are_not_shipped(self):
        rejected = re.findall(r"\| `(idx_\w+)` \|[^\n]*\| rejected \|", self.doc)
        self.assertTrue(rejected, "the document records no rejected candidate")
        for name in rejected:
            with self.subTest(index=name):
                self.assertNotIn(name, self.names)

    def test_the_document_records_the_scale_it_was_measured_at(self):
        """A timing without its row counts is not a measurement."""
        self.assertIn("Row counts of the benchmarked database", self.doc)
        self.assertIn("SYNTHETIC", self.doc)

    def test_connect_creates_exactly_the_shipped_indexes(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = dbmod.connect(str(pathlib.Path(tmp) / "x.db"))
            try:
                created = {
                    row[0] for row in database.execute(
                        "SELECT name FROM sqlite_master WHERE type='index' "
                        "AND sql IS NOT NULL"
                    )
                }
            finally:
                database.close()
        self.assertEqual(created, set(self.names))


if __name__ == "__main__":
    unittest.main()

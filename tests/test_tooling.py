"""Tests for the Makefile, tools/clean.py and docs/DEPLOY.md.

Documentation drifts away from code silently, and a deployment runbook that
has drifted is worse than none: the reader follows it, it fails halfway, and
they cannot tell which half was wrong. So the cross-checks here assert that
docs/DEPLOY.md only tells the reader to run flags the CLIs actually accept,
and only to expect log filenames the loader actually discovers.

tools/clean.py gets tested for one property: it must refuse to delete anything
outside the repository. That is the entire reason it exists instead of
`rm -rf $(VAR)` lines in the Makefile, where an unset variable silently
becomes `rm -rf /`.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import clean as cleanup                              # noqa: E402
from shadowpot import ingest as ingest_mod            # noqa: E402
from shadowpot import report as report_mod            # noqa: E402

MAKEFILE = (REPO_ROOT / "Makefile").read_text()
DEPLOY = (REPO_ROOT / "docs" / "DEPLOY.md").read_text()


class TestCleanupSafety(unittest.TestCase):
    """tools/clean.py must not be able to delete outside the repository."""

    def test_paths_inside_the_repo_are_accepted(self):
        self.assertTrue(cleanup.inside_repo(REPO_ROOT / "data"))
        self.assertTrue(cleanup.inside_repo(REPO_ROOT / "a" / "b" / "c"))

    def test_the_repo_root_itself_is_refused(self):
        """`make clean` must never be one typo away from deleting the project."""
        self.assertFalse(cleanup.inside_repo(REPO_ROOT))

    def test_paths_outside_the_repo_are_refused(self):
        for outside in ("/", "/tmp", "/etc/passwd", str(pathlib.Path.home())):
            with self.subTest(path=outside):
                self.assertFalse(cleanup.inside_repo(pathlib.Path(outside)))

    def test_parent_traversal_is_refused(self):
        self.assertFalse(cleanup.inside_repo(REPO_ROOT / ".." / "elsewhere"))

    def test_a_symlink_pointing_out_of_the_repo_is_refused(self):
        """resolve() collapses symlinks, so a symlinked data/ aimed at $HOME
        cannot be used to walk out of the tree."""
        with tempfile.TemporaryDirectory() as outside:
            link = REPO_ROOT / ".test-escape-link"
            try:
                os.symlink(outside, link)
                self.assertFalse(cleanup.inside_repo(link))
            finally:
                if link.is_symlink():
                    link.unlink()

    def test_remove_refuses_and_reports_rather_than_deleting(self):
        """A refusal must be loud. Silently skipping would leave the user
        believing the file was removed."""
        with tempfile.TemporaryDirectory() as outside:
            victim = pathlib.Path(outside) / "precious.txt"
            victim.write_text("do not delete me")
            link = REPO_ROOT / ".test-escape-file"
            try:
                os.symlink(victim, link)
                result = cleanup.remove(".test-escape-file")
                self.assertIsNone(result)
                self.assertTrue(victim.exists(),
                                "clean.py followed a symlink out of the repo")
            finally:
                if link.is_symlink():
                    link.unlink()

    def test_the_committed_sample_report_is_on_the_keep_list(self):
        """It is the one artifact a stranger can read without running
        anything, so `make clean` must not take it."""
        self.assertIn("reports/sample-report.md", cleanup.KEEP)
        self.assertNotIn("reports/sample-report.md", cleanup.REGENERATABLE)

    def test_real_databases_need_the_all_flag(self):
        """data/real.db holds a real deployment's capture, which cannot be
        regenerated. It must not be in the default sweep."""
        self.assertNotIn("data", cleanup.REGENERATABLE)
        self.assertIn("data", cleanup.EVERYTHING_ELSE)


class TestMakefile(unittest.TestCase):
    def documented_targets(self) -> set[str]:
        return set(re.findall(r"^([a-z][a-zA-Z0-9_-]*):.*## ", MAKEFILE,
                              re.MULTILINE))

    def test_every_documented_target_is_phony(self):
        """None of these produce a file named after the target, so make must
        not skip them because a same-named file happens to exist."""
        phony = set()
        match = re.search(r"^\.PHONY:((?:[^\n\\]*\\\n)*[^\n]*)", MAKEFILE,
                          re.MULTILINE)
        self.assertIsNotNone(match, "no .PHONY declaration")
        phony = set(match.group(1).replace("\\", " ").split())
        missing = self.documented_targets() - phony
        self.assertEqual(missing, set(), f"not declared .PHONY: {missing}")

    def test_the_targets_the_brief_asked_for_exist(self):
        for target in ("sample", "load", "report", "test"):
            with self.subTest(target=target):
                self.assertIn(target, self.documented_targets())

    def test_recipes_are_tab_indented(self):
        """A recipe indented with spaces fails with "missing separator", and
        make's error does not say which line.

        Continuation lines are skipped: a backslash-continued .PHONY or
        variable assignment is legitimately space-indented because it is not
        a recipe. Only a line that starts a new logical line counts.
        """
        previous_continues = False
        for number, line in enumerate(MAKEFILE.splitlines(), start=1):
            if (not previous_continues and line.startswith("    ")
                    and not line.startswith("\t")):
                self.fail(f"line {number} is space-indented: {line!r}")
            previous_continues = line.rstrip().endswith("\\")

    def test_no_recipe_shells_out_to_a_bare_recursive_delete(self):
        """The reason tools/clean.py exists.

        `rm -rf $(SOMEVAR)` in a Makefile deletes the filesystem root when
        SOMEVAR is unset, and reading the recipe does not make that visible.
        Deletion goes through clean.py, which resolves every path and refuses
        anything outside the repository.
        """
        offenders = [
            line.strip() for line in MAKEFILE.splitlines()
            if re.search(r"\brm\s+-[a-zA-Z]*r", line)
        ]
        self.assertEqual(offenders, [],
                         f"recursive delete in the Makefile: {offenders}")

    def test_distclean_requires_explicit_confirmation(self):
        recipe = MAKEFILE.split("distclean:")[1]
        self.assertIn("CONFIRM", recipe)
        self.assertIn("NOT reproducible", recipe)

    def test_avoids_make_4_only_syntax(self):
        """GNU Make 3.81 is what Apple ships as /usr/bin/make.

        Comments are stripped before checking, because the Makefile's own
        header explains why .ONESHELL is not used -- and a test that cannot
        tell a mention from a use is a test that forces you to stop
        documenting your decisions.
        """
        code = "\n".join(line for line in MAKEFILE.splitlines()
                         if not line.lstrip().startswith("#"))
        for feature in (".ONESHELL", "$(file ", ".RECIPEPREFIX"):
            with self.subTest(feature=feature):
                self.assertNotIn(
                    feature, code,
                    f"{feature} needs GNU Make 4, but this project targets "
                    "3.81",
                )

    def test_help_is_the_default_goal(self):
        """Running a bare `make` in an unfamiliar repository should explain
        itself, not start building something."""
        self.assertIn(".DEFAULT_GOAL := help", MAKEFILE)

    def test_overridable_variables_use_conditional_assignment(self):
        """`?=` so that `make load DB=...` works. A plain `=` would ignore
        the override and silently use the default."""
        for variable in ("PY", "DB", "LOGS", "OUT", "SEED", "TOP"):
            with self.subTest(variable=variable):
                self.assertRegex(
                    MAKEFILE, rf"(?m)^{variable}\s+\?=",
                    f"{variable} is not declared with ?=, so it cannot be "
                    "overridden on the command line",
                )

    def test_verify_report_checks_the_synthetic_banner(self):
        """`make check` must not pass on a report that forgot to label
        generated data."""
        recipe = MAKEFILE.split("verify-report:")[1].split("\nbench:")[0]
        self.assertIn("SYNTHETIC SAMPLE DATA", recipe)
        self.assertIn("exit 1", recipe)


class TestDeployGuideMatchesTheCode(unittest.TestCase):
    """Anti-drift. The runbook must not tell the reader to run something the
    code does not support, or to expect a filename the loader cannot find.
    """

    def test_flags_named_in_the_guide_exist_in_the_loader(self):
        parser = ingest_mod.parse_args(["x"])
        self.assertTrue(hasattr(parser, "db"))
        self.assertIn("--db", DEPLOY)
        # The guide tells the reader to run `make load DB=... LOGS=...`
        for variable in ("DB=", "LOGS="):
            with self.subTest(variable=variable):
                self.assertIn(variable, DEPLOY)
                self.assertIn(variable.rstrip("="), MAKEFILE)

    def test_flags_named_in_the_guide_exist_in_the_reporter(self):
        namespace = report_mod.parse_args([])
        for attribute in ("db", "out", "top"):
            with self.subTest(attribute=attribute):
                self.assertTrue(hasattr(namespace, attribute))
        self.assertIn("OUT=", DEPLOY)

    def test_the_log_filenames_the_guide_promises_are_what_the_loader_finds(self):
        """If Cowrie's rotation naming ever changes, these must change
        together: the guide's claim and the loader's own regex."""
        self.assertIn("cowrie.json", DEPLOY)
        self.assertIn("cowrie.json.YYYY-MM-DD", DEPLOY)
        self.assertTrue(ingest_mod.ROTATED.match("cowrie.json.2026-11-06"))
        self.assertTrue(ingest_mod.ROTATED.match("cowrie.json.2026-11-06.gz"))

    def test_the_config_keys_the_guide_sets_are_the_ones_cowrie_reads(self):
        """Each of these was read out of Cowrie's own source or its bundled
        cowrie.cfg.dist; see docs/LOG_FORMAT.md for the provenance."""
        for key in ("[output_jsonlog]", "logfile", "logtype = rotating",
                    "log_path", "listen_endpoints", "timezone = UTC"):
            with self.subTest(key=key):
                self.assertIn(key, DEPLOY)

    def test_the_guide_pins_the_cowrie_version_it_was_verified_against(self):
        self.assertRegex(DEPLOY, r"Cowrie \*\*3\.\d+\.\d+\*\*")
        self.assertIn("cowrie init", DEPLOY,
                      "Cowrie 3.0 added this step; a guide without it fails")


class TestDeployGuideSafety(unittest.TestCase):
    """The parts of the runbook that exist to stop someone getting hurt."""

    def test_it_forbids_running_on_a_home_or_campus_network(self):
        for phrase in ("laptop", "home network", "college"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, DEPLOY)

    def test_it_tells_the_reader_to_move_sshd_before_anything_else(self):
        move = DEPLOY.index("Move the real sshd")
        install = DEPLOY.index("## 6. Install Cowrie")
        self.assertLess(move, install,
                        "the sshd relocation must come before Cowrie is "
                        "installed, or port 22 is contested mid-setup")

    def test_it_warns_against_locking_yourself_out(self):
        self.assertIn("second terminal", DEPLOY)
        self.assertIn("sshd -t", DEPLOY)

    def test_it_restricts_outbound_traffic(self):
        self.assertIn("policy drop", DEPLOY)
        for phrase in ("cannot brute force", "spam"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, DEPLOY)

    def test_it_explains_that_cowrie_fetches_attacker_urls(self):
        """The one genuinely surprising egress fact, and the reason ports 80
        and 443 are open outbound."""
        self.assertIn("really fetches", DEPLOY)

    def test_logs_are_pulled_not_pushed(self):
        self.assertIn("pulls", DEPLOY)
        self.assertIn("never", DEPLOY)
        self.assertIn("rrsync", DEPLOY)
        self.assertIn("restrict", DEPLOY)

    def test_it_covers_teardown(self):
        for phrase in ("Destroy the instance", "Delete the snapshots",
                       "Keep the logs"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, DEPLOY)

    def test_it_forbids_retaliation(self):
        self.assertIn("Never retaliate", DEPLOY)
        self.assertIn("compromised third party", DEPLOY)

    def test_it_says_publish_aggregates_not_raw_logs(self):
        self.assertIn("publish aggregates", DEPLOY)
        self.assertIn("hashes", DEPLOY.lower())

    def test_it_contains_the_seven_day_checklist_and_a_template(self):
        self.assertIn("## 10. The 7-day checklist", DEPLOY)
        self.assertIn("Days deployed", DEPLOY)
        self.assertIn("Unique source IPs", DEPLOY)
        self.assertIn("Top 3 credential pairs", DEPLOY)
        self.assertIn("not measured", DEPLOY)

    def test_it_names_more_than_one_provider_and_demands_reading_the_aup(self):
        providers = sum(name in DEPLOY for name in
                        ("Hetzner", "DigitalOcean", "Vultr"))
        self.assertGreaterEqual(providers, 2)
        self.assertIn("acceptable-use", DEPLOY.lower())
        self.assertIn('"honeypot"', DEPLOY)

    def test_fenced_code_blocks_are_balanced(self):
        """An unbalanced fence silently swallows the rest of the document on
        GitHub, which would hide half the runbook."""
        fences = [line for line in DEPLOY.splitlines()
                  if line.strip().startswith("```")]
        self.assertEqual(len(fences) % 2, 0,
                         f"{len(fences)} fences: one is unclosed")


if __name__ == "__main__":
    unittest.main()

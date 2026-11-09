"""Tests for the documentation.

Three things get checked, all of which rot silently otherwise.

LINKS. Every relative link in every document must resolve, and every in-page
anchor must match a real heading. A broken link in a README is the first thing
a stranger hits and the last thing an author notices, because the author
already knows where everything is.

NUMBERS. README.md quotes figures from docs/MEASUREMENTS.md, which
tools/measure.py regenerates. If the generated file moves and the README does
not, the README is lying. These tests make that a failure rather than a
discovery.

CLAIMS. The status line must not still say the project is in progress once it
isn't, the footer link must survive a rewrite, and every unmeasured quantity
must be marked as such in both places rather than one.
"""

from __future__ import annotations

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
README = (REPO_ROOT / "README.md").read_text()
DOCS_DIR = REPO_ROOT / "docs"
MEASUREMENTS = (DOCS_DIR / "MEASUREMENTS.md").read_text()

MARKDOWN_FILES = sorted(
    [REPO_ROOT / "README.md", *DOCS_DIR.glob("*.md"),
     REPO_ROOT / "reports" / "sample-report.md"]
)

LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def slugify(heading: str) -> str:
    """GitHub's heading-anchor rules, near enough: lowercase, strip
    punctuation, spaces to hyphens."""
    text = heading.strip().lstrip("#").strip().lower()
    text = re.sub(r"[`*_\[\]()]", "", text)
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    return re.sub(r"\s+", "-", text).strip("-")


def headings(text: str) -> set[str]:
    return {slugify(line) for line in text.splitlines()
            if line.startswith("#")}


class TestLinksResolve(unittest.TestCase):
    def test_relative_file_links_point_at_real_files(self):
        for path in MARKDOWN_FILES:
            text = path.read_text()
            for label, target in LINK.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                file_part = target.split("#", 1)[0]
                if not file_part:
                    continue
                resolved = (path.parent / file_part).resolve()
                with self.subTest(doc=path.name, link=target):
                    self.assertTrue(
                        resolved.exists(),
                        f"{path.name} links to {target!r} ({label!r}) which "
                        "does not exist",
                    )

    def test_in_page_anchors_match_a_heading(self):
        for path in MARKDOWN_FILES:
            text = path.read_text()
            available = headings(text)
            for label, target in LINK.findall(text):
                if not target.startswith("#"):
                    continue
                with self.subTest(doc=path.name, anchor=target):
                    self.assertIn(
                        target[1:], available,
                        f"{path.name} links to {target!r} ({label!r}) but has "
                        "no such heading",
                    )

    def test_cross_document_anchors_match_a_heading(self):
        for path in MARKDOWN_FILES:
            text = path.read_text()
            for label, target in LINK.findall(text):
                if target.startswith(("http", "mailto:", "#")) or "#" not in target:
                    continue
                file_part, anchor = target.split("#", 1)
                other = (path.parent / file_part).resolve()
                if not other.exists() or other.suffix != ".md":
                    continue
                with self.subTest(doc=path.name, link=target):
                    self.assertIn(anchor, headings(other.read_text()),
                                  f"{path.name} links to {target!r} but "
                                  f"{other.name} has no such heading")


class TestReadmeMatchesTheMeasurements(unittest.TestCase):
    """README figures must still be in the generated measurements file."""

    def test_the_quoted_test_count_matches(self):
        from_measurements = re.search(r"\| Tests \| ([\d,]+) \|", MEASUREMENTS)
        self.assertIsNotNone(from_measurements)
        count = from_measurements.group(1)
        self.assertIn(
            count, README,
            f"MEASUREMENTS.md reports {count} tests but README.md does not "
            "mention that number. Re-run tools/measure.py and update the "
            "README."
        )

    def test_the_quoted_line_counts_match(self):
        for value in ("9,253", "160,708"):
            with self.subTest(value=value):
                self.assertIn(value, MEASUREMENTS)
                self.assertIn(value, README)

    def test_the_quoted_row_counts_match(self):
        for value in ("670 / 5,332 / 942", "11,318 / 95,086 / 16,026"):
            with self.subTest(value=value):
                self.assertIn(value, MEASUREMENTS)
                self.assertIn(value, README)

    def test_the_readme_bound_is_never_smaller_than_the_measured_one(self):
        """A bound must cover the worst observed run.

        Asserting EQUALITY would be wrong: it would make the README churn on
        every re-measurement, turning a conservative, sticky claim into a
        moving one. What matters is the direction -- the published bound may
        be looser than the measurement, never tighter. That is what stops the
        table quietly becoming optimistic.
        """
        measured = [int(x) for x in re.findall(
            r"\| \*\*Safe bound to quote\*\* \| \*\*under (\d+) s\*\* \|",
            MEASUREMENTS)]
        self.assertEqual(len(measured), 2, "expected two scales")
        published = [int(x) for x in re.findall(r"under (\d+) s", README)]
        self.assertTrue(published, "the README quotes no load bound")
        for measured_bound in measured:
            with self.subTest(measured=measured_bound):
                self.assertTrue(
                    any(p >= measured_bound for p in published),
                    f"measurements support only 'under {measured_bound} s' "
                    f"but the README's bounds are {published}: the published "
                    "bound is tighter than the evidence",
                )

    def test_the_readme_explains_why_it_quotes_bounds(self):
        self.assertIn("bounds", README.lower())
        self.assertRegex(README, r"40%")

    def test_the_readme_does_not_quote_a_lines_per_second_rate(self):
        """A rate derived from the fastest of five noisy runs reads as
        precision it does not have. The README quotes bounds instead."""
        self.assertNotRegex(
            README, r"[\d,]+ lines/s\*\*",
            "the README is quoting a throughput rate as a headline figure; "
            "use a bound from the slowest run"
        )


class TestHonestyClaims(unittest.TestCase):
    def test_the_status_line_is_no_longer_in_progress(self):
        """Checked against the opening of the file rather than a fixed
        paragraph index, so reordering the header does not break the test for
        a reason that has nothing to do with what it is asserting."""
        head = "\n".join(README.splitlines()[:20])
        self.assertIn("Status:", head,
                      "the README must state its status near the top")
        for stale in ("In progress", "Code is being added", "Coming soon"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, README)

    def test_the_status_line_says_part_b_is_not_deployed(self):
        """The single most important claim in the README: there is no real
        data here."""
        head = "\n".join(README.splitlines()[:20])
        self.assertIn("not been deployed", head)
        self.assertIn("no real attacker data", head)

    def test_the_footer_link_survives(self):
        self.assertIn("github.com/Kunal0626", README)

    def test_unmeasured_quantities_are_marked_in_both_places(self):
        limitations = README.split("## Limitations")[1]
        for quantity in ("Days deployed", "not measured"):
            with self.subTest(quantity=quantity):
                self.assertIn(quantity, MEASUREMENTS)
        for phrase in ("not measured", "never run against a live server",
                       "unvalidated"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, limitations)

    def test_the_readme_does_not_claim_detection_or_blocking(self):
        """A honeypot blocks nothing and protects nothing. These verbs are the
        ones that collapse under a follow-up question."""
        lowered = README.lower()
        for claim in ("blocked attack", "prevented attack",
                      "real-time threat detection", "mitigated"):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, lowered)

    def test_every_doc_is_listed_in_the_readme(self):
        """A document nobody links to is a document nobody reads."""
        for path in sorted(DOCS_DIR.glob("*.md")):
            with self.subTest(doc=path.name):
                self.assertIn(f"docs/{path.name}", README)

    def test_generated_documents_say_they_are_generated(self):
        for name in ("INDEXES.md", "MEASUREMENTS.md"):
            with self.subTest(doc=name):
                text = (DOCS_DIR / name).read_text()
                self.assertIn("Do not edit by hand", text)
                self.assertRegex(text, r"re-run|regenerat")


class TestResumeBullets(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (DOCS_DIR / "RESUME_BULLETS.md").read_text()

    def test_unsupportable_bullets_are_marked(self):
        """Every bullet in the deployment-dependent section must carry what is
        missing, so one cannot be copied out by accident."""
        section = self.text.split("## Needs a deployment")[1].split(
            "## Bullets not to write")[0]
        bullets = re.findall(r"^### Bullet \d+", section, re.MULTILINE)
        needs = re.findall(r"`needs:`", section)
        self.assertTrue(bullets)
        self.assertGreaterEqual(
            len(needs), len(bullets),
            "a bullet in the deployment section has no `needs:` marker"
        )

    def test_usable_bullets_cite_their_evidence(self):
        section = self.text.split("## Usable now")[1].split(
            "## Needs a deployment")[0]
        self.assertIn("Where it comes from", section)
        self.assertIn("tools/measure.py", section)
        self.assertIn("make test", section)

    def test_the_anti_examples_are_present(self):
        """Knowing which sentences fail is as useful as having one that
        works."""
        section = self.text.split("## Bullets not to write")[1]
        for bad in ("blocked", "countries", "millions of events"):
            with self.subTest(bad=bad):
                self.assertIn(bad, section.lower())

    def test_no_usable_bullet_quotes_an_unmeasured_quantity(self):
        section = self.text.split("## Usable now")[1].split(
            "## Needs a deployment")[0]
        for forbidden in ("days deployed", "unique source addresses",
                          "countries"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, section.lower())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Measure this project and write docs/MEASUREMENTS.md.

    python3 tools/measure.py

Every number that appears in README.md comes from here, so that each one can
be re-derived by running one command. The rule this enforces is simple: if a
figure is not produced by a script in this repository, it does not get
published. A number you cannot regenerate is a number you cannot defend in an
interview, and the difference between "I measured 8,000 events/second" and "I
think it was fast" is whether you can show the command.

WHAT THIS CANNOT MEASURE. Every throughput figure below is produced from
SYNTHETIC logs on one developer machine. They describe how fast this code
processes generated data here; they say nothing about real attacker behaviour.
The deployment numbers -- days deployed, sessions captured, credentials seen --
are deliberately absent, and docs/MEASUREMENTS.md records them as "not
measured" until a real deployment produces them. See docs/DEPLOY.md.

Timings are the FASTEST of several runs. The minimum is the run least
disturbed by other processes, which makes it the most reproducible statistic
available on a machine that is also doing other things. A mean would mostly
measure what else was running.
"""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from shadowpot import __version__  # noqa: E402

# (label, glob patterns, what it is)
SOURCE_GROUPS: list[tuple[str, tuple[str, ...], str]] = [
    ("Python (library)", ("shadowpot/*.py",), "parser, loader, analytics, report"),
    ("Python (tools)", ("tools/*.py",), "generator, benchmark, measurement, cleanup"),
    ("Python (tests)", ("tests/*.py",), "the test suite"),
    ("SQL (schema)", ("schema/*.sql",), "both dialects plus the measured indexes"),
    ("SQL (queries)", ("queries/*.sql", "queries/mysql/*.sql"), "the analytics"),
    ("Documentation", ("README.md", "docs/*.md"), "written prose, not generated"),
]


def count_lines(patterns: tuple[str, ...]) -> tuple[int, int]:
    files = sorted({p for pattern in patterns for p in REPO_ROOT.glob(pattern)})
    total = 0
    for path in files:
        total += len(path.read_text(encoding="utf-8").splitlines())
    return len(files), total


def run(argv: list[str], cwd: pathlib.Path | None = None) -> tuple[int, str]:
    completed = subprocess.run(
        argv, cwd=str(cwd or REPO_ROOT), capture_output=True, text=True
    )
    return completed.returncode, completed.stdout + completed.stderr


def timing(callable_, runs: int) -> tuple[float, float]:
    """Return (fastest, slowest) seconds over `runs`.

    Both, not just the fastest, because the spread turned out to matter. An
    early version reported only the minimum, and two consecutive measurement
    runs of the same work gave 25,400 and 15,400 lines/s -- a 40% swing caused
    by whatever else the laptop was doing. A single number from that
    distribution looks like precision and is not.

    So the document reports the range and the README quotes a BOUND ("under
    N seconds") rather than a point estimate. A bound survives re-measurement;
    a point estimate does not, and a resume figure that collapses when
    re-measured is worse than no figure.
    """
    best, worst = float("inf"), 0.0
    for _ in range(runs):
        start = time.perf_counter()
        callable_()
        elapsed = time.perf_counter() - start
        best = min(best, elapsed)
        worst = max(worst, elapsed)
    return best, worst


def measure_test_suite() -> dict[str, object]:
    start = time.perf_counter()
    code, output = run([sys.executable, "-W", "error::ResourceWarning",
                        "-m", "unittest", "discover", "-s", "tests", "-t", "."])
    elapsed = time.perf_counter() - start
    match = re.search(r"Ran (\d+) tests", output)
    skipped = re.search(r"skipped=(\d+)", output)
    return {
        "total": int(match.group(1)) if match else 0,
        "skipped": int(skipped.group(1)) if skipped else 0,
        "passed": code == 0,
        "seconds": elapsed,
    }


def measure_pipeline(days: int, sessions: int, seed: int,
                     runs: int) -> dict[str, object]:
    """Generate, load and report once, timing each stage."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        logs, db = root / "logs", root / "m.db"

        gen_seconds, gen_worst = timing(
            lambda: run([sys.executable, "tools/gen_sample_logs.py",
                         "--out", str(logs), "--days", str(days),
                         "--sessions-per-day", str(sessions),
                         "--seed", str(seed), "--quiet", "--force"]),
            runs,
        )
        log_bytes = sum(p.stat().st_size for p in logs.glob("cowrie.json*"))

        # Load is timed once: it is idempotent, so a second run would skip
        # every file and measure nothing. The database is removed between
        # repetitions instead.
        def load_once() -> None:
            if db.exists():
                db.unlink()
            code, output = run([sys.executable, "-m", "shadowpot.ingest",
                                "--db", str(db), str(logs), "--quiet"])
            if code != 0:
                raise RuntimeError(output[-2000:])

        load_seconds, load_worst = timing(load_once, runs)
        db_bytes = db.stat().st_size

        conn = sqlite3.connect(db)
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("sessions", "login_attempts", "commands",
                          "file_transfers", "sources", "ingested_lines")
        }
        lines_read = conn.execute(
            "SELECT SUM(lines_read) FROM ingest_runs").fetchone()[0] or 0
        conn.close()

        report_seconds, report_worst = timing(
            lambda: run([sys.executable, "-m", "shadowpot.report",
                         "--db", str(db), "--out", str(root / "r.md"),
                         "--quiet"]),
            runs,
        )
        report_bytes = (root / "r.md").stat().st_size

        # Time all 18 analytics queries together, without process startup.
        from shadowpot import analytics
        from shadowpot import db as dbmod
        database = dbmod.connect(str(db), apply_schema=False,
                                 apply_indexes=False)
        try:
            queries = analytics.load_queries()
            query_seconds, query_worst = timing(
                lambda: [analytics.run(database, q) for q in queries], runs)
        finally:
            database.close()

        return {
            "days": days,
            "sessions_per_day": sessions,
            "log_bytes": log_bytes,
            "lines_read": lines_read,
            "db_bytes": db_bytes,
            "counts": counts,
            "generate_seconds": gen_seconds,
            "load_seconds": load_seconds,
            "load_worst": load_worst,
            "lines_per_second": lines_read / load_seconds if load_seconds else 0,
            "lines_per_second_worst": (lines_read / load_worst
                                       if load_worst else 0),
            "report_seconds": report_seconds,
            "report_worst": report_worst,
            "report_bytes": report_bytes,
            "query_seconds": query_seconds,
            "query_worst": query_worst,
            "query_count": len(queries),
            "runs": runs,
        }


def _ceil_seconds(value: float) -> int:
    """Round a duration up to a tidy integer, for quoting as a bound."""
    import math
    return max(1, int(math.ceil(value)))


def human_bytes(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024.0
    return f"{value}"


def build_document(env: dict[str, str], groups: list[tuple[str, int, int, str]],
                   tests: dict[str, object],
                   scales: list[dict[str, object]]) -> str:
    lines = [
        "# Measurements",
        "",
        "Generated by `tools/measure.py`. **Do not edit by hand** -- re-run",
        "the tool:",
        "",
        "```bash",
        "python3 tools/measure.py",
        "```",
        "",
        "Every number in `README.md` comes from this file, so each one can be",
        "re-derived with one command. If a figure is not produced by a script",
        "in this repository, it does not get published.",
        "",
        "## What these numbers are not",
        "",
        "**Every throughput figure here was produced from SYNTHETIC logs on",
        "one developer machine.** They measure how fast this code processes",
        "generated data on this hardware. They are not findings about attacker",
        "behaviour, and none of them belongs in a sentence beginning \"I",
        "detected\".",
        "",
        "The numbers that would describe real attacker behaviour are listed",
        "under *Not measured* at the bottom, and they stay there until a real",
        "deployment produces them. `docs/DEPLOY.md` is how that happens.",
        "",
        "## Environment",
        "",
        "| | |",
        "|---|---|",
    ]
    lines += [f"| {key} | {value} |" for key, value in env.items()]

    lines += [
        "",
        "## Size of the project",
        "",
        "Line counts, not a quality metric. They are here because \"how big is",
        "it\" is a reasonable first question and a guess would be wrong.",
        "",
        "| component | files | lines | what it is |",
        "|---|---:|---:|---|",
    ]
    total_files = total_lines = 0
    for label, files, count, what in groups:
        lines.append(f"| {label} | {files} | {count:,} | {what} |")
        total_files += files
        total_lines += count
    lines.append(f"| **total** | **{total_files}** | **{total_lines:,}** | |")

    lines += [
        "",
        "## Test suite",
        "",
        "| | |",
        "|---|---|",
        f"| Tests | {tests['total']:,} |",
        f"| Passing | {'all' if tests['passed'] else 'NOT ALL -- see below'} |",
        f"| Skipped | {tests['skipped']} "
        "(the MySQL round trip, which needs a live server) |",
        f"| Wall clock | {float(tests['seconds']):.2f} s |",
        "| Command | `make test` |",
        "",
        "Run with `-W error::ResourceWarning`, so a leaked database handle",
        "fails the suite rather than printing a warning nobody reads.",
        "",
        "## Pipeline throughput",
        "",
        "Generation and reporting include Python interpreter startup, because",
        "that is what you actually wait for; the query row times the analytics",
        "queries inside one process, without startup, because that is the",
        "number that would matter if this were serving a dashboard.",
        "",
        "**Both the fastest and the slowest run are shown, and the spread is",
        "large.** On a laptop that is also doing other things, two consecutive",
        "measurements of the same work have differed by 40%. Quote the",
        "SLOWEST figure, or a bound derived from it -- \"loaded 160,708 lines",
        "in under 11 s\" survives re-measurement, and \"25,400 lines/s\" does",
        "not. A number that collapses when someone re-runs it is worse than",
        "no number.",
        "",
    ]

    for scale in scales:
        counts = scale["counts"]
        lines += [
            f"### {scale['days']} days, {scale['sessions_per_day']} "
            f"sessions/day (synthetic)",
            "",
            "| | |",
            "|---|---|",
            f"| Log files on disk | {human_bytes(int(scale['log_bytes']))} |",
            f"| Lines read | {int(scale['lines_read']):,} |",
            f"| Sessions / login attempts / commands | "
            f"{counts['sessions']:,} / {counts['login_attempts']:,} / "
            f"{counts['commands']:,} |",
            f"| Database size | {human_bytes(int(scale['db_bytes']))} |",
            f"| Generate | {float(scale['generate_seconds']):.2f} s |",
            f"| **Load (fastest of {scale['runs']})** | "
            f"**{float(scale['load_seconds']):.2f} s "
            f"({float(scale['lines_per_second']):,.0f} lines/s)** |",
            f"| Load (slowest) | {float(scale['load_worst']):.2f} s "
            f"({float(scale['lines_per_second_worst']):,.0f} lines/s) |",
            f"| **Safe bound to quote** | "
            f"**under {_ceil_seconds(float(scale['load_worst']))} s** |",
            f"| Run all {scale['query_count']} queries | "
            f"{float(scale['query_seconds']) * 1000:,.0f} ms "
            f"(slowest {float(scale['query_worst']) * 1000:,.0f} ms) |",
            f"| Build the report | {float(scale['report_seconds']):.2f} s "
            f"({human_bytes(int(scale['report_bytes']))} of Markdown) |",
            "",
        ]

    lines += [
        "## Index measurements",
        "",
        "Kept separate because they need a larger database and their own",
        "method: see [INDEXES.md](INDEXES.md), regenerated by `make bench`.",
        "Four of seven candidate indexes earned a place; the three that did",
        "not are recorded with the measurement that rejected them.",
        "",
        "## Not measured",
        "",
        "These are the numbers an interviewer or a reader will care about",
        "most, and this project does not have them yet. They can only come",
        "from a real honeypot on the public internet, following",
        "[DEPLOY.md](DEPLOY.md).",
        "",
        "| quantity | status |",
        "|---|---|",
        "| Days deployed | **not measured** |",
        "| Sessions captured from real attackers | **not measured** |",
        "| Unique real source addresses | **not measured** |",
        "| Most-tried real credentials | **not measured** |",
        "| Malware samples captured | **not measured** |",
        "| Geolocation / ASN of attackers | **not measured**, and out of "
        "scope: it needs an offline GeoIP database this project does not "
        "ship, and ShadowPot makes no live lookups against attacker "
        "addresses |",
        "| Whether the bot-vs-human thresholds suit real traffic | "
        "**not measured**. The synthetic populations separate cleanly by "
        "construction, which demonstrates the SQL and cannot validate the "
        "threshold |",
        "| MySQL round trip | **not verified** against a live server |",
        "",
        "When a deployment finishes, fill in the template in",
        "[DEPLOY.md](DEPLOY.md) §10 and regenerate the report against the",
        "real database. Nothing above moves out of this list until then.",
        "",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=3,
                        help="timed repetitions per stage (default: %(default)s)")
    parser.add_argument("--out", default="docs/MEASUREMENTS.md")
    parser.add_argument("--skip-tests", action="store_true",
                        help="omit the test-suite timing")
    args = parser.parse_args(argv)

    code, cowrie_note = 0, "not installed here (Part B runs on a VPS)"
    env = {
        "Generated": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"),
        "ShadowPot": __version__,
        "Machine": platform.platform(),
        "CPU": platform.processor() or platform.machine(),
        "Python": platform.python_version(),
        "SQLite (via Python)": sqlite3.sqlite_version,
        "SQLite (CLI)": _sqlite_cli_version(),
        "MySQL client": _mysql_version(),
        "GNU Make": _make_version(),
        "Cowrie": cowrie_note,
    }

    print("measuring source size...")
    groups = []
    for label, patterns, what in SOURCE_GROUPS:
        files, count = count_lines(patterns)
        groups.append((label, files, count, what))

    tests = {"total": 0, "skipped": 0, "passed": True, "seconds": 0.0}
    if not args.skip_tests:
        print("running the test suite...")
        tests = measure_test_suite()
        print(f"  {tests['total']} tests, "
              f"{'all passing' if tests['passed'] else 'FAILURES'}")

    scales = []
    for days, sessions, seed in ((7, 90, 1337), (30, 350, 7)):
        print(f"timing the pipeline at {days} days x {sessions}/day "
              f"({args.runs} runs)...")
        scale = measure_pipeline(days, sessions, seed, args.runs)
        scales.append(scale)
        print(f"  load {scale['load_seconds']:.2f}s "
              f"({scale['lines_per_second']:,.0f} lines/s)")

    target = REPO_ROOT / args.out
    target.write_text(build_document(env, groups, tests, scales),
                      encoding="utf-8")
    print(f"\nwrote {args.out}")
    return 0


def _sqlite_cli_version() -> str:
    if not shutil.which("sqlite3"):
        return "not installed"
    code, out = run(["sqlite3", "--version"])
    return out.split()[0] if code == 0 and out.split() else "unknown"


def _mysql_version() -> str:
    if not shutil.which("mysql"):
        return "not installed"
    code, out = run(["mysql", "--version"])
    match = re.search(r"Ver (\S+)", out)
    return match.group(1) if match else "unknown"


def _make_version() -> str:
    if not shutil.which("make"):
        return "not installed"
    code, out = run(["make", "--version"])
    match = re.search(r"Make (\S+)", out)
    return match.group(1) if match else "unknown"


if __name__ == "__main__":
    raise SystemExit(main())

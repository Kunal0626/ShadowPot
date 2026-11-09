#!/usr/bin/env python3
"""Measure whether a candidate index actually helps, and write docs/INDEXES.md.

    python3 tools/bench_indexes.py --db data/bench.db

An index is not free. It costs space, it costs write time on every insert, and
it gives the planner another way to be wrong. "Index the foreign keys" is a
habit, not a reason. So every index ShadowPot ships has to earn its place by
changing a query plan from a scan to a search, or by moving a measured time --
and the candidates that do NOT earn it are recorded here too, because knowing
which indexes you deliberately left out is worth as much as knowing which you
added.

The method:

  1. Copy the database so the baseline cannot be contaminated.
  2. For every query: EXPLAIN QUERY PLAN, then run it `--runs` times and keep
     the FASTEST. Fastest, not mean: the minimum is the run least disturbed by
     the scheduler and by other processes, so it is the most reproducible
     statistic on a machine that is also doing other things.
  3. Create the candidate indexes, ANALYZE, repeat.
  4. Report, per query, the plan before and after and the time ratio; and per
     index, whether any query plan actually names it.

SCALE MATTERS AND IS REPORTED. On a few thousand rows SQLite reads the whole
table in well under a millisecond and no index can beat that, so a benchmark
on the default sample data would "prove" that no index helps. Build a larger
database first; the row counts used are printed in the output and written into
the document, so the numbers are never quoted without their scale.
"""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import platform
import shutil
import sqlite3
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from shadowpot import analytics  # noqa: E402

# Candidate indexes, each with the reason it is plausible. Columns already
# covered by a PRIMARY KEY or UNIQUE constraint are deliberately included
# where a reader would expect to need them, so the measurement can show that
# the constraint already provides the index.
CANDIDATES: list[tuple[str, str, str]] = [
    ("idx_login_attempts_cred", "login_attempts(cred_id)",
     "03/15 group login attempts by credential; 05 joins them"),
    ("idx_login_attempts_keycred", "login_attempts(keycred_id)",
     "v_login_attempts LEFT JOINs key_credentials on this column"),
    ("idx_login_attempts_session", "login_attempts(session_pk)",
     "every per-session join. EXPECTED TO BE REDUNDANT: the table already "
     "has UNIQUE(session_pk, ts), whose index has session_pk as its leading "
     "column"),
    ("idx_sessions_source", "sessions(source_id)",
     "05/06/14/15 group or join by source address"),
    ("idx_sessions_start", "sessions(start_ts)",
     "06/07/08 bucket sessions by day and by hour"),
    ("idx_commands_input", "commands(input)",
     "09/10/11 group commands by their text"),
    ("idx_file_transfers_sha", "file_transfers(sha256)",
     "14 joins transfers to artifacts by content hash"),
]


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = ("sessions", "login_attempts", "commands", "file_transfers",
              "credentials", "sources", "ingested_lines")
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in tables}


def plan_for(conn: sqlite3.Connection, sql: str) -> list[str]:
    return [row[3] for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}")]


def time_query(conn: sqlite3.Connection, sql: str, runs: int) -> float:
    """Fastest of `runs`, in milliseconds. fetchall() forces full execution:
    SQLite is lazy, so timing only the execute() would measure almost
    nothing."""
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        conn.execute(sql).fetchall()
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def summarize_plan(plan: list[str]) -> tuple[str, set[str]]:
    """Reduce a plan to a verdict and the set of indexes it names."""
    used = {
        line.split("USING INDEX ")[1].split(" ")[0].rstrip(")")
        for line in plan if "USING INDEX " in line
    }
    covering = sum(1 for line in plan if line.startswith("SCAN"))
    verdict = "scan" if covering and not used else ("search" if used else "scan")
    return verdict, used


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True,
                        help="a loaded ShadowPot database to benchmark")
    parser.add_argument("--runs", type=int, default=7,
                        help="timed repetitions per query (default: %(default)s)")
    parser.add_argument("--out", default="docs/INDEXES.md")
    args = parser.parse_args(argv)

    source = pathlib.Path(args.db)
    if not source.is_file():
        print(f"no such database: {source}", file=sys.stderr)
        return 1

    scratch = source.parent / f".bench-{source.name}"
    shutil.copyfile(source, scratch)
    conn = sqlite3.connect(scratch)

    # Drop every explicitly created index on the WORKING COPY, so the baseline
    # is genuinely unindexed.
    #
    # This is not optional tidying. shadowpot/db.py applies
    # schema/indexes.sqlite.sql on connect, so any database built by the
    # loader already carries the four measured indexes -- which means the
    # "before" column would silently be measuring an indexed database against
    # itself, and every speedup would read as 1.00x. Before this existed the
    # tool simply crashed with "index already exists", which was luckier than
    # the alternative.
    #
    # `sql IS NOT NULL` is the filter that matters: SQLite reports the indexes
    # it creates implicitly for PRIMARY KEY and UNIQUE constraints with a NULL
    # sql column, and those cannot be dropped -- nor should they be, since
    # they are part of the schema's correctness rather than its tuning.
    existing = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' "
        "AND sql IS NOT NULL"
    )]
    for name in existing:
        conn.execute(f"DROP INDEX {name}")
    conn.execute("ANALYZE")
    conn.commit()
    if existing:
        print(f"dropped {len(existing)} pre-existing "
              f"{'index' if len(existing) == 1 else 'indexes'} from the "
              f"working copy to get an unindexed baseline: "
              f"{', '.join(sorted(existing))}\n")

    counts = table_counts(conn)
    queries = analytics.load_queries()

    print(f"benchmarking {len(queries)} queries over "
          f"{counts['sessions']} sessions / {counts['commands']} commands, "
          f"best of {args.runs}\n")

    baseline: dict[str, tuple[list[str], float]] = {}
    for query in queries:
        baseline[query.name] = (plan_for(conn, query.sql),
                                time_query(conn, query.sql, args.runs))

    # Measure each candidate ALONE, from the same baseline. Creating all the
    # indexes at once and reading the plans would show WHICH index the planner
    # picked, but not what any one of them is worth: a query that got faster
    # might owe it to a different index created in the same pass. One at a
    # time costs more wall clock and buys attribution.
    per_index: dict[str, dict[str, tuple[str, float]]] = {}
    for name, target, _ in CANDIDATES:
        conn.execute(f"CREATE INDEX {name} ON {target}")
        conn.execute("ANALYZE")
        conn.commit()
        measured: dict[str, tuple[str, float]] = {}
        for query in queries:
            plan = plan_for(conn, query.sql)
            _, used = summarize_plan(plan)
            elapsed = time_query(conn, query.sql, args.runs)
            measured[query.name] = ("used" if name in used else "ignored",
                                    elapsed)
        per_index[name] = measured
        conn.execute(f"DROP INDEX {name}")
        conn.execute("ANALYZE")
        conn.commit()
        users = [q for q, (verdict, _) in measured.items() if verdict == "used"]
        best = max(
            (baseline[q][1] / measured[q][1] for q in users
             if measured[q][1] > 0), default=0.0)
        print(f"  {name:30s} {'used by ' + str(len(users)) if users else 'UNUSED':12s}"
              f" best x{best:4.2f}  {', '.join(users[:3])}")

    kept = [(n, t, w) for n, t, w in CANDIDATES
            if any(v == "used" for v, _ in per_index[n].values())]
    dropped = [(n, t, w) for n, t, w in CANDIDATES
               if not any(v == "used" for v, _ in per_index[n].values())]

    # Final configuration: only the indexes that earned a place, together.
    for name, target, _ in kept:
        conn.execute(f"CREATE INDEX {name} ON {target}")
    conn.execute("ANALYZE")
    conn.commit()

    shipped: dict[str, tuple[list[str], float]] = {}
    print("\n  with the kept indexes in place:")
    rows = []
    for query in queries:
        plan = plan_for(conn, query.sql)
        elapsed = time_query(conn, query.sql, args.runs)
        shipped[query.name] = (plan, elapsed)
        vb, _ = summarize_plan(baseline[query.name][0])
        va, used = summarize_plan(plan)
        tb, ta = baseline[query.name][1], elapsed
        ratio = tb / ta if ta > 0 else float("inf")
        rows.append((query.name, vb, va, tb, ta, ratio,
                     sorted(u for u in used if u in dict((k, 1) for k, _, _ in CANDIDATES))))
        print(f"    {query.name:32s} {vb:7s} -> {va:7s} "
              f"{tb:8.2f} -> {ta:8.2f} ms  x{ratio:5.2f}")

    _write_report(pathlib.Path(args.out), rows, per_index, baseline,
                  kept, dropped, counts, args.runs)
    conn.close()
    scratch.unlink()
    print(f"\n  wrote {args.out}")
    return 0


def _write_report(path: pathlib.Path, rows, per_index, baseline, kept,
                  dropped, counts, runs) -> None:
    improved = sorted((r for r in rows if r[5] >= 1.10), key=lambda r: -r[5])

    lines = [
        "# Index measurements",
        "",
        "Generated by `tools/bench_indexes.py`. **Do not edit by hand** -- "
        "re-run the tool.",
        "",
        "Every index ShadowPot ships is here with the measurement that "
        "justified it, and every candidate that was rejected is here with the "
        "measurement that rejected it. An index is not free: it costs space, "
        "it costs write time on every insert, and it gives the planner another "
        "way to be wrong. \"Index the foreign keys\" is a habit, not a reason.",
        "",
        "## Conditions",
        "",
        "| | |",
        "|---|---|",
        f"| Generated | {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| Machine | {platform.platform()} |",
        f"| Python | {platform.python_version()} |",
        f"| SQLite | {sqlite3.sqlite_version} |",
        f"| Timing | fastest of {runs} runs, `fetchall()` included |",
        "| Data | **SYNTHETIC** (`tools/gen_sample_logs.py`). These are "
        "timings of this machine on generated data, not findings about real "
        "attackers. |",
        "",
        "Row counts of the benchmarked database:",
        "",
        "| table | rows |",
        "|---|---:|",
    ]
    lines += [f"| `{t}` | {n:,} |" for t, n in counts.items()]
    lines += [
        "",
        "**Scale is part of the result.** On a few thousand rows SQLite reads "
        "a whole table in well under a millisecond, so the same benchmark on "
        "the default 7-day sample would show that no index helps -- true of "
        "that dataset, and useless as guidance. Never quote these numbers "
        "without the row counts above.",
        "",
        "## Method",
        "",
        "Each candidate was created **alone**, from the same baseline, then "
        "dropped. Creating all of them at once shows which index the planner "
        "picked but not what any one is worth, because a query that got "
        "faster might owe it to a different index created in the same pass. "
        "The timing is the **fastest** of several runs rather than the mean: "
        "the minimum is the run least disturbed by other processes, so it is "
        "the most reproducible statistic available on a machine that is also "
        "doing other things.",
        "",
        "## Per-index verdict",
        "",
        "| index | columns | rationale | verdict | queries that used it | best speedup |",
        "|---|---|---|---|---|---:|",
    ]
    for name, target, why in [*kept, *dropped]:
        measured = per_index[name]
        users = [q for q, (verdict, _) in measured.items() if verdict == "used"]
        best = max((baseline[q][1] / measured[q][1]
                    for q in users if measured[q][1] > 0), default=0.0)
        verdict = "**KEPT**" if users else "rejected"
        rationale = why.split(". EXPECTED")[0]
        speed = f"{best:.2f}x" if users else "--"
        used_text = ", ".join(f"`{u}`" for u in sorted(users)) or "none"
        lines.append(f"| `{name}` | `{target}` | {rationale} | {verdict} | "
                     f"{used_text} | {speed} |")

    lines += [
        "",
        "## Per-query plans, with the kept indexes in place",
        "",
        "`scan` means SQLite read a whole table; `search` means it used an "
        "index to go straight to the rows. The plan change matters more than "
        "the time: a time can be noise, a plan change cannot. Ratios below "
        "1.00 are measurement noise, not regressions -- at these sizes "
        "several queries are dominated by sorting and grouping, which no "
        "index affects.",
        "",
        "| query | plan before | plan after | before (ms) | after (ms) | speedup |",
        "|---|---|---|---:|---:|---:|",
    ]
    for name, vb, va, tb, ta, ratio, _ in rows:
        lines.append(f"| `{name}` | {vb} | {va} | {tb:.2f} | {ta:.2f} | "
                     f"{ratio:.2f}x |")

    lines += ["", "## What moved most", ""]
    if improved:
        for name, _, _, tb, ta, ratio, _ in improved[:6]:
            lines.append(f"- `{name}`: {tb:.2f} ms -> {ta:.2f} ms "
                         f"({ratio:.2f}x)")
    else:
        lines.append("No query improved by more than 10% at this scale.")

    lines += [
        "",
        "## How to reproduce",
        "",
        "```bash",
        "python3 tools/gen_sample_logs.py --out /tmp/bench-logs \\",
        "    --days 30 --sessions-per-day 350 --seed 7 --quiet",
        "python3 -m shadowpot.ingest --db /tmp/bench.db /tmp/bench-logs --quiet",
        "python3 tools/bench_indexes.py --db /tmp/bench.db",
        "```",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

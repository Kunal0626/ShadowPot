"""Turn a loaded ShadowPot database into reports/report.md.

    python3 -m shadowpot.report --db data/shadowpot.db --out reports/report.md

Three rules govern everything in this module.

1. NO INVENTED FINDINGS. Every sentence in the narrative is assembled from a
   value a query returned. There is no prose that is not a template filled
   from data, and where something was not measured the report says "not
   measured" rather than estimating. A report that reads better than its
   evidence is worse than no report.

2. SYNTHETIC DATA IS LABELLED, LOUDLY. If any session carries is_synthetic
   the report leads with a banner and repeats the warning in the narrative.
   A database that MIXES real and generated sessions gets a stronger warning
   still, because that is the case where a number could quietly end up on a
   resume.

3. EVERY STRING IN HERE IS ATTACKER-CONTROLLED. Usernames, passwords,
   commands and URLs come from whoever connected to the honeypot. They reach
   a Markdown table, and from there a terminal or a browser. So they are
   escaped, not interpolated: see `md_cell`. A command like
   `cat /proc/cpuinfo | grep name` would otherwise silently split a table
   row into extra columns, and a terminal escape sequence pasted into a
   username would be executed by whatever `cat`s the file.

Charts are optional and off by default. matplotlib is not a dependency: the
default report is tables plus ASCII bars, so it works from a clean clone with
nothing installed.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import pathlib
import platform
import re
import sqlite3
import sys
from typing import Any, Iterable, Sequence

from shadowpot import __version__, analytics
from shadowpot import db as dbmod

BANNER_SYNTHETIC = "SYNTHETIC SAMPLE DATA"
BAR_WIDTH = 42

# Control characters, including the ESC that starts an ANSI escape sequence.
# An attacker can put these in a username or a command, and this report is a
# file someone will `cat`.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Markdown rendering, with attacker-controlled content in mind
# ---------------------------------------------------------------------------

def md_cell(value: Any, *, code: bool = False, max_len: int = 120) -> str:
    """Render one value safely into a Markdown table cell.

    What has to be handled, and why:

    pipes       `|` ends a cell in a GFM table, so a command containing one
                would split its row and shift every later column. Escaped as
                `\\|`, which GFM honours even inside a code span.
    control
    characters  stripped to a visible \\xNN form. A report is a file people
                open in a terminal; an ESC sequence in a username must not be
                interpreted there.
    backticks   a code span cannot contain a backtick run as long as its own
                fence, so the fence is grown to be longer than anything in
                the content rather than assuming one backtick is enough.
    length      truncated with a visible ellipsis. Cowrie records whole
                command lines and base64 key blobs, which can be kilobytes.
    """
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.2f}"

    text = str(value)
    text = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"

    if code:
        if text == "":
            return "*(empty string)*"
        longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
        fence = "`" * (longest + 1)
        # A pipe still breaks the row even inside a code span, so escape it.
        inner = text.replace("|", "\\|")
        pad = " " if text.startswith("`") or text.endswith("`") else ""
        return f"{fence}{pad}{inner}{pad}{fence}"

    if text == "":
        return "*(empty string)*"
    return text.replace("\\", "\\\\").replace("|", "\\|")


def md_table(columns: Sequence[str], rows: Iterable[Sequence[Any]], *,
             code_columns: Sequence[str] = (),
             align_right: Sequence[str] = ()) -> list[str]:
    rows = list(rows)
    if not rows:
        return ["*No rows.*", ""]

    code_at = {i for i, c in enumerate(columns) if c in code_columns}
    right_at = {i for i, c in enumerate(columns) if c in align_right}

    head = "| " + " | ".join(columns) + " |"
    rule = "|" + "|".join("---:" if i in right_at else "---"
                          for i in range(len(columns))) + "|"
    body = [
        "| " + " | ".join(
            md_cell(value, code=index in code_at)
            for index, value in enumerate(row)
        ) + " |"
        for row in rows
    ]
    return [head, rule, *body, ""]


def ascii_bars(labels: Sequence[str], values: Sequence[float], *,
               width: int = BAR_WIDTH) -> list[str]:
    """A bar chart that needs no dependencies and survives being pasted
    anywhere. The optional matplotlib charts are prettier; this one always
    works, which matters more for a report that has to render from a clean
    clone."""
    if not values or max(values) <= 0:
        return ["*Nothing to plot.*", ""]
    label_width = max(len(str(l)) for l in labels)
    peak = max(values)
    lines = ["```"]
    for label, value in zip(labels, values):
        filled = int(round(width * value / peak))
        lines.append(
            f"{str(label):>{label_width}}  "
            f"{'#' * filled}{' ' * (width - filled)}  {value:,.0f}"
        )
    lines += ["```", ""]
    return lines


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Dataset:
    """Everything the report knows, keyed by query name."""

    results: dict[str, analytics.Result]
    db_path: str
    schema_version: str

    def rows(self, name: str) -> list[dict[str, Any]]:
        return self.results[name].dicts()

    def one(self, name: str) -> dict[str, Any]:
        rows = self.rows(name)
        return rows[0] if rows else {}

    @property
    def summary(self) -> dict[str, Any]:
        return self.one("dataset_summary")

    @property
    def synthetic_state(self) -> str:
        """'none', 'all' or 'mixed'."""
        total = self.summary.get("sessions") or 0
        synthetic = self.summary.get("synthetic_sessions") or 0
        if total == 0 or synthetic == 0:
            return "none"
        return "all" if synthetic == total else "mixed"


def collect(database: dbmod.Database, dialect: str = "sqlite") -> Dataset:
    queries = analytics.load_queries(dialect)
    results = {q.name: analytics.run(database, q) for q in queries}
    schema_version = str(database.scalar(
        database.dialect.select_one("db_meta", "meta_value", ["meta_key"]),
        ["schema_version"],
    ))
    return Dataset(results=results, db_path="", schema_version=schema_version)


def banner(state: str) -> list[str]:
    if state == "none":
        return []
    if state == "all":
        return [
            "> # " + BANNER_SYNTHETIC,
            "> ",
            "> **Every session in this database was generated by "
            "`tools/gen_sample_logs.py`.** No real attacker produced any of "
            "it. Every address below is from a reserved documentation range "
            "(RFC 5737, RFC 3849) and every URL uses the reserved `.invalid` "
            "TLD, so none of them refers to anything real.",
            "> ",
            "> **No number in this report may be published as a measurement, "
            "put on a resume, or quoted as a finding.** It exists to show "
            "that the pipeline works. Only a real deployment's own logs can "
            "support a claim about attacker behaviour.",
            "",
        ]
    return [
        "> # " + BANNER_SYNTHETIC + " MIXED WITH REAL DATA",
        "> ",
        "> **This database contains both real and synthetic sessions.** That "
        "is the one state in which a generated figure can be mistaken for a "
        "measurement, because the report cannot tell you which rows "
        "contributed to which total.",
        "> ",
        "> Every aggregate below is therefore **unusable as evidence**. "
        "Rebuild from a database loaded only with real logs:",
        "> ",
        "> ```",
        "> rm -f data/real.db",
        "> python3 -m shadowpot.ingest --db data/real.db /path/to/real/logs",
        "> ```",
        "",
    ]


def provenance(data: Dataset, dialect: str) -> list[str]:
    runs = data.rows("ingest_quality")
    lines = [
        "## Provenance",
        "",
        "Everything below was produced by the commands in this repository "
        "against the database named here. Nothing was typed in by hand.",
        "",
        "| | |",
        "|---|---|",
        f"| Generated | {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC |",
        f"| Database | `{data.db_path}` (schema version {data.schema_version}) |",
        f"| Dialect | {dialect} |",
        f"| ShadowPot | {__version__} |",
        f"| Python | {platform.python_version()} |",
        f"| SQLite | {sqlite3.sqlite_version} |",
        f"| Machine | {platform.platform()} |",
        f"| Loader runs | {len(runs)} |",
        "",
        "Regenerate with:",
        "",
        "```bash",
        f"python3 -m shadowpot.report --db {data.db_path or 'data/shadowpot.db'}",
        "```",
        "",
    ]
    return lines


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or singular + "s")


def _was_were(count: int) -> str:
    """Generated prose still has to read like prose. "There were 1 login
    attempt" is the kind of detail that makes a report look machine-made,
    which invites the reader to distrust the numbers too."""
    return "was" if count == 1 else "were"


def _quoted(value: Any) -> str:
    """Render an attacker-controlled string for use in PROSE.

    The tables get this for free through md_cell; the narrative does not, and
    forgetting it here was a real bug caught by
    tests/test_report.py::TestAttackerControlledContent. A username of
    "ro|ot\x1b[31m" was interpolated straight into a sentence, putting a live
    ANSI escape into a file that people open in a terminal.

    Same treatment as a code cell: control characters made visible, backtick
    fence grown to fit, length capped.
    """
    return md_cell(value, code=True, max_len=80)


def narrative(data: Dataset) -> list[str]:
    """The plain-language summary, assembled strictly from query output.

    Every sentence is a template with a measured value in it. Nothing here
    characterises, infers motive, or fills a gap with a plausible guess: when
    a quantity is zero the sentence says so, and when something was not
    measured it says "not measured".
    """
    summary = data.summary
    sentences: list[str] = []

    sessions = summary.get("sessions") or 0
    if sessions == 0:
        return [
            "## What attackers did",
            "",
            "No sessions are recorded in this database, so there is nothing "
            "to summarize. Load some logs first:",
            "",
            "```bash",
            "python3 -m shadowpot.ingest --db data/shadowpot.db "
            "data/sample-logs",
            "```",
            "",
        ]

    days = summary.get("days_observed") or 0
    ips = summary.get("distinct_ips") or 0
    sentences.append(
        f"Across {days:,} {_plural(days, 'day')} this honeypot recorded "
        f"{sessions:,} {_plural(sessions, 'session')} from {ips:,} distinct "
        f"{_plural(ips, 'address', 'addresses')}, between "
        f"{summary.get('first_session')} and {summary.get('last_session')}."
    )

    attempts = summary.get("login_attempts") or 0
    successes = summary.get("login_successes") or 0
    if attempts:
        pairs = data.rows("top_credential_pairs")
        line = (f"There {_was_were(attempts)} {attempts:,} login "
                f"{_plural(attempts, 'attempt')}, of which {successes:,} "
                f"succeeded.")
        if pairs:
            top = pairs[0]
            line += (f" The most-tried credential pair was "
                     f"{_quoted(top['username'])} / "
                     f"{_quoted(top['password'])}, attempted "
                     f"{top['attempts']:,} "
                     f"{_plural(top['attempts'], 'time')} from "
                     f"{top['distinct_ips']:,} distinct "
                     f"{_plural(top['distinct_ips'], 'address', 'addresses')}.")
        sentences.append(line)

    if successes:
        accepted = data.rows("successful_credentials")
        names = ", ".join(
            f"{_quoted(row['username'])} / {_quoted(row['secret'])}"
            for row in accepted[:3]
        )
        count = len(accepted[:3])
        sentences.append(
            f"The {_plural(count, 'credential')} that "
            f"{_was_were(count)} accepted {_was_were(count)} {names}. This is "
            "not evidence of a compromise: a honeypot accepts whatever its "
            "configuration tells it to accept, so what this measures is "
            "which staged credential the attackers happened to find."
        )
    else:
        sentences.append("No login attempt succeeded.")

    offenders = data.rows("repeat_offenders")
    if offenders:
        worst = offenders[0]
        # worst['ip'] is NOT passed through _quoted. It is the only
        # attacker-supplied value in this narrative that is safe raw: the
        # parser canonicalizes every address through Python's ipaddress
        # module before it is stored, so it cannot contain a pipe, a backtick
        # or a control character. Reading as plain text in a sentence is
        # worth more than uniformity here.
        sentences.append(
            f"{len(offenders):,} "
            f"{_plural(len(offenders), 'address', 'addresses')} came back on "
            f"more than one day; the most persistent was {worst['ip']}, seen "
            f"on {worst['active_days']:,} separate days across "
            f"{worst['sessions']:,} {_plural(worst['sessions'], 'session')}."
        )
    else:
        sentences.append(
            "No address was seen on more than one day, so this traffic shows "
            "no returning attackers."
        )

    shared = data.rows("shared_credentials")
    if shared:
        sentences.append(
            f"{len(shared):,} credential "
            f"{_plural(len(shared), 'pair')} {_was_were(len(shared))} tried "
            f"from five or more "
            f"different addresses, which means those hosts are working from a "
            f"shared list rather than each from its own."
        )

    commands = summary.get("commands") or 0
    if commands:
        first = data.rows("first_commands")
        line = (f"{commands:,} shell {_plural(commands, 'command')} "
                f"{_was_were(commands)} entered.")
        if first:
            line += (f" The most common opening command was "
                     f"{_quoted(first[0]['first_command'])}, which started "
                     f"{first[0]['sessions']:,} "
                     f"{_plural(first[0]['sessions'], 'session')}.")
        sentences.append(line)

        verdicts: dict[str, int] = {}
        for row in data.rows("bot_vs_human"):
            key = str(row["verdict"]).split(":")[0]
            verdicts[key] = verdicts.get(key, 0) + 1
        if verdicts:
            parts = ", ".join(f"{n:,} {k}" for k, n in sorted(verdicts.items()))
            sentences.append(
                f"By the heuristic in `queries/13_bot_vs_human.sql`, the "
                f"sessions that ran commands break down as {parts}. That is "
                f"a heuristic over command timing and sequence reuse, not a "
                f"measurement of who was at the keyboard, and its thresholds "
                f"are stated in the query."
            )
    else:
        sentences.append(
            "No shell commands were recorded, so no attacker got past "
            "authentication in this data."
        )

    transfers = summary.get("file_transfers") or 0
    if transfers:
        downloads = data.rows("downloads_and_fetchers")
        line = (f"{transfers:,} file {_plural(transfers, 'transfer')} "
                f"{_was_were(transfers)} recorded, covering "
                f"{summary.get('distinct_artifacts') or 0:,} distinct "
                f"{_plural(summary.get('distinct_artifacts') or 0, 'file')} "
                f"by content hash.")
        if downloads:
            widest = downloads[0]
            line += (f" The most widely shared was fetched by "
                     f"{widest['distinct_ips']:,} distinct "
                     f"{_plural(widest['distinct_ips'], 'address', 'addresses')}.")
        sentences.append(line)
    else:
        sentences.append("No files entered or left the honeypot.")

    quality = data.rows("ingest_quality")
    if quality:
        dropped = sum(
            (row["lines_malformed"] or 0) + (row["events_incomplete"] or 0)
            for row in quality
        )
        unknown = sum(row["events_unknown"] or 0 for row in quality)
        sentences.append(
            f"Across {len(quality):,} loader {_plural(len(quality), 'run')}, "
            f"{dropped:,} {_plural(dropped, 'line')} could not be used "
            f"and "
            f"{unknown:,} {_plural(unknown, 'event')} had an event id this "
            f"project does not model. Those are broken out per run under "
            f"Data quality below; no finding here accounts for them."
        )

    sentences.append(
        "Geolocation and network ownership are **not measured**. That would "
        "need an offline GeoIP database, which this project does not ship, "
        "and ShadowPot deliberately makes no live lookups against attacker "
        "addresses."
    )

    out = ["## What attackers did", ""]
    if data.synthetic_state != "none":
        out += [
            f"**These sentences describe generated data, not real attackers.**"
            f" See the {BANNER_SYNTHETIC.lower()} banner above.",
            "",
        ]
    out += [" ".join(sentences[:4]), ""]
    if len(sentences) > 4:
        out += [" ".join(sentences[4:]), ""]
    return out


# Section layout: (heading, query name, columns to render as code, limit)
SECTIONS: list[tuple[str, list[tuple[str, str, tuple[str, ...], bool]]]] = [
    ("Credentials", [
        ("Most-tried usernames", "top_usernames", ("username",), True),
        ("Most-tried passwords", "top_passwords", ("password",), True),
        ("Most-tried username and password pairs", "top_credential_pairs",
         ("username", "password"), True),
        ("Credentials that were accepted", "successful_credentials",
         ("username", "secret"), False),
        ("Credentials tried from five or more addresses", "shared_credentials",
         ("username", "password"), True),
    ]),
    ("Source addresses", [
        ("Busiest addresses", "attempts_per_source", (), True),
        ("Addresses seen on more than one day", "repeat_offenders", (), True),
    ]),
    ("Shell activity", [
        ("First command of a session", "first_commands",
         ("first_command",), True),
        ("Most-run commands", "top_commands", ("input",), True),
        ("Command pairs", "command_bigrams",
         ("first_command", "second_command"), True),
    ]),
    ("Files", [
        ("Downloads, and how widely each was fetched",
         "downloads_and_fetchers", ("url", "sha256", "outfile"), True),
    ]),
    ("Clients", [
        ("Banners and HASSH fingerprints", "client_fingerprints",
         ("client_version", "hassh"), True),
    ]),
]


def build(data: Dataset, *, top: int = 10, dialect: str = "sqlite",
          charts: list[str] | None = None) -> str:
    queries = {name: result.query for name, result in data.results.items()}
    lines: list[str] = ["# ShadowPot report", ""]
    lines += banner(data.synthetic_state)
    lines += narrative(data)
    lines += provenance(data, dialect)

    # Dataset
    lines += ["## Dataset", "",
              f"*{queries['dataset_summary'].question}*", ""]
    summary = data.summary
    lines += md_table(
        ["measure", "value"],
        [[key.replace("_", " "), value] for key, value in summary.items()],
        align_right=["value"],
    )

    # Timeline
    per_day = data.rows("sessions_per_day")
    lines += ["## Timeline", "",
              f"*{queries['sessions_per_day'].question}*", ""]
    lines += md_table(
        ["day", "sessions", "distinct ips", "login attempts", "commands"],
        [[r["day"], r["sessions"], r["distinct_ips"], r["login_attempts"],
          r["commands"]] for r in per_day],
        align_right=["sessions", "distinct ips", "login attempts", "commands"],
    )
    if per_day:
        lines += ["Sessions per day:", ""]
        lines += ascii_bars([r["day"] for r in per_day],
                            [r["sessions"] for r in per_day])

    per_hour = data.rows("sessions_per_hour")
    lines += [f"*{queries['sessions_per_hour'].question}*", ""]
    if per_hour:
        lines += ascii_bars([f"{r['hour_utc']:02d}" for r in per_hour],
                            [r["sessions"] for r in per_hour])
        lines += [
            "A flat profile is itself a finding: human operators sleep and "
            "software does not. Hours are UTC.",
            "",
        ]

    durations = data.rows("session_duration_distribution")
    lines += ["## Session durations", "",
              f"*{queries['session_duration_distribution'].question}*", ""]
    lines += md_table(
        ["duration", "sessions", "% of measured"],
        [[r["bucket"], r["sessions"], r["pct_of_measured"]]
         for r in durations],
        align_right=["sessions", "% of measured"],
    )
    lines += [
        "Buckets rather than an average, because the distribution is "
        "bimodal: a mass of sub-second credential probes and a thin tail of "
        "real sessions. A mean over those two populations describes neither.",
        "",
    ]

    # The tabular sections
    for heading, entries in SECTIONS:
        lines += [f"## {heading}", ""]
        for title, name, code_columns, limited in entries:
            result = data.results[name]
            rows = result.rows[:top] if limited else result.rows
            shown = (f" (top {min(top, len(result.rows)):,} of "
                     f"{len(result.rows):,})" if limited
                     and len(result.rows) > top else "")
            lines += [f"### {title}{shown}", "",
                      f"*{result.query.question}*", ""]
            lines += md_table(list(result.columns), rows,
                              code_columns=code_columns,
                              align_right=[c for c in result.columns
                                           if c not in code_columns
                                           and c not in ("url", "outfile",
                                                         "first_seen",
                                                         "last_seen",
                                                         "first_success",
                                                         "last_success",
                                                         "ip", "auth_method")])

    # The heuristic, kept apart and labelled
    bot = data.results["bot_vs_human"]
    lines += ["## Scripted or hand-driven sessions", "",
              "**This section is a heuristic, not a measurement.** It infers "
              "from command timing and from sequences repeating across "
              "sessions. The log records what arrived, not who sent it. The "
              "thresholds are written into "
              "`queries/13_bot_vs_human.sql` so they can be argued with.",
              "",
              f"*{bot.query.question}*", ""]
    verdict_counts: dict[str, int] = {}
    for row in bot.dicts():
        verdict_counts[str(row["verdict"])] = (
            verdict_counts.get(str(row["verdict"]), 0) + 1)
    lines += md_table(
        ["verdict", "sessions"],
        sorted(verdict_counts.items(), key=lambda kv: -kv[1]),
        align_right=["sessions"],
    )
    lines += [f"### Slowest and fastest sessions (top {top:,} by command "
              f"count)", ""]
    lines += md_table(list(bot.columns), bot.rows[:top],
                      align_right=["duration_ms", "command_count",
                                   "mean_gap_ms", "min_gap_ms",
                                   "sessions_sharing_script", "session_pk"])

    # Data quality
    quality = data.results["ingest_quality"]
    lines += ["## Data quality", "",
              f"*{quality.query.question}*", "",
              "Every other section reports what was found. This one reports "
              "what was lost, which is the only way to judge the rest.", ""]
    lines += md_table(list(quality.columns), quality.rows,
                      align_right=[c for c in quality.columns
                                   if c not in ("started_at", "finished_at")])

    if charts:
        lines += ["## Charts", ""]
        for path in charts:
            lines += [f"![{pathlib.Path(path).stem}]({path})", ""]

    lines += limitations(data)
    return "\n".join(lines).rstrip() + "\n"


def limitations(data: Dataset) -> list[str]:
    items = [
        "**Geolocation and network ownership are not measured.** That needs "
        "an offline GeoIP database this project does not ship. ShadowPot "
        "makes no live API calls with attacker addresses, deliberately.",
        "**The scripted-or-hand-driven split is a heuristic.** Thresholds are "
        "in `queries/13_bot_vs_human.sql`. On synthetic data the two "
        "populations separate cleanly, which demonstrates the SQL is correct "
        "and says nothing about whether the thresholds suit real traffic.",
        "**A successful login is not a compromise.** Cowrie accepts whatever "
        "its configuration accepts, so successes measure which staged "
        "credential was found.",
        "**Unmodelled events are excluded from every total.** The event ids "
        "this project does not handle are listed in "
        "`docs/LOG_FORMAT.md` section 6, and counted under Data quality.",
        "**Session identifiers are unique per sensor, not globally.** Merging "
        "two honeypots' databases needs the `(sensor, session)` key; see "
        "`docs/NORMALIZATION.md` section 8.3.",
    ]
    if data.synthetic_state != "none":
        items.insert(0, f"**{BANNER_SYNTHETIC}.** Nothing here is a "
                        "measurement of real attacker behaviour.")
    return ["## Limitations", "", *[f"- {item}" for item in items], ""]


# ---------------------------------------------------------------------------
# Optional charts
# ---------------------------------------------------------------------------

def write_charts(data: Dataset, out_dir: pathlib.Path) -> list[str]:
    """PNG charts, if matplotlib is available.

    matplotlib is deliberately NOT a dependency. The default report is tables
    plus ASCII bars so that it renders from a clean clone with nothing
    installed; this is strictly an extra.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")       # no display on a server or in CI
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError(
            "--charts needs matplotlib, which is not installed. Either\n"
            "    python3 -m pip install matplotlib\n"
            "or just omit --charts: the default report contains the same "
            "figures as tables and ASCII bar charts, and needs nothing "
            "beyond the standard library."
        ) from exc

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    per_day = data.rows("sessions_per_day")
    if per_day:
        figure, axes = plt.subplots(figsize=(9, 3.2))
        axes.bar([r["day"] for r in per_day], [r["sessions"] for r in per_day])
        axes.set_title("Sessions per day"
                       + (f"  [{BANNER_SYNTHETIC}]"
                          if data.synthetic_state != "none" else ""))
        axes.set_ylabel("sessions")
        plt.xticks(rotation=45, ha="right")
        figure.tight_layout()
        target = out_dir / "sessions_per_day.png"
        figure.savefig(target, dpi=120)
        plt.close(figure)
        written.append(str(target.relative_to(out_dir.parent)))

    per_hour = data.rows("sessions_per_hour")
    if per_hour:
        figure, axes = plt.subplots(figsize=(9, 3.2))
        axes.bar([r["hour_utc"] for r in per_hour],
                 [r["sessions"] for r in per_hour])
        axes.set_title("Sessions by hour of day (UTC)"
                       + (f"  [{BANNER_SYNTHETIC}]"
                          if data.synthetic_state != "none" else ""))
        axes.set_xlabel("hour (UTC)")
        axes.set_ylabel("sessions")
        figure.tight_layout()
        target = out_dir / "sessions_per_hour.png"
        figure.savefig(target, dpi=120)
        plt.close(figure)
        written.append(str(target.relative_to(out_dir.parent)))

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m shadowpot.report",
        description="Generate reports/report.md from a loaded database.",
    )
    p.add_argument("--db", default="data/shadowpot.db", metavar="DSN")
    p.add_argument("--out", default="reports/report.md")
    p.add_argument("--top", type=int, default=10, metavar="N",
                   help="rows per top-N table (default: %(default)s)")
    p.add_argument("--charts", action="store_true",
                   help="also write PNG charts (needs matplotlib, which is "
                        "not a dependency)")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target = pathlib.Path(args.out)

    database = dbmod.connect(args.db, apply_schema=False, apply_indexes=False)
    try:
        data = collect(database, database.dialect.name)
        data.db_path = args.db
        charts = (write_charts(data, target.parent / "charts")
                  if args.charts else None)
        text = build(data, top=args.top, dialect=database.dialect.name,
                     charts=charts)
    finally:
        database.close()

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")

    if not args.quiet:
        state = data.synthetic_state
        print(f"wrote {target} ({len(text):,} bytes, "
              f"{text.count(chr(10)):,} lines)", file=sys.stderr)
        if state != "none":
            label = (BANNER_SYNTHETIC if state == "all"
                     else BANNER_SYNTHETIC + " MIXED WITH REAL DATA")
            print(f"\n  {'=' * 62}\n   {label}\n"
                  "   No number in this report may be published as a "
                  "measurement.\n"
                  f"  {'=' * 62}\n", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Load and run the analytics queries in queries/.

The SQL lives in .sql files rather than in Python strings for three reasons:
it can be run by hand with the sqlite3 CLI while you are developing it, it
diffs readably, and the point of this project is the SQL itself -- burying it
in string literals would hide the work.

Each file carries a metadata header that this module parses:

    -- @name      top_usernames
    -- @title     Most-tried usernames
    -- @question  Which account names do attackers guess most often?
    -- @uses      view, GROUP BY
    -- @dialect   mysql: DATE() replaces substr(ts, 1, 10)
    --
    -- ... free prose explaining the reasoning, not parsed ...

A continuation line is a comment indented by two or more spaces. The header
ends at the first bare `--`.

NO QUERY CONTAINS A LIMIT. They order their rows and the caller takes what it
wants. Two reasons: LIMIT with a bound parameter needs different placeholder
syntax in each dialect, which would have meant an override file per top-N
query for no analytical difference; and the same query then serves both "the
top 10 for the report" and "the whole table for a test" without duplication.
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
from typing import Any, Sequence

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
QUERY_DIR = REPO_ROOT / "queries"

_META = re.compile(r"^--\s+@(\w+)\s+(.*)$")
_CONT = re.compile(r"^--\s{2,}(\S.*)$")


@dataclasses.dataclass(frozen=True)
class Query:
    name: str
    title: str
    question: str
    uses: str
    sql: str
    path: pathlib.Path
    dialect_note: str | None = None

    @property
    def features(self) -> set[str]:
        """The SQL features this query demonstrates, from its @uses line.

        Used by tests to prove the suite as a whole covers what the project
        set out to show, rather than asserting it in prose and hoping.
        """
        found = set()
        text = self.uses.lower()
        if "having" in text:
            found.add("having")
        if "window" in text:
            found.add("window")
        if "cte" in text:
            found.add("cte")
        if "view" in text:
            found.add("view")
        return found


@dataclasses.dataclass(frozen=True)
class Result:
    query: Query
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]

    def __len__(self) -> int:
        return len(self.rows)

    def dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, row)) for row in self.rows]

    def top(self, n: int) -> tuple[tuple[Any, ...], ...]:
        return self.rows[:n]


class QueryError(RuntimeError):
    pass


def parse_query(path: pathlib.Path) -> Query:
    text = path.read_text(encoding="utf-8")
    meta: dict[str, str] = {}
    current: str | None = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if line == "--":
            break
        match = _META.match(line)
        if match:
            current = match.group(1)
            meta[current] = match.group(2).strip()
            continue
        cont = _CONT.match(line)
        if cont and current:
            meta[current] = f"{meta[current]} {cont.group(1).strip()}"
            continue
        if not line.startswith("--"):
            break
        current = None

    missing = {"name", "title", "question", "uses"} - meta.keys()
    if missing:
        raise QueryError(
            f"{path.name} is missing header field(s) {sorted(missing)}. Every "
            "query must state the question it answers; a query whose purpose "
            "is not written down cannot be reviewed."
        )

    return Query(
        name=meta["name"],
        title=meta["title"],
        question=meta["question"],
        uses=meta["uses"],
        dialect_note=meta.get("dialect"),
        sql=text,
        path=path,
    )


def load_queries(dialect: str = "sqlite") -> list[Query]:
    """All queries in filename order, with dialect overrides substituted.

    queries/*.sql is canonical SQLite. queries/<dialect>/*.sql holds ONLY the
    files whose SQL genuinely differs -- in practice the date and time
    functions. An override replaces the base file of the same name, so the
    set of queries is identical in both dialects and only their text differs.
    """
    base = {path.name: path for path in sorted(QUERY_DIR.glob("*.sql"))}
    if not base:
        raise QueryError(f"no .sql files found in {QUERY_DIR}")

    override_dir = QUERY_DIR / dialect
    if override_dir.is_dir():
        for path in override_dir.glob("*.sql"):
            if path.name not in base:
                raise QueryError(
                    f"{dialect} override {path.name} has no base query of "
                    "that name, so it would never be loaded"
                )
            base[path.name] = path

    return [parse_query(base[name]) for name in sorted(base)]


def run(database: Any, query: Query) -> Result:
    """Execute one query. Read-only by construction: the SQL files contain
    only SELECTs, which tests assert."""
    cursor = database.execute(query.sql)
    columns = tuple(d[0] for d in (cursor.description or ()))
    return Result(query=query, columns=columns,
                  rows=tuple(tuple(row) for row in cursor.fetchall()))


def run_all(database: Any, queries: Sequence[Query] | None = None,
            dialect: str = "sqlite") -> list[Result]:
    return [run(database, q) for q in (queries or load_queries(dialect))]


def feature_coverage(queries: Sequence[Query]) -> dict[str, list[str]]:
    """Which queries demonstrate which SQL feature."""
    coverage: dict[str, list[str]] = {
        "having": [], "window": [], "cte": [], "view": [],
    }
    for query in queries:
        for feature in query.features:
            coverage[feature].append(query.name)
    return coverage

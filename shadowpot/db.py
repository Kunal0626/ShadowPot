"""Connections, schema application, and the SQLite/MySQL dialect switch.

SQLite is canonical: it needs no server, ships in Python's standard library,
and therefore lets anyone clone the repository and run the whole pipeline. The
MySQL path exists because the project brief asks for it and because MySQL is
what most places actually run.

HONEST STATUS OF THE MySQL PATH. It is wired end to end -- DSN parsing,
placeholder style, INSERT IGNORE, DATETIME(6) conversion -- and the SQL it
generates is unit-tested for both dialects without a server. But it has never
been executed against a live MySQL server, because the development machine's
MySQL rejects connections without credentials and this project stores no
database passwords. Until someone runs it, treat it as unproven: the generated
SQL is verified, the round trip is not. tests/test_db.py marks the gap
explicitly rather than leaving it to be discovered.

The dialect differences that actually matter here are small but unforgiving:

    placeholder     ?            vs  %s
    ignore-dupes    INSERT OR IGNORE  vs  INSERT IGNORE
    timestamps      canonical TEXT    vs  DATETIME(6), which rejects
                                          the 'T' separator and the 'Z'
    foreign keys    PRAGMA per connection  vs  always on in InnoDB
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
import sqlite3
from typing import Any, Iterable, Sequence

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schema"

SCHEMA_VERSION = "2"


class SchemaMismatch(RuntimeError):
    """The database was built by a different version of the schema."""


# ---------------------------------------------------------------------------
# Dialects
# ---------------------------------------------------------------------------

class Dialect:
    """Everything that differs between the two engines, in one place."""

    name: str
    placeholder: str
    schema_file: str

    def insert_or_ignore(self, table: str, columns: Sequence[str]) -> str:
        raise NotImplementedError

    def insert(self, table: str, columns: Sequence[str]) -> str:
        raise NotImplementedError

    def update(self, table: str, set_columns: Sequence[str],
               where_columns: Sequence[str]) -> str:
        marks = ", ".join(f"{c} = {self.placeholder}" for c in set_columns)
        where = " AND ".join(f"{c} = {self.placeholder}" for c in where_columns)
        return f"UPDATE {table} SET {marks} WHERE {where}"

    def select_one(self, table: str, column: str,
                   where_columns: Sequence[str]) -> str:
        where = " AND ".join(f"{c} = {self.placeholder}" for c in where_columns)
        return f"SELECT {column} FROM {table} WHERE {where}"

    def timestamp(self, canonical: str | None) -> Any:
        raise NotImplementedError

    def _marks(self, n: int) -> str:
        return ", ".join([self.placeholder] * n)


class SQLiteDialect(Dialect):
    name = "sqlite"
    placeholder = "?"
    schema_file = "schema.sqlite.sql"

    def insert_or_ignore(self, table: str, columns: Sequence[str]) -> str:
        return (f"INSERT OR IGNORE INTO {table} ({', '.join(columns)}) "
                f"VALUES ({self._marks(len(columns))})")

    def insert(self, table: str, columns: Sequence[str]) -> str:
        return (f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({self._marks(len(columns))})")

    def timestamp(self, canonical: str | None) -> Any:
        # Stored verbatim. The canonical form is the storage format, and the
        # schema's CHECK constraints enforce it -- which is what stops a
        # non-canonical value from silently breaking every date query.
        return canonical


class MySQLDialect(Dialect):
    name = "mysql"
    placeholder = "%s"
    schema_file = "schema.mysql.sql"

    def insert_or_ignore(self, table: str, columns: Sequence[str]) -> str:
        return (f"INSERT IGNORE INTO {table} ({', '.join(columns)}) "
                f"VALUES ({self._marks(len(columns))})")

    def insert(self, table: str, columns: Sequence[str]) -> str:
        return (f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({self._marks(len(columns))})")

    def timestamp(self, canonical: str | None) -> Any:
        """Convert the canonical text form to something DATETIME(6) accepts.

        MySQL rejects both the 'T' separator and the trailing 'Z'. The value
        is already UTC, and DATETIME carries no zone, so dropping the marker
        loses nothing -- as long as every writer and reader agrees that the
        column is UTC, which is recorded in the schema header.
        """
        if canonical is None:
            return None
        return canonical.replace("T", " ").rstrip("Z")


DIALECTS = {"sqlite": SQLiteDialect(), "mysql": MySQLDialect()}


# ---------------------------------------------------------------------------
# DSN parsing
# ---------------------------------------------------------------------------

_MYSQL_DSN = re.compile(
    r"^mysql://(?:(?P<user>[^:@/]+)(?::(?P<password>[^@/]*))?@)?"
    r"(?P<host>[^:/]+)(?::(?P<port>\d+))?/(?P<database>[^?]+)$"
)


@dataclasses.dataclass(frozen=True)
class Target:
    dialect: Dialect
    sqlite_path: pathlib.Path | None = None
    mysql_kwargs: dict[str, Any] | None = None


def parse_dsn(dsn: str) -> Target:
    """Accept a bare filesystem path, sqlite:///path, or mysql://...

    A bare path is accepted because `--db data/shadowpot.db` is what anyone
    actually types, and demanding a URL scheme for the default engine would be
    friction with no benefit.
    """
    if dsn.startswith("mysql://"):
        match = _MYSQL_DSN.match(dsn)
        if not match:
            raise ValueError(
                f"malformed MySQL DSN: {dsn!r}. Expected "
                "mysql://user:password@host:port/database"
            )
        parts = match.groupdict()
        kwargs: dict[str, Any] = {
            "host": parts["host"],
            "database": parts["database"],
        }
        if parts["user"]:
            kwargs["user"] = parts["user"]
        if parts["password"] is not None:
            kwargs["password"] = parts["password"]
        if parts["port"]:
            kwargs["port"] = int(parts["port"])
        return Target(DIALECTS["mysql"], mysql_kwargs=kwargs)

    path = dsn[len("sqlite:///"):] if dsn.startswith("sqlite:///") else dsn
    if not path:
        raise ValueError("no SQLite path given")
    return Target(DIALECTS["sqlite"], sqlite_path=pathlib.Path(path))


# ---------------------------------------------------------------------------
# Database handle
# ---------------------------------------------------------------------------

class Database:
    """A thin wrapper: a connection, its dialect, and the few helpers the
    loader needs. Deliberately not an ORM -- the SQL in this project is the
    point of the project.
    """

    def __init__(self, conn: Any, dialect: Dialect) -> None:
        self.conn = conn
        self.dialect = dialect

    # -- plumbing -------------------------------------------------------

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        cur = self.conn.cursor()
        cur.execute(sql, tuple(params))
        return cur

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        cur = self.execute(sql, params)
        row = cur.fetchone()
        return None if row is None else row[0]

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- helpers --------------------------------------------------------

    def get_or_create(self, table: str, unique: dict[str, Any],
                      pk: str, extra: dict[str, Any] | None = None) -> Any:
        """INSERT OR IGNORE then SELECT, returning the primary key.

        Why not rely on cursor.lastrowid? Because when the row already exists
        the INSERT is ignored and lastrowid is meaningless -- in SQLite it
        holds the id of whatever was last inserted on that connection, which
        is a different row entirely. Reading the key back is the only correct
        answer, and it is also what makes the operation idempotent.

        This is the single pattern that makes re-ingestion safe for every
        dimension table, and it works only because each of those tables has a
        UNIQUE constraint over NOT NULL columns.
        """
        columns = {**unique, **(extra or {})}
        self.execute(
            self.dialect.insert_or_ignore(table, list(columns)),
            list(columns.values()),
        )
        return self.scalar(
            self.dialect.select_one(table, pk, list(unique)),
            list(unique.values()),
        )

    def insert_or_ignore(self, table: str, values: dict[str, Any]) -> int:
        """Returns the number of rows actually inserted (0 or 1).

        The caller uses this to tell "applied" from "already present", which
        is what the ingest_runs tally reports.
        """
        cur = self.execute(
            self.dialect.insert_or_ignore(table, list(values)),
            list(values.values()),
        )
        return int(cur.rowcount or 0)

    def update(self, table: str, changes: dict[str, Any],
               where: dict[str, Any]) -> None:
        self.execute(
            self.dialect.update(table, list(changes), list(where)),
            list(changes.values()) + list(where.values()),
        )


def connect(dsn: str, *, apply_schema: bool = True) -> Database:
    target = parse_dsn(dsn)

    if target.dialect.name == "sqlite":
        assert target.sqlite_path is not None
        if target.sqlite_path.parent != pathlib.Path(""):
            target.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(target.sqlite_path))
        db = Database(conn, target.dialect)
        if apply_schema:
            _apply_schema_sqlite(conn, target.dialect)
        # MUST be set on every connection, and AFTER executescript: SQLite
        # defaults foreign keys OFF for backward compatibility, and the PRAGMA
        # is a no-op inside a transaction. Getting this wrong gives a database
        # that looks constrained and is not.
        conn.execute("PRAGMA foreign_keys = ON")
        if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise RuntimeError("could not enable foreign key enforcement")
    else:
        assert target.mysql_kwargs is not None
        try:
            import mysql.connector as driver  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "the MySQL path needs mysql-connector-python, which is not "
                "installed. Install it with:\n"
                "    python3 -m pip install mysql-connector-python\n"
                "SQLite is the default and needs nothing: --db data/shadowpot.db"
            ) from exc
        conn = driver.connect(**target.mysql_kwargs)
        db = Database(conn, target.dialect)
        if apply_schema:
            _apply_schema_mysql(conn, target.dialect)

    _check_schema_version(db)
    return db


def _schema_sql(dialect: Dialect) -> str:
    return (SCHEMA_DIR / dialect.schema_file).read_text(encoding="utf-8")


def _apply_schema_sqlite(conn: sqlite3.Connection, dialect: Dialect) -> None:
    conn.executescript(_schema_sql(dialect))
    conn.commit()


def _split_statements(sql: str) -> Iterable[str]:
    """Split a MySQL script into statements.

    Naive on purpose: it works because schema.mysql.sql contains no stored
    procedures, triggers, or semicolons inside string literals. If that ever
    stops being true this needs a real tokenizer, and the schema file says so.
    """
    for chunk in sql.split(";\n"):
        statement = "\n".join(
            line for line in chunk.splitlines()
            if line.strip() and not line.strip().startswith("--")
        ).strip()
        if statement:
            yield statement


def _apply_schema_mysql(conn: Any, dialect: Dialect) -> None:
    cur = conn.cursor()
    for statement in _split_statements(_schema_sql(dialect)):
        cur.execute(statement)
    conn.commit()


def _check_schema_version(db: Database) -> None:
    found = db.scalar(
        db.dialect.select_one("db_meta", "meta_value", ["meta_key"]),
        ["schema_version"],
    )
    if found is None:
        raise SchemaMismatch(
            "db_meta holds no schema_version; this database was not created "
            "by schema/ and may be something else entirely"
        )
    if str(found) != SCHEMA_VERSION:
        raise SchemaMismatch(
            f"database schema_version is {found!r} but this code expects "
            f"{SCHEMA_VERSION!r}. Rebuild the database, or load it with the "
            "matching ShadowPot version."
        )

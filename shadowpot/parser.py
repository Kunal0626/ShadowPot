"""Turn one raw Cowrie JSON line into a typed, canonicalized Event.

This module is deliberately pure: it touches no database, no filesystem and no
clock. That is what makes the awkward cases cheap to test -- every edge case in
docs/LOG_FORMAT.md section 9 is a one-line assertion here rather than a
fixture file and a database.

It is also the single place where "whatever Cowrie emitted" becomes "what
ShadowPot stores". Keeping that boundary in one function is what makes an
upstream field rename a one-line change instead of a hunt.

Every line ends up in exactly one of four categories, which map one-to-one
onto the counters in the ingest_runs table:

    EVENT       usable; apply it
    MALFORMED   not parseable, or parseable but not an event      -> lines_malformed
    UNKNOWN     a well-formed event with an id we do not model    -> events_unknown
    INCOMPLETE  an event we model, but missing or holding an
                unusable value for something we require           -> events_incomplete

The distinction between MALFORMED and UNKNOWN matters: an event id we have
never heard of is normal and expected (Cowrie gains events, and enrichment
plugins write their own into the same stream), whereas an unparseable line
means something truncated or corrupted the file. Counting them together would
hide a real problem behind a routine one.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import ipaddress
import json
from typing import Any

# The canonical timestamp form every ts column stores, enforced by CHECK
# constraints in the schema. See db.py and schema/schema.sqlite.sql.
CANONICAL_TS = "%Y-%m-%dT%H:%M:%S.{micro:06d}Z"


class Status(enum.Enum):
    EVENT = "event"
    MALFORMED = "malformed"
    UNKNOWN = "unknown"
    INCOMPLETE = "incomplete"


@dataclasses.dataclass(frozen=True)
class Event:
    """One usable Cowrie event, canonicalized.

    `data` holds the event-specific values, already coerced to the types the
    schema expects. What goes in it is documented per event in
    _EXTRACTORS below.
    """

    eventid: str
    ts: str                       # canonical UTC ISO-8601 with a literal Z
    sensor: str
    session: str | None
    src_ip: str | None            # canonicalized through ipaddress
    src_ip_version: int | None
    is_synthetic: bool
    is_late: bool
    data: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class ParsedLine:
    status: Status
    event: Event | None = None
    reason: str | None = None


# Event ids ShadowPot models. Anything else is UNKNOWN, which is a routine
# outcome rather than an error: see docs/LOG_FORMAT.md section 6 for the list
# of real Cowrie events deliberately not modelled here.
HANDLED_EVENTS = frozenset({
    "cowrie.session.connect",
    "cowrie.client.version",
    "cowrie.client.kex",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
    "cowrie.session.closed",
})

DEFAULT_SENSOR = "unknown"


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

class FieldError(ValueError):
    """A field exists but cannot be used. Carries the reason for the tally."""


def canonical_timestamp(raw: object) -> str:
    """Normalize a Cowrie timestamp to the one form the schema accepts.

    Cowrie picks its format from the process environment: TZ=UTC yields
    '...Z', anything else yields '%z', which renders the LOCAL offset with no
    colon -- '+0000' on a UTC box, but '+0530' or '-0500' elsewhere. All of
    those have to arrive at the same canonical UTC string, because the schema
    stores timestamps as text and relies on lexicographic ordering being
    chronological.

    This is not a theoretical concern. SQLite's date functions return NULL for
    the no-colon offset form while storing it happily as text, so a load that
    skipped this step would make GROUP BY date(ts) collapse every row into one
    NULL bucket -- a plausible-looking wrong answer rather than an error.
    """
    if not isinstance(raw, str):
        raise FieldError(f"timestamp is {type(raw).__name__}, not a string")
    try:
        # Python 3.11+ fromisoformat handles 'Z', '+0000' and '+05:30'.
        moment = dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise FieldError(f"unparseable timestamp {raw!r}: {exc}") from exc
    if moment.tzinfo is None:
        # Cowrie always writes an offset or a Z. A naive timestamp means a
        # hand-edited or third-party file; UTC is the only defensible
        # assumption, and it is recorded here rather than left implicit.
        moment = moment.replace(tzinfo=dt.timezone.utc)
    moment = moment.astimezone(dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}Z"


def canonical_ip(raw: object) -> tuple[str, int]:
    """Return (canonical text form, version).

    ipaddress collapses the many spellings of one IPv6 address, so ::1 and
    0:0:0:0:0:0:0:1 cannot become two rows in `sources`.
    """
    if not isinstance(raw, str):
        raise FieldError(f"ip is {type(raw).__name__}, not a string")
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise FieldError(f"not an IP address: {raw!r}") from exc
    return str(addr), addr.version


def _as_int(raw: object, field: str) -> int:
    """Coerce to int, refusing anything lossy.

    bool is rejected explicitly because it is a subclass of int in Python, and
    a True arriving in a port column should be a visible error rather than 1.
    """
    if isinstance(raw, bool):
        raise FieldError(f"{field} is a boolean, not a number")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        if raw != int(raw):
            raise FieldError(f"{field} is {raw!r}, not a whole number")
        return int(raw)
    if isinstance(raw, str):
        try:
            return int(raw.strip())
        except ValueError as exc:
            raise FieldError(f"{field} is {raw!r}, not a number") from exc
    raise FieldError(f"{field} is {type(raw).__name__}, not a number")


def _as_bool01(raw: object) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, (int, float)) and raw in (0, 1):
        return int(raw)
    if isinstance(raw, str) and raw.lower() in ("true", "false"):
        return int(raw.lower() == "true")
    raise FieldError(f"not a boolean: {raw!r}")


def _as_text(raw: object, field: str) -> str:
    if isinstance(raw, str):
        return raw
    raise FieldError(f"{field} is {type(raw).__name__}, not a string")


def _join_list(raw: object, field: str) -> str | None:
    """Cowrie sends the key-exchange algorithm offers as JSON ARRAYS.

    They are stored as comma-joined text. docs/NORMALIZATION.md section 3
    records this as the project's one deliberate 1NF compromise and names the
    child table that would fix it if a query ever needs individual algorithms.
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, str):
                raise FieldError(f"{field} contains a non-string element")
        return ",".join(raw)
    raise FieldError(f"{field} is {type(raw).__name__}, not a list or string")


# ---------------------------------------------------------------------------
# Per-event extraction
#
# Each extractor returns the event-specific `data` dict, or raises FieldError
# if the event cannot be used. Required fields are read with raw[...] so a
# missing one raises KeyError, which parse_line turns into INCOMPLETE.
# ---------------------------------------------------------------------------

def _connect(raw: dict) -> dict:
    data: dict[str, Any] = {}
    # protocol is passed through rather than filtered to ssh/telnet. If Cowrie
    # ever adds a third, the schema's CHECK rejects the row and it is counted
    # as incomplete with a clear reason -- surfacing format drift instead of
    # silently storing NULL and pretending nothing changed.
    if "protocol" in raw:
        data["protocol"] = _as_text(raw["protocol"], "protocol")
    for field in ("src_port", "dst_port"):
        if field in raw:
            data[field] = _as_int(raw[field], field)
    if "dst_ip" in raw:
        data["dst_ip"] = _as_text(raw["dst_ip"], "dst_ip")
    return data


def _client_version(raw: dict) -> dict:
    # The Cowrie field is `version`. Not `client_version`.
    return {"version": _as_text(raw["version"], "version")}


def _client_kex(raw: dict) -> dict:
    return {
        "hassh": _as_text(raw["hassh"], "hassh"),
        "hassh_algorithms": _as_text(raw["hasshAlgorithms"], "hasshAlgorithms"),
        # keyAlgs and langCS are NOT inputs to the HASSH digest, so hassh does
        # not determine them and they belong to the session rather than to the
        # fingerprint. See docs/NORMALIZATION.md N1 -- this is the trap that
        # makes all eight kex fields look like one unit.
        "key_algs": _join_list(raw.get("keyAlgs"), "keyAlgs"),
        "lang_cs": _join_list(raw.get("langCS"), "langCS"),
    }


def _login(raw: dict, *, success: bool) -> dict:
    data: dict[str, Any] = {
        "success": int(success),
        "username": _as_text(raw["username"], "username"),
    }
    if "password" in raw:
        data["auth_method"] = "password"
        data["password"] = _as_text(raw["password"], "password")
    elif "fingerprint" in raw:
        # A public-key attempt carries NO password field at all. This is the
        # case that defeats a nullable-password credentials table, and the
        # reason login_attempts uses an exclusive arc.
        data["auth_method"] = "publickey"
        data["fingerprint"] = _as_text(raw["fingerprint"], "fingerprint")
        data["key_type"] = (_as_text(raw["type"], "type")
                            if "type" in raw else None)
        data["key_blob"] = (_as_text(raw["key"], "key")
                            if "key" in raw else None)
    else:
        raise FieldError(
            "login event has neither a password nor a fingerprint, so there "
            "is no credential to record"
        )
    return data


def _command(raw: dict, *, implemented: bool) -> dict:
    # The Cowrie field is `input`. Not `command`.
    return {
        "input": _as_text(raw["input"], "input"),
        "realm": _as_text(raw["realm"], "realm") if "realm" in raw else None,
        "implemented": int(implemented),
    }


def _file_transfer(raw: dict, *, direction: str) -> dict:
    data: dict[str, Any] = {
        "direction": direction,
        # `shasum` is a SHA-256 despite the name. Absent in some edge cases,
        # so it is optional rather than required.
        "sha256": _as_text(raw["shasum"], "shasum") if "shasum" in raw else None,
        "outfile": _as_text(raw["outfile"], "outfile") if "outfile" in raw else None,
        "destfile": (_as_text(raw["destfile"], "destfile")
                     if "destfile" in raw else None),
        "is_duplicate": _as_bool01(raw.get("duplicate")),
        # url is absent for stdin and shell-redirect captures, and always
        # absent on an upload. The project brief had this NOT NULL.
        "url": _as_text(raw["url"], "url") if "url" in raw else None,
        "filename": (_as_text(raw["filename"], "filename")
                     if "filename" in raw else None),
    }
    return data


def _session_closed(raw: dict) -> dict:
    """Read the session duration, accepting both the current and legacy fields.

    Cowrie 3.0.4 renamed `duration` to `duration_ms` and changed its type. The
    changelog records the old field as "a string for some transports and a
    float for others", so the legacy branch coerces from either.
    """
    if "duration_ms" in raw:
        return {"duration_ms": _as_int(raw["duration_ms"], "duration_ms")}
    if "duration" in raw:
        legacy = raw["duration"]
        if isinstance(legacy, bool) or not isinstance(legacy, (int, float, str)):
            raise FieldError(f"legacy duration is {type(legacy).__name__}")
        try:
            seconds = float(legacy)
        except ValueError as exc:
            raise FieldError(f"legacy duration {legacy!r} is not numeric") from exc
        return {"duration_ms": round(seconds * 1000)}
    # A session.closed with no duration at all is still useful: it tells us
    # when the session ended. Only the duration is missing.
    return {"duration_ms": None}


_EXTRACTORS = {
    "cowrie.session.connect": _connect,
    "cowrie.client.version": _client_version,
    "cowrie.client.kex": _client_kex,
    "cowrie.login.failed": lambda raw: _login(raw, success=False),
    "cowrie.login.success": lambda raw: _login(raw, success=True),
    "cowrie.command.input": lambda raw: _command(raw, implemented=True),
    "cowrie.command.failed": lambda raw: _command(raw, implemented=False),
    "cowrie.session.file_download":
        lambda raw: _file_transfer(raw, direction="download"),
    "cowrie.session.file_upload":
        lambda raw: _file_transfer(raw, direction="upload"),
    "cowrie.session.closed": _session_closed,
}

# Events that cannot be applied without a session id, because every row they
# produce hangs off one. cowrie.abuseipdb.* events carry no session at all,
# which is why this is checked rather than assumed.
_REQUIRE_SESSION = frozenset(HANDLED_EVENTS)


def parse_line(raw_line: str) -> ParsedLine:
    """Classify and parse one line of cowrie.json.

    Dispatch is on the WHOLE eventid by exact match, never on a split prefix:
    `cowrie.session.file_download.failed` has four dotted components, so
    splitting on '.' and taking [1:3] would misroute it onto
    `cowrie.session.file_download` and invent a download that never happened.
    """
    text = raw_line.strip()
    if not text:
        return ParsedLine(Status.MALFORMED, reason="blank line")

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        return ParsedLine(Status.MALFORMED, reason=f"invalid JSON: {exc.msg}")

    if not isinstance(obj, dict):
        return ParsedLine(
            Status.MALFORMED,
            reason=f"top-level JSON is {type(obj).__name__}, not an object",
        )

    eventid = obj.get("eventid")
    if not isinstance(eventid, str):
        # Guarding the type, not just presence: a parser doing
        # eventid.startswith(...) raises AttributeError on a numeric eventid.
        return ParsedLine(
            Status.MALFORMED,
            reason="eventid is missing or not a string",
        )

    if eventid not in HANDLED_EVENTS:
        return ParsedLine(Status.UNKNOWN, reason=f"unmodelled event {eventid}")

    session = obj.get("session")
    if eventid in _REQUIRE_SESSION and not isinstance(session, str):
        return ParsedLine(
            Status.INCOMPLETE,
            reason=f"{eventid} has no session id",
        )

    try:
        ts = canonical_timestamp(obj.get("timestamp"))
        src_ip: str | None = None
        version: int | None = None
        if obj.get("src_ip") is not None:
            src_ip, version = canonical_ip(obj["src_ip"])
        data = _EXTRACTORS[eventid](obj)
    except FieldError as exc:
        return ParsedLine(Status.INCOMPLETE, reason=f"{eventid}: {exc}")
    except KeyError as exc:
        return ParsedLine(
            Status.INCOMPLETE,
            reason=f"{eventid} is missing required field {exc.args[0]!r}",
        )

    sensor = obj.get("sensor")
    event = Event(
        eventid=eventid,
        ts=ts,
        sensor=sensor if isinstance(sensor, str) and sensor else DEFAULT_SENSOR,
        session=session if isinstance(session, str) else None,
        src_ip=src_ip,
        src_ip_version=version,
        # Not a Cowrie field. tools/gen_sample_logs.py stamps it on every line
        # it writes so that synthetic data can never be mistaken for a real
        # capture, and so report.py can refuse to present it as a finding.
        is_synthetic=obj.get("synthetic") is True,
        # Dispatched after its connection closed, so it appears AFTER
        # cowrie.session.closed in the file. Treating `closed` as a terminator
        # would drop exactly these rows -- completed malware downloads.
        is_late=obj.get("late") is True,
        data=data,
    )
    return ParsedLine(Status.EVENT, event=event)

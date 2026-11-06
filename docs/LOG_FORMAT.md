# Cowrie log format: verified field reference

This document records the **exact** JSON fields ShadowPot's loader relies on, and
how each one was verified. It exists because guessing log field names is the
single easiest way to build a parser that silently drops data.

Nothing in this file is from memory. Every field below was read out of Cowrie's
own source or its own event reference on the date given.

---

## 1. What was checked, and when

| Item | Value |
|---|---|
| Verified on | 2026-11-06 |
| Cowrie latest release | **3.1.5** (released 2026-10-31) |
| Source branch read | `master`, as checked out by `raw.githubusercontent.com` on 2026-11-06 |
| Verified by | reading Cowrie source + `docs/OUTPUT.rst` (not the rendered website) |

Sources read, in order of authority:

1. `docs/OUTPUT.rst` — Cowrie's own event-code reference. `src/cowrie/core/output.py`
   names this file as the canonical list: *"The event ids and their attributes are
   documented in docs/OUTPUT.rst."*
   <https://raw.githubusercontent.com/cowrie/cowrie/master/docs/OUTPUT.rst>
2. `src/cowrie/output/jsonlog.py` — the plugin that actually writes `cowrie.json`.
   This is the only authority on what survives into the file.
   <https://raw.githubusercontent.com/cowrie/cowrie/master/src/cowrie/output/jsonlog.py>
3. `src/cowrie/core/output.py` — base class; shared attributes and timestamp format.
   <https://raw.githubusercontent.com/cowrie/cowrie/master/src/cowrie/core/output.py>
4. `src/cowrie/ssh/transport.py`, `src/cowrie/telnet/transport.py` — session id
   generation and `duration_ms` computation.
5. `src/cowrie/python/logfile.py` — rotation and rotated filename suffix.
6. `CHANGELOG.rst` — to date the one breaking field rename that affects us.
7. `docs/sql/mysql.sql` — Cowrie's own (old, barely normalized) SQL schema, kept
   here for comparison in `NORMALIZATION.md`.

### A warning about the published docs

`readthedocs.io` and `docs.cowrie.org` were **out of sync** when checked:
`/en/stable/` showed 3.0.0 as newest while `/en/latest/` topped out at 2.9.0, and
the generated PDF self-reported `3.0.4.dev42+gd610dc061`. Meanwhile
`CHANGELOG.rst` on `master` lists releases up to 3.1.5. **Read the source, not
the website.** Anything in this file that disagrees with the rendered docs was
taken from the source and wins.

---

## 2. The file itself

- **Format:** JSON Lines. One complete JSON object per line, `\n` separated.
- **Serialization:** `json.dumps(event, separators=(",", ":"))` — compact, no
  spaces after separators. Do not rely on whitespace to find anything.
- **Atomicity:** `jsonlog.py` serializes the whole event to a string and writes it
  in **one** `write()` call, with a comment explaining why: a rotating logfile
  checks for rotation on every write, so a chunked write could rotate mid-event
  and split one JSON object across two files. It then `flush()`es every line.
  **Consequence for us:** a line is never split across files, and a partially
  written trailing line is possible only if the process is killed mid-write. Our
  parser must still tolerate a truncated final line, but it will be rare.
- **Default path:** `var/log/cowrie/cowrie.json`, set by `[output_jsonlog] logfile`.
- **Rotation:** controlled by `[honeypot] logtype`.
  - `plain` (the default) — a plain appended file, never rotated by Cowrie.
  - `rotating` — `CowrieDailyLogFile`, daily. The suffix comes from
    `CowrieDailyLogFile.suffix()`, which formats a `(year, month, day)` tuple as
    `f"{y:02d}-{m:02d}-{d:02d}"`, so rotated files are **`cowrie.json.YYYY-MM-DD`**.
  - **Cowrie never gzips.** Any `.gz` you see came from an external `logrotate`.
    The loader must handle both naming schemes and both compressed and plain.

---

## 3. Shared attributes (on every event)

From `docs/OUTPUT.rst` plus `jsonlog.py`:

| Field | Type | Notes |
|---|---|---|
| `eventid` | string | e.g. `cowrie.session.connect`. Always present. |
| `message` | string | Human readable. Some events carry none (`cowrie.session.params`). |
| `sensor` | string | `[honeypot] sensor_name`, defaults to the hostname. |
| `timestamp` | string | ISO 8601, UTC. **See the format trap below.** |
| `session` | string | Session id. See §5. |
| `src_ip` | string | Attacker IP. |

Events emitted from a live connection **also** carry:

| Field | Type | Notes |
|---|---|---|
| `protocol` | string | `ssh` or `telnet`. |
| `src_port` | integer | Attacker source port. |
| `dst_ip` | string | Honeypot address. |
| `dst_port` | integer | Honeypot port (2222 in a normal deployment). |

And two more that matter a great deal to a loader:

| Field | Type | Notes |
|---|---|---|
| `late` | boolean | Present and `true` when the event was dispatched **after its connection closed** — e.g. a download that finished after the attacker disconnected. |
| `epoch` | integer | **Only if** `[output_jsonlog] epoch_timestamp = true`. Computed as `int(event["time"] * 1000000 / 1000)`, i.e. **milliseconds**, not seconds. Off by default. |

### Keys that do NOT reach the file

`jsonlog.py` deletes, for every event, any key starting with `log_`, plus `time`
and `system`:

```python
for i in list(event):
    if i.startswith("log_") or i == "time" or i == "system":
        del event[i]
```

This matters because `core/output.py` documents that "the time is available in two
formats in each event, as key `time` in epoch format and in key `timestamp` as a
ISO compliant string." That is true of the event dict handed to output plugins —
but **`time` is stripped before the JSON line is written.** So in `cowrie.json`
there is exactly one timestamp (`timestamp`), unless `epoch_timestamp` is on.

**Design consequence:** our parser must treat `timestamp` as the only reliable
time source and must parse it itself. It cannot fall back to a numeric epoch.

### The timestamp format trap

`core/output.py` picks the format from the environment:

```python
if "TZ" in environ and environ["TZ"] == "UTC":
    self.timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
else:
    self.timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"
```

So the same Cowrie produces **either** `2026-11-06T14:22:31.123456Z` **or**
`2026-11-06T14:22:31.123456+0000`, depending on whether `TZ=UTC` is exported for
the process. Note that `%z` emits `+0000` with **no colon**, which
`datetime.fromisoformat()` accepts on Python 3.11+ but which older code and many
other tools reject.

**Design consequence:** the parser must accept both, normalize to one canonical
representation, and never assume a trailing `Z`. This is tested in Phase 4.

---

## 4. Events ShadowPot handles

Required fields are marked **R**; optional/conditional ones **O**. "Optional"
here means *the field is genuinely absent from the JSON in some real cases* —
not that we tolerate its absence out of politeness.

### `cowrie.session.connect` — R
The first event of every session.

| Field | | Notes |
|---|---|---|
| `src_ip` | R | Attacker address. |
| `src_port` | R | Attacker port. |
| `dst_ip` | R | Honeypot address. |
| `dst_port` | R | Honeypot port. |

Note: behind a PROXY-protocol proxy, Cowrie **delays** this event so it carries
the real client IP rather than the proxy's. Ordering is still "first event of the
session" from the log's point of view.

### `cowrie.client.version` — R
| Field | | Notes |
|---|---|---|
| `version` | R | The client identification string. **The field is `version`, not `client_version`.** |

### `cowrie.client.kex` — R
The client's key-exchange proposal and the derived HASSH fingerprint.

| Field | | Notes |
|---|---|---|
| `hassh` | R | HASSH fingerprint (an MD5 hex digest). |
| `hasshAlgorithms` | R | The algorithm string the fingerprint is built from. |
| `kexAlgs` | R | Key exchange algorithms offered. |
| `keyAlgs` | R | Host key algorithms offered. |
| `encCS` | R | Encryption algorithms, client→server. |
| `macCS` | R | MAC algorithms, client→server. |
| `compCS` | R | Compression algorithms, client→server. |
| `langCS` | R | Languages, client→server. |

The `*Algs`/`*CS` fields are **lists**, not strings. Note the camelCase: these
names come straight off the SSH wire protocol, so they do not follow the
snake_case convention of the rest of the event.

### `cowrie.login.failed` / `cowrie.login.success` — R
| Field | | Notes |
|---|---|---|
| `username` | R | |
| `password` | **O** | Present for password and keyboard-interactive attempts. **Absent for public-key attempts.** |
| `fingerprint` | O | Public-key attempts only. |
| `key` | O | Public-key attempts only, OpenSSH format. |
| `type` | O | Public-key attempts only, e.g. `ssh-rsa`. |

**This is the most important correction to the project brief.** The brief assumed
`(username, password)` is always available. It is not: a key-based attempt has a
username and no password at all. A `credentials(username, password)` table with
`UNIQUE(username, password)` will therefore receive NULL passwords — and in both
SQLite and MySQL, **NULLs are treated as distinct in a UNIQUE constraint**, so
every key-based attempt would insert a *new* credential row and the uniqueness
guarantee would silently fail. Phase 2 has to solve this deliberately (an
`auth_method` discriminator plus a non-NULL sentinel is the likely answer) rather
than discover it in production.

### `cowrie.command.input` — R
| Field | | Notes |
|---|---|---|
| `input` | R | The command line. **The field is `input`, not `command`.** |
| `realm` | O | Present only when the line was fed to a running command's *stdin*; absent for ordinary shell command lines. |

**There is no sequence number.** Nothing in the event says "this was the 3rd
command of the session." Command order must be derived by the loader from arrival
order within the file. That is a real design constraint, and it is why the
`commands.seq` column is something ShadowPot computes rather than reads.

### `cowrie.command.failed` — R
| Field | | Notes |
|---|---|---|
| `input` | R | The command line the emulated shell does not implement. |

Together, `command.input` and `command.failed` give us the `success` flag that
Cowrie's own `input` table carries as a column.

### `cowrie.session.file_download` — R
| Field | | Notes |
|---|---|---|
| `url` | **O** | **Absent** for stdin captures and shell-redirect captures. Only present for an actual fetch (`wget`, `curl`, `tftp`, `ftpget`). |
| `outfile` | R | Where Cowrie stored it, named after its checksum. |
| `shasum` | R | **SHA-256** of the file. Despite the name "shasum", it is SHA-256, confirmed by `OUTPUT.rst`. |
| `destfile` | O | The path the attacker wrote to, where applicable. |
| `duplicate` | O | Whether this file has been seen before. |

**Second correction to the brief:** the brief has `downloads(url NOT NULL)`. `url`
must be nullable, because a file can enter the honeypot with no URL at all.

### `cowrie.session.file_upload` — R
| Field | | Notes |
|---|---|---|
| `filename` | R | Name of the uploaded file. |
| `outfile` | R | Storage path, named after checksum. |
| `shasum` | R | SHA-256. |
| `destfile` | O | SCP only. |
| `duplicate` | O | SCP only. |

Note there is **no `url`** here, and the "name" field is `filename`, not
`destfile`. Download and upload are near-identical in shape but differ in exactly
two fields — the argument for one `file_transfers` table with a `direction`
discriminator rather than two tables and a `UNION` in every query.

### `cowrie.session.closed` — R
| Field | | Notes |
|---|---|---|
| `duration_ms` | R | **Integer milliseconds.** |

**Third and largest correction to the brief.** The brief specifies
`duration_s` / a `duration` field. That field **no longer exists**.
`CHANGELOG.rst` records it as a breaking change in **release 3.0.4 (2026-06-22)**:

> **Event field rename**: `cowrie.session.closed` and `cowrie.log.closed` report
> `duration_ms` as an integer number of milliseconds. The `duration` field is
> gone. It was a string for some transports and a float for others.

Confirmed at the source in both transports:

```python
duration_ms = round((time.time() - self.startTime) * 1000)
```

**Design consequence:** the parser must read `duration_ms` and must *also* accept
a legacy `duration` field for logs from Cowrie < 3.0.4, where it may arrive as
**either a string or a float**. ShadowPot stores a single canonical
`duration_ms INTEGER` and converts on the way in.

---

## 5. Session identifiers

Both transports generate the id the same way:

```python
self.transportId = uuid.uuid4().hex[:12]
```

So a session id is **12 lowercase hexadecimal characters**, for SSH and Telnet alike.

Three consequences worth stating plainly:

1. **Cowrie's own schema is stale.** `docs/sql/mysql.sql` declares
   `session char(32)`. That file's copyright header reads 2010-2019 and the
   current code produces 12 characters. A `CHECK(length(session_id) = 12)`
   constraint would therefore be correct today and wrong against archived logs
   from an older Cowrie, which used a different width and uppercase hex.
   ShadowPot validates loosely (hex, 8-64 chars) and records why.
2. **48 bits of entropy.** 12 hex chars is 2^48. Collisions are unlikely but not
   impossible: at 100,000 sessions the birthday probability is roughly 2 in
   100,000. Not zero.
3. **Session ids are generated per process, so they are not globally unique
   across sensors.** Two honeypots can mint the same id independently. Any schema
   intending to merge several sensors must key on `(sensor, session)`, not
   `session` alone. ShadowPot is single-sensor by default; Phase 2 records this
   assumption explicitly instead of leaving it as a latent bug.

---

## 6. Events ShadowPot deliberately ignores

Unknown and unhandled events must be **counted and skipped, never fatal**. These
exist in the wild and we do not model them:

- `cowrie.client.fingerprint`, `cowrie.client.size`, `cowrie.client.var`,
  `cowrie.client.kex_unexpected`, `cowrie.client.malformed_packet`
- `cowrie.command.chpasswd`, `cowrie.command.success` (legacy)
- `cowrie.session.input`, `cowrie.session.params`,
  `cowrie.session.file_download.failed`
- `cowrie.log.open`, `cowrie.log.closed`
- all `cowrie.direct-tcpip.*`, `cowrie.tunnelproxy-tcpip.*`, `cowrie.proxy.*`,
  `cowrie.telnet.*`
- enrichment plugins that write their own events into the same stream:
  `cowrie.virustotal.*`, `cowrie.urlhaus.*`, `cowrie.malwarebazaar.*`,
  `cowrie.reversedns.*`, `cowrie.greynoise.*`, `cowrie.abuseipdb.*`

Two parsing traps in that list:

- **`cowrie.session.file_download.failed` has four dotted components**, not three.
  Dispatching on `eventid.split(".")[1:3]` would misroute it onto
  `session.file_download`. Dispatch on the **whole** `eventid` string, by exact
  match.
- **`cowrie.abuseipdb.*` events carry no `session`**, and per `OUTPUT.rst` appear
  only in `cowrie.log`, not in the output plugins. Code that assumes every line
  has a `session` key will raise on them if they ever do appear.

---

## 7. Ordering guarantees (and the lack of them)

1. `cowrie.session.connect` is the first event of a session. We may create the
   session row from it.
2. `cowrie.session.closed` is **not** guaranteed to be the last event for a
   session. An event carrying `late: true` is dispatched after the connection
   closed and therefore appears *after* `session.closed` in the file. A loader
   that treats `session.closed` as a terminator and discards later rows for that
   session will lose exactly the most interesting records — completed malware
   downloads.
3. With daily rotation, a session that spans midnight has its `connect` in one
   file and its `closed` in the next. **An event can legitimately arrive for a
   session whose `connect` we have never seen**, because that file was rotated
   away or deleted before we ever ingested it. The schema must therefore either
   tolerate an orphan event or synthesize a placeholder session row. Phase 2
   decides and documents which; it is not an error case to crash on.

---

## 8. Illustrative lines

> **These examples are constructed by hand from the field tables above to show
> shape only. They are NOT captured output and contain no real attacker data.**
> Real synthetic fixtures arrive in Phase 3 and carry `"synthetic": true`.
> Reformatted with newlines for reading; real lines are single-line and compact.

```json
{"eventid":"cowrie.session.connect","timestamp":"2026-11-06T14:22:31.123456Z",
 "session":"a1b2c3d4e5f6","src_ip":"198.51.100.7","src_port":54321,
 "dst_ip":"203.0.113.10","dst_port":2222,"protocol":"ssh",
 "message":"New connection: 198.51.100.7:54321","sensor":"honeypot-1"}
```

```json
{"eventid":"cowrie.login.failed","timestamp":"2026-11-06T14:22:31.998001Z",
 "session":"a1b2c3d4e5f6","src_ip":"198.51.100.7","username":"root",
 "password":"123456","message":"login attempt [root/123456] failed",
 "sensor":"honeypot-1","protocol":"ssh","src_port":54321,
 "dst_ip":"203.0.113.10","dst_port":2222}
```

A key-based attempt, showing the **absent** `password`:

```json
{"eventid":"cowrie.login.failed","timestamp":"2026-11-06T14:22:32.100000Z",
 "session":"a1b2c3d4e5f6","src_ip":"198.51.100.7","username":"root",
 "fingerprint":"aa:bb:cc:dd:ee:ff","type":"ssh-rsa","key":"AAAAB3NzaC1yc2E...",
 "message":"public key attempt","sensor":"honeypot-1"}
```

---

## 9. Requirements this imposes on the loader (Phase 4 checklist)

Each line below is a test case in Phase 4.

1. Parse `timestamp` in **both** `...Z` and `...+0000` forms.
2. Never read `time`; it is stripped from the file. Tolerate `epoch` if present
   and treat it as **milliseconds**.
3. Dispatch on the **exact** `eventid` string, never on a split prefix.
4. Treat `password` as nullable, and make `credentials` uniqueness work anyway.
5. Treat `url` on `file_download` as nullable.
6. Read `duration_ms` as an integer; accept legacy `duration` as str **or** float.
7. Do not require `session` to exist on every line.
8. Do not treat `session.closed` as a session terminator; accept `late: true`
   events after it.
9. Accept events for sessions whose `connect` was never ingested.
10. Count, log and skip: malformed JSON, a truncated last line, unknown `eventid`,
    and events missing a field we require.
11. Handle `cowrie.json`, `cowrie.json.YYYY-MM-DD`, and externally gzipped
    `*.gz`.
12. Treat `*Algs` / `*CS` kex fields as lists, not strings.

---

## 10. Interview answers this section supports

- *"How did you know the log format was right?"* — Read `docs/OUTPUT.rst` and
  `output/jsonlog.py` at a pinned commit, not the rendered docs, which were
  three releases stale and self-contradictory.
- *"What breaks when the upstream format changes?"* — `duration` → `duration_ms`
  in 3.0.4 is the worked example. Named in `CHANGELOG.rst` as breaking;
  ShadowPot accepts both and normalizes to milliseconds.
- *"What is the hardest thing about parsing these logs?"* — Not the JSON. It is
  that the log is a stream of partial facts about sessions, with no sequence
  numbers, no guaranteed terminator, and rotation boundaries that cut sessions in
  half.

# Interview notes

Two parts. **[Design decisions](#part-1-design-decisions)** records what was
chosen, what the alternatives were, and why — including the places where the
first choice was wrong and a test caught it. **[The fifteen hardest
questions](#part-2-the-fifteen-hardest-questions)** are the ones this project
invites, with answers short enough to actually say out loud.

One rule runs through all of it: **the honest answer is stronger than the
clean one.** "I predicted that index was redundant and the measurement proved
me wrong" is a better answer than a tidy story, because it shows the
measurement happened. Several answers below are of that shape on purpose.

---

## Part 1: Design decisions

### 1. SQLite is canonical, MySQL is a port

**Alternatives:** MySQL only (it is what most places run); PostgreSQL;
SQLAlchemy over both.

**Chosen because** SQLite needs no server and ships in Python's standard
library, so anyone can clone the repository and run the entire pipeline with
no setup. That is what makes "reproduce every number" a real claim rather than
an aspiration. MySQL exists as a second dialect because that is what a job
will actually use.

**Cost:** two schema files to keep in step, and five query files duplicated
where the date functions differ. Mitigated by tests asserting both dialects
declare the same tables, views and questions.

### 2. `login_attempts` uses an exclusive arc, not one credentials FK

**Alternatives:** one `credentials(username, password)` with a nullable
password; a sentinel `''` for "no password offered"; two parallel fact tables.

**Chosen because** the nullable version fails *silently*. Cowrie omits
`password` entirely for public-key attempts, and SQL treats NULLs as distinct
inside a UNIQUE constraint — measured: three `INSERT OR IGNORE` of
`('root', NULL)` give three rows. The sentinel was rejected because `''` is
itself one of the most-attempted passwords, so it cannot also mean "absent".
The arc keeps both dimension tables fully `NOT NULL`, so their UNIQUE
constraints work, and `CHECK ((cred_id IS NULL) <> (keycred_id IS NULL))`
makes the database enforce the invariant rather than the loader.

**Cost:** queries need a double `LEFT JOIN`, hidden behind
`v_login_attempts`.

### 3. `hassh_algorithms` lives in its own table; `keyAlgs` does not

**Alternatives:** all eight key-exchange fields on `sessions`; all eight in
one `clients(version, hassh)` table.

**Chosen because** HASSH *is* the MD5 of `hassh_algorithms`, so
`hassh → hassh_algorithms` is a true functional dependency and leaving both on
`sessions` is a 3NF violation. Putting them in a table keyed `(version, hassh)`
would have been worse — a **2NF** violation, since `hassh_algorithms` depends
on only part of that key.

**The trap:** `keyAlgs` and `langCS` are *not* inputs to the digest, so `hassh`
does not determine them, and they stay on `sessions`. All eight fields arrive
in one event and look like one unit. A generator test asserts that one `hassh`
appears with differing `keyAlgs`, so the fixture keeps exercising the
non-dependency.

### 4. `ssh_keys` and `artifacts` split out for the same reason

A fingerprint is a hash of a key, so `fingerprint → key_type, key_blob`.
Cowrie names a captured file after its checksum, so `sha256 → outfile`. Both
are transitive dependencies and both decompose. Practical payoff: a
multi-kilobyte `key_blob` is stored once instead of once per username tried,
and one malware sample fetched by 300 addresses is one `artifacts` row.

### 5. Derived values are not stored

**Alternatives:** `sources(first_seen, last_seen)` and `commands.seq` as
columns, as the original plan had them.

**Chosen because** both are aggregates over other tables. Storing them means
two copies of one truth and a loader that must keep them agreeing forever, on
every code path, with no constraint able to notice drift. `v_source_activity`
and `v_session_commands` compute them instead, the latter with
`ROW_NUMBER() OVER (PARTITION BY session_pk ORDER BY ts, command_id)`.

**Unresolved, honestly:** "most common first command" is an index seek against
a stored `seq` and a windowed scan against the view. If a measurement at real
scale shows it matters, `seq` gets materialized **and the measurement goes in
`INDEXES.md`**. Denormalizing on evidence is engineering; denormalizing on a
hunch is how schemas rot.

### 6. One `file_transfers` table with a `direction` discriminator

Download and upload events are the same shape and differ in two fields. Two
tables would force a `UNION` into every "what files moved" query for no
modelling benefit. `url` is nullable because Cowrie fires `file_download` for
stdin and shell-redirect captures, which have no URL at all.

### 7. The session natural key is `(sensor_id, cowrie_session_id)`

Cowrie generates session ids as `uuid.uuid4().hex[:12]`, **per process**, so
they are unique within one sensor and not globally. Two honeypots can mint the
same id independently. A surrogate integer PK keeps the fact tables' foreign
keys narrow.

### 8. Timestamps are canonical UTC text, enforced by CHECK

**Alternatives:** integer epoch; SQLite's own `datetime` text without
constraint.

**Chosen because** SQLite has no date type, and ISO-8601 in one fixed form
sorts lexicographically in chronological order, so `ORDER BY ts` is correct
with no conversion. The CHECK is the load-bearing part: Cowrie emits `...+0000`
whenever `TZ` is not UTC, and SQLite's date functions return **NULL** for that
form while storing it happily. Measured: `GROUP BY date(ts)` over such data
returns one row with a NULL date and every record collapsed into it — a
plausible-looking wrong answer, which is the kind most likely to get
published. The constraint turns it into an insert failure.

### 9. `STRICT` tables, with an accurate claim about what they buy

Originally written up as "stops a string going into an integer column". A test
disproved that: `STRICT` is *lossless-conversion-or-error*, so `'2222'` is
accepted and stored as the integer 2222. What it does reject is `'22.5'`,
`''`, `'abc'` and `2222.5`. Still worth having as a backstop; the comment now
says what it actually does.

### 10. Two independent idempotence mechanisms

UNIQUE natural keys make `INSERT OR IGNORE` a no-op, *and* every applied
line's SHA-256 goes into `ingested_lines`. The natural keys rest on an
assumption — no two events in one session share a microsecond — and the ledger
does not. A test empties the ledger and asserts the natural keys still prevent
every duplicate; another bypasses offsets with `--force-rescan` and asserts the
ledger absorbs all 9,253 lines.

**Cost:** one ledger row per log line, roughly 100 bytes, never pruned. Listed
under future work.

### 11. `ingest_state` stores a first-line fingerprint

The standard trio of inode, size and offset handles rotation and truncation
and **misses** a file truncated in place and rewritten to the same length. A
test built exactly that and failed. Hashing the first line costs one short
read, never changes under append, and always changes under rewrite. The
residual hole — a rewrite whose first line is byte-identical — is documented,
not hidden.

### 12. The stored offset is the end of the last *complete* line

A partial trailing line, from the honeypot being killed mid-write, is counted
as malformed for that run and **not consumed**. Recording an offset past it
would permanently skip the rest of that line once written. Rows and the resume
point commit in one transaction, so a crash replays a batch — which the ledger
makes a no-op — rather than losing it.

### 13. The parser is pure

No database, no filesystem, no clock. Every edge case in `LOG_FORMAT.md` is a
one-line assertion instead of a fixture plus a database, and the parser is the
single place where "whatever Cowrie emitted" becomes "what ShadowPot stores",
so an upstream field rename is a one-line change.

### 14. The SQL lives in `.sql` files

**Alternatives:** strings in Python; an ORM; a query builder.

**Chosen because** the SQL *is* the project. It can be run by hand with the
`sqlite3` CLI while being written, it diffs readably, and each file carries a
parsed header stating the question it answers — a test asserts every one does,
because a query whose purpose is not written down cannot be reviewed. No query
contains a `LIMIT`: they order, and the caller takes what it wants, since a
bound `LIMIT` needs different placeholder syntax per dialect.

### 15. Indexes are measured, and live in a separate file

`schema/` ships no index beyond those implied by PRIMARY KEY and UNIQUE, which
is what lets `tools/bench_indexes.py` measure from an honestly unindexed
baseline. Each candidate is created **alone** — creating them together shows
which one the planner picked but not what any is worth. Four of seven earned a
place; the three rejected are listed in the index file with their reasons so
the omission looks deliberate.

The file quotes **no speedup figures**, on purpose: `make bench` regenerates
`INDEXES.md`, and a number copied into a second place drifts away from the
measurement that produced it.

### 16. Synthetic data is labelled in code, not just in prose

Every generated line carries `"synthetic": true`; the flag is sticky per
session; the report banners on it and declares a *mixed* database unusable as
evidence. Addresses come only from RFC 5737 and RFC 3849 reserved ranges and
URLs only from the reserved `.invalid` TLD, both asserted by tests that
re-declare the ranges rather than importing them. The reason is not tidiness:
a synthetic log containing a plausible address invites someone to block,
report or retaliate against an innocent third party.

### 17. Logs are pulled, never pushed

The private key lives on the analysis machine; the honeypot holds only a
public key restricted to a read-only `rrsync` command. The honeypot is the
machine most likely to be compromised, so it must hold no credential that
leads anywhere. A push model would hand an attacker the laptop.

### 18. `unittest`, and no third-party dependencies

pytest is nicer to write. The standard library means `make test` works on a
clean clone with no `pip install`, which matters more for a project whose
central claim is reproducibility. matplotlib is optional for the same reason:
the default report is tables and ASCII bars.

---

## Part 2: The fifteen hardest questions

### 1. Why is `credentials` its own table? What anomaly does that remove?

The usual answer — "it removes an update anomaly" — is weak here, and saying
so is the better answer. You never *rename* a credential; 50,000 attempts at
`root/123456` are 50,000 distinct facts, not one fact stored 50,000 times.

The real reasons, in order: **it is what makes idempotent ingestion possible**,
because `UNIQUE(username, password)` plus `INSERT OR IGNORE` is where the
deduplication lives and there is nowhere else to put that constraint; storage
grows with distinct pairs rather than attempts; and a credential gets a stable
integer identity, so "tried from more than 20 addresses" becomes a
`GROUP BY cred_id HAVING COUNT(DISTINCT source_id) > 20` over integers instead
of a group-by over millions of string pairs.

There *is* one genuine update anomaly, and it is specific to log processing:
**repair**. If the parser is found to have mangled an encoding, the fix touches
one row per distinct pair instead of one per attempt.

### 2. Your `credentials` table has `UNIQUE(username, password)` and the password is nullable. What happens?

Nothing — which is the problem. SQL treats NULLs as **distinct** inside a
UNIQUE constraint, so the constraint does not deduplicate NULL-password rows
at all. Cowrie omits `password` entirely for public-key attempts, so every
re-ingest would multiply those credentials and inflate the top-credentials
table by exactly the traffic that has no password.

Measured on SQLite 3.50.4: three `INSERT OR IGNORE` of `('root', NULL)` yields
three rows. The fix is an exclusive arc — two `NOT NULL` dimension tables and
a `CHECK` that exactly one is referenced. A sentinel `''` does not work,
because the empty password is real, common data.

### 3. Is your schema in third normal form? Is it in first?

3NF yes. **1NF no, in one specific place**: the key-exchange algorithm lists
are stored as delimited strings, which is a repeating group in a single
attribute. That is a deliberate compromise — no analytic filters by an
individual algorithm, and `hassh`'s meaning is the identity of the joined
string, not its parts. The remedy if that changes is a
`session_algorithms(session_pk, category, position, algorithm)` child table,
and nothing is lost by waiting because the full string is retained.

Being able to name your own violation, justify it, and state the exact fix is
worth more than claiming full compliance.

### 4. How do you make ingestion idempotent and resumable? Now give me a case your design gets wrong.

Idempotent two ways: UNIQUE natural keys over `NOT NULL` columns with
`INSERT OR IGNORE`, and a SHA-256 ledger of every applied line. Resumable by
storing inode, size, byte offset and a hash of the file's first line, which
distinguishes five conditions: rotation (inode changed), in-place rewrite
(first line changed), truncation (size below offset), nothing new (size equals
offset), and normal growth.

**The case it gets wrong:** a file truncated and rewritten in place whose new
first line is byte-identical to the old one. The fingerprint matches, so the
loader resumes at a stale offset and silently skips the replacement content.
Catching it needs a hash of everything already consumed, which costs a full
re-read every run. For Cowrie an identical first line means the same session
at the same microsecond, so the risk is accepted and written down.

The offset also points at the end of the last **complete** line, so a partial
trailing line is re-read rather than skipped once finished.

### 5. What does a honeypot catch that an IDS does not?

**Intent and interaction, rather than signatures and volume.** An IDS watching
real traffic tells you a connection matched a pattern. A honeypot has no
legitimate traffic at all, so **every single event is hostile by definition** —
there are no false positives to tune away, which is the single biggest
operational difference.

Concretely, this dataset contains things an IDS does not give you: the exact
credentials being guessed, in order of popularity; what an attacker types
*after* authenticating; which payload URL they fetch; and the fact that one
credential pair arrives from 196 unrelated addresses, which is a shared
wordlist and therefore a botnet.

The trade is coverage: a honeypot sees only what comes to it, so it tells you
about internet-wide automated behaviour and nothing about attacks on your real
services.

### 6. Why is a low-interaction honeypot safer than a real vulnerable machine, and how can an attacker tell?

Cowrie emulates a shell in Python. There is no real shell, no real filesystem
and no real execution, so `rm -rf /` destroys a fake tree and `./malware` runs
nothing. A deliberately vulnerable real machine, by contrast, genuinely
executes whatever it is given and becomes a platform for attacking others.

**How it is detected:** the emulation is incomplete, and this project measures
exactly that — `cowrie.command.failed` events *are* the commands the fake shell
does not implement, and in the sample data the top three are `/ip cloud print`,
`enable` and `system`, all BusyBox and router-firmware probes. Beyond that:
timing, since a fake `wget` returns impossibly fast; inconsistencies between
the SSH banner and the emulated OS; and a filesystem that does not change in
the ways a real one would.

That is fine, because the traffic worth measuring is automated and does not
check. A human who probes for 30 seconds will work it out.

### 7. What are the actual risks of running one?

Four, in order of likelihood, and only the last is about the honeypot:

1. **Your own host.** Leaving the real `sshd` on port 22 with password auth on
   a box advertising itself as an SSH target. This is the real danger, which is
   why the runbook relocates `sshd` *before* installing Cowrie.
2. **Being used against someone else.** Cowrie **really fetches**
   attacker-supplied URLs, because that is how it captures samples, so the box
   makes outbound requests to attacker-chosen addresses. The egress policy
   allows 80 and 443 and blocks 22, 23, 25, 445 and 3389, so the box cannot
   brute force, spam or spread.
3. **Your provider.** Expect an abuse notice. Read the acceptable-use policy
   first; some providers forbid honeypots outright.
4. **The honeypot itself.** A flaw in Cowrie or the kernel. Mitigated by
   putting nothing of value on the box and planning to destroy it.

### 8. Why did you index those columns and not others? How do you know?

Because they were measured, one at a time, from an unindexed baseline on a
database of 11,318 sessions and 95,086 login attempts. Four of seven
candidates changed a query plan from a scan to a search; three were used by no
plan and are not shipped. The rejected ones are listed in the index file with
their reasons.

**The interesting part is that the measurement contradicted my prediction.** I
expected `login_attempts(session_pk)` to be redundant, because
`UNIQUE(session_pk, ts)` already indexes that column as its leading key. It
turned out to be used by more queries than any other candidate. The reason is
width, not correctness: the single-column index stores one integer per row
where the UNIQUE index stores an integer plus a 27-character timestamp, so it
fits far more rows per page. *"A prefix of an existing index covers it"* is a
statement about correctness, not about cost.

Scale is part of the answer too: at the default 600-session sample none of
this is measurable, because SQLite reads those tables in under a millisecond.

### 9. Walk me through what happens to one log line.

1. `discover()` orders the files oldest-first, with the un-suffixed current
   file last, so a session's `connect` is normally seen before its later
   events.
2. `decide_action()` compares stored inode, size, offset and first-line hash
   to decide whether to skip, resume, or re-read the file.
3. `iter_complete_lines()` yields only newline-terminated lines and tracks the
   offset just past each one.
4. The line's SHA-256 is checked against `ingested_lines`; a hit counts as a
   duplicate and stops there.
5. `parse_line()` classifies it as event, malformed, unknown, or incomplete —
   dispatching on the **whole** `eventid` by exact match, because
   `cowrie.session.file_download.failed` has four dotted components and a
   prefix match would invent a completed download out of a failure.
6. The timestamp is normalized to canonical UTC and the IP through Python's
   `ipaddress` module.
7. The loader gets-or-creates the dimension rows, upserts the session, and
   inserts the fact row with `INSERT OR IGNORE`.
8. The ledger row and the resume offset commit in the same transaction as the
   data.

### 10. Your report says 152 logins succeeded. Were you compromised?

No. A honeypot accepts whatever its configuration tells it to accept — in this
deployment, exactly one staged credential, `root` / `123456`. What the number
measures is **which staged credential the attackers found**, not that anything
got in. There is nothing to compromise: the shell is emulated.

The report says this in its own words, and a test asserts the words *breach*,
*compromised*, *owned* and *pwned* never appear in the narrative. It would be
the single most misleading sentence this tool could produce.

### 11. How do you know your bot-versus-human classifier works?

I know the SQL implements the stated rule. I do **not** know the thresholds are
right, and the query says so.

The rule is two signals: a mean inter-command gap under 250 ms, and a command
sequence that repeats across sessions. On the synthetic data the populations
separate cleanly — 19–83 ms against 5.2–10.7 s — but the generator was written
to produce that separation, so it cannot disconfirm the threshold. Validating
250 ms needs a real capture.

That gap was also where the heuristic was caught being useless: it initially
flagged sessions with 8.4-second gaps as scripted, because the generator reused
only two interactive scripts, so the sequence-reuse signal fired on
everything. Fixing the fixture was the only way to make the heuristic
testable.

### 12. Two honeypots. You merge their databases. What breaks?

The obvious thing is handled: session ids are per-process, so
`UNIQUE(sensor_id, cowrie_session_id)` already expects collisions across
sensors.

The subtle thing is not. `artifacts.outfile` depends on the deployment's
`download_path` setting, so the functional dependency `sha256 → outfile` holds
*within* one sensor and quietly stops holding across two configured
differently. The schema records single-sensor as a scope assumption rather than
leaving it to be discovered.

### 13. You store timestamps as text. Defend that.

In SQLite there is no alternative type — its date functions operate on text or
numbers — and ISO-8601 in one fixed form sorts lexicographically in
chronological order, so ordering and range scans are correct with no
conversion. In MySQL, where there *is* a real type, the schema uses
`DATETIME(6)`: 8 bytes instead of 27.

The part worth defending is the `CHECK` constraint. Cowrie's timestamp format
depends on the process's `TZ`, so the same honeypot emits either `...Z` or a
numeric offset, and SQLite's date functions return NULL for the no-colon
offset form while accepting it as a string. Without the constraint, a
mis-canonicalized load produces one NULL bucket holding every row rather than
an error. The constraint makes it fail at insert time.

### 14. Why raw SQL and no ORM?

Because the SQL is the deliverable. An ORM would hide the normalization
decisions, the window functions and the index measurements — which is most of
what this project is for. It would also make the two-dialect story harder, not
easier, since the places the dialects genuinely differ are date functions and
collation, neither of which an ORM saves you from thinking about.

For an application with a large evolving domain model I would want one. For
twelve tables and eighteen analytical queries, it is overhead that obscures
the work.

### 15. What is the weakest part of this project?

**That it has no real data.** Every number is throughput on generated logs.
The whole analytical layer is unexercised against real attacker behaviour, and
real data always breaks assumptions — I would expect the first real load to
turn up event shapes the parser classifies as incomplete, and credentials
containing bytes that make the report's escaping earn its place.

After that, in order: the MySQL path has never run against a live server; the
bot heuristic's thresholds are unvalidated; and the `ingested_lines` ledger
grows without bound, which is fine for a week and wrong for a year.

What I would do next, in order: deploy it for seven days; load the real logs
and see what breaks; then revisit the `commands.seq` decision with a
measurement at real scale instead of a guess.

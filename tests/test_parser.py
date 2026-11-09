"""Tests for shadowpot.parser.

The parser is pure, so every edge case in docs/LOG_FORMAT.md section 9 is a
one-line assertion here instead of a fixture file plus a database. That is the
whole reason the module has no I/O in it.
"""

from __future__ import annotations

import json
import unittest

from shadowpot.parser import (
    FieldError, Status, canonical_ip, canonical_timestamp, parse_line,
)

TS = "2026-11-06T14:22:31.123456Z"


def line(**fields) -> str:
    base = {
        "timestamp": TS,
        "session": "a1b2c3d4e5f6",
        "src_ip": "198.51.100.7",
        "sensor": "honeypot-1",
    }
    base.update(fields)
    return json.dumps(base)


class TestCanonicalTimestamp(unittest.TestCase):
    def test_z_form_passes_through(self):
        self.assertEqual(canonical_timestamp(TS), TS)

    def test_no_colon_offset_is_converted(self):
        """Cowrie emits this whenever TZ is not UTC, and SQLite's date()
        returns NULL for it while storing it happily as text."""
        self.assertEqual(
            canonical_timestamp("2026-11-06T14:22:31.123456+0000"), TS
        )

    def test_colon_offset_is_converted(self):
        self.assertEqual(
            canonical_timestamp("2026-11-06T14:22:31.123456+00:00"), TS
        )

    def test_non_utc_offsets_are_shifted_not_truncated(self):
        """`%z` renders the LOCAL offset, so a honeypot in Asia/Kolkata emits
        +0530. Dropping the offset instead of applying it would shift every
        event by hours and put sessions on the wrong day."""
        self.assertEqual(
            canonical_timestamp("2026-11-06T19:52:31.123456+0530"), TS
        )
        self.assertEqual(
            canonical_timestamp("2026-11-06T09:22:31.123456-0500"), TS
        )

    def test_naive_timestamp_is_assumed_utc(self):
        self.assertEqual(
            canonical_timestamp("2026-11-06T14:22:31.123456"), TS
        )

    def test_microseconds_are_padded_to_six_digits(self):
        """The schema's CHECK requires exactly six fractional digits, so a
        shorter fraction has to be padded rather than passed through."""
        self.assertEqual(
            canonical_timestamp("2026-11-06T14:22:31.5Z"),
            "2026-11-06T14:22:31.500000Z",
        )
        self.assertEqual(
            canonical_timestamp("2026-11-06T14:22:31Z"),
            "2026-11-06T14:22:31.000000Z",
        )

    def test_garbage_raises(self):
        for bad in ("not a timestamp", "", "2026-13-45T99:99:99Z", 1762435351):
            with self.subTest(bad=bad), self.assertRaises(FieldError):
                canonical_timestamp(bad)


class TestCanonicalIp(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(canonical_ip("198.51.100.7"), ("198.51.100.7", 4))

    def test_ipv6_spellings_collapse(self):
        """Otherwise ::1 and 0:0:0:0:0:0:0:1 become two rows in `sources` for
        one host, and every per-IP count is wrong."""
        forms = ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001",
                 "2001:DB8::1")
        self.assertEqual({canonical_ip(f)[0] for f in forms}, {"2001:db8::1"})
        self.assertEqual(canonical_ip(forms[0])[1], 6)

    def test_surrounding_whitespace_tolerated(self):
        self.assertEqual(canonical_ip("  198.51.100.7 ")[0], "198.51.100.7")

    def test_garbage_raises(self):
        for bad in ("not an ip", "999.1.1.1", "", None):
            with self.subTest(bad=bad), self.assertRaises(FieldError):
                canonical_ip(bad)


class TestMalformed(unittest.TestCase):
    def test_blank_and_whitespace(self):
        for raw in ("", "   ", "\n", "\t "):
            with self.subTest(raw=repr(raw)):
                self.assertIs(parse_line(raw).status, Status.MALFORMED)

    def test_invalid_json(self):
        result = parse_line('{"eventid": "cowrie.session.conn')
        self.assertIs(result.status, Status.MALFORMED)
        self.assertIn("invalid JSON", result.reason or "")

    def test_json_that_is_not_an_object(self):
        for raw in ("[1, 2, 3]", '"a string"', "42", "null"):
            with self.subTest(raw=raw):
                self.assertIs(parse_line(raw).status, Status.MALFORMED)

    def test_missing_eventid(self):
        self.assertIs(parse_line(line()).status, Status.MALFORMED)

    def test_eventid_of_the_wrong_type(self):
        """A parser doing eventid.startswith(...) raises AttributeError here
        rather than skipping the line."""
        result = parse_line(line(eventid=42))
        self.assertIs(result.status, Status.MALFORMED)
        self.assertIn("not a string", result.reason or "")


class TestUnknown(unittest.TestCase):
    def test_unmodelled_real_events(self):
        for eventid in ("cowrie.client.size", "cowrie.session.params",
                        "cowrie.log.closed", "cowrie.virustotal.scanfile",
                        "cowrie.direct-tcpip.request"):
            with self.subTest(eventid=eventid):
                self.assertIs(parse_line(line(eventid=eventid)).status,
                              Status.UNKNOWN)

    def test_four_component_event_id_is_not_misrouted(self):
        """The dispatch trap.

        cowrie.session.file_download.failed has FOUR dotted components. A
        parser that split on '.' and matched a prefix would route it onto
        cowrie.session.file_download and invent a completed download that
        never happened -- fabricating malware activity out of a failure.
        """
        result = parse_line(line(
            eventid="cowrie.session.file_download.failed",
            url="http://x.invalid/a", error="404",
        ))
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertIsNone(result.event)


class TestIncomplete(unittest.TestCase):
    def test_missing_session(self):
        raw = json.dumps({"eventid": "cowrie.session.closed",
                          "timestamp": TS, "src_ip": "198.51.100.7",
                          "duration_ms": 10})
        result = parse_line(raw)
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIn("session", result.reason or "")

    def test_bad_timestamp_on_an_otherwise_good_event(self):
        result = parse_line(line(eventid="cowrie.session.closed",
                                 timestamp="nope", duration_ms=1))
        self.assertIs(result.status, Status.INCOMPLETE)

    def test_missing_required_field(self):
        result = parse_line(line(eventid="cowrie.command.input"))
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIn("input", result.reason or "")

    def test_login_with_neither_password_nor_fingerprint(self):
        result = parse_line(line(eventid="cowrie.login.failed",
                                 username="root"))
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIn("fingerprint", result.reason or "")

    def test_boolean_is_not_accepted_as_a_number(self):
        """bool is a subclass of int in Python, so True would silently become
        port 1 without an explicit guard."""
        result = parse_line(line(eventid="cowrie.session.connect",
                                 src_port=True, dst_port=2222))
        self.assertIs(result.status, Status.INCOMPLETE)

    def test_lossy_float_is_rejected(self):
        result = parse_line(line(eventid="cowrie.session.closed",
                                 duration_ms=1234.5))
        self.assertIs(result.status, Status.INCOMPLETE)


class TestEventExtraction(unittest.TestCase):
    def ev(self, **fields):
        result = parse_line(line(**fields))
        self.assertIs(result.status, Status.EVENT, result.reason)
        assert result.event is not None
        return result.event

    def test_connect(self):
        event = self.ev(eventid="cowrie.session.connect", protocol="ssh",
                        src_port=54321, dst_ip="203.0.113.10", dst_port=2222)
        self.assertEqual(event.data, {"protocol": "ssh", "src_port": 54321,
                                      "dst_ip": "203.0.113.10",
                                      "dst_port": 2222})
        self.assertEqual(event.src_ip, "198.51.100.7")
        self.assertEqual(event.src_ip_version, 4)

    def test_numeric_strings_are_coerced(self):
        """Cowrie sends integers, but a hand-edited or third-party file may
        quote them, and the schema's STRICT tables reject text in an INTEGER
        column."""
        event = self.ev(eventid="cowrie.session.connect", src_port="54321")
        self.assertEqual(event.data["src_port"], 54321)

    def test_client_version_field_is_version(self):
        event = self.ev(eventid="cowrie.client.version",
                        version="SSH-2.0-libssh2_1.9.0")
        self.assertEqual(event.data["version"], "SSH-2.0-libssh2_1.9.0")

    def test_kex_splits_hassh_determined_fields_from_session_ones(self):
        """hassh determines hassh_algorithms, but NOT keyAlgs or langCS --
        those are not inputs to the digest. Keeping them apart is what makes
        kex_fingerprints correct; see docs/NORMALIZATION.md N1."""
        event = self.ev(
            eventid="cowrie.client.kex",
            hassh="0" * 32,
            hasshAlgorithms="kex;enc;mac;comp",
            kexAlgs=["curve25519-sha256", "ecdh-sha2-nistp256"],
            keyAlgs=["ssh-rsa", "ssh-ed25519"],
            encCS=["aes128-ctr"], macCS=["hmac-sha2-256"], compCS=["none"],
            langCS=[""],
        )
        self.assertEqual(event.data["hassh"], "0" * 32)
        self.assertEqual(event.data["hassh_algorithms"], "kex;enc;mac;comp")
        self.assertEqual(event.data["key_algs"], "ssh-rsa,ssh-ed25519")
        self.assertEqual(event.data["lang_cs"], "")
        # The component lists are recoverable from hassh_algorithms, so they
        # are not stored separately.
        self.assertNotIn("kex_algs", event.data)

    def test_kex_lists_must_hold_strings(self):
        result = parse_line(line(eventid="cowrie.client.kex", hassh="0" * 32,
                                 hasshAlgorithms="a;b;c;d", keyAlgs=[1, 2]))
        self.assertIs(result.status, Status.INCOMPLETE)

    def test_password_login(self):
        event = self.ev(eventid="cowrie.login.failed", username="root",
                        password="123456")
        self.assertEqual(event.data["auth_method"], "password")
        self.assertEqual(event.data["password"], "123456")
        self.assertEqual(event.data["success"], 0)

    def test_success_is_derived_from_the_event_id(self):
        event = self.ev(eventid="cowrie.login.success", username="root",
                        password="123456")
        self.assertEqual(event.data["success"], 1)

    def test_empty_password_is_real_data_not_absence(self):
        """'' is one of the most-tried passwords. Treating it as "no password"
        would both lose the attempt and make a sentinel-based credentials
        table ambiguous."""
        event = self.ev(eventid="cowrie.login.failed", username="root",
                        password="")
        self.assertEqual(event.data["auth_method"], "password")
        self.assertEqual(event.data["password"], "")

    def test_publickey_login_has_no_password_key(self):
        event = self.ev(eventid="cowrie.login.failed", username="root",
                        fingerprint="aa:bb:cc", type="ssh-rsa", key="AAAA")
        self.assertEqual(event.data["auth_method"], "publickey")
        self.assertEqual(event.data["fingerprint"], "aa:bb:cc")
        self.assertEqual(event.data["key_type"], "ssh-rsa")
        self.assertNotIn("password", event.data)

    def test_publickey_without_type_or_key_still_usable(self):
        event = self.ev(eventid="cowrie.login.failed", username="root",
                        fingerprint="aa:bb:cc")
        self.assertIsNone(event.data["key_type"])
        self.assertIsNone(event.data["key_blob"])

    def test_command_field_is_input(self):
        event = self.ev(eventid="cowrie.command.input", input="uname -a")
        self.assertEqual(event.data["input"], "uname -a")
        self.assertEqual(event.data["implemented"], 1)
        self.assertIsNone(event.data["realm"])

    def test_command_failed_means_unimplemented_not_unsuccessful(self):
        event = self.ev(eventid="cowrie.command.failed", input="enable")
        self.assertEqual(event.data["implemented"], 0)

    def test_command_realm_present_for_stdin_input(self):
        event = self.ev(eventid="cowrie.command.input", input="yes",
                        realm="passwd")
        self.assertEqual(event.data["realm"], "passwd")

    def test_download_with_url(self):
        event = self.ev(eventid="cowrie.session.file_download",
                        url="http://x.invalid/a.sh", shasum="a" * 64,
                        outfile="var/lib/cowrie/downloads/" + "a" * 64,
                        destfile="a.sh", duplicate=False)
        self.assertEqual(event.data["direction"], "download")
        self.assertEqual(event.data["url"], "http://x.invalid/a.sh")
        self.assertEqual(event.data["sha256"], "a" * 64)
        self.assertEqual(event.data["is_duplicate"], 0)

    def test_download_without_url(self):
        """stdin and shell-redirect captures have no url at all. The project
        brief had this column NOT NULL."""
        event = self.ev(eventid="cowrie.session.file_download",
                        shasum="b" * 64, destfile="/tmp/.x")
        self.assertIsNone(event.data["url"])
        self.assertEqual(event.data["sha256"], "b" * 64)

    def test_upload_uses_filename_and_has_no_url(self):
        event = self.ev(eventid="cowrie.session.file_upload",
                        filename="payload.bin", shasum="c" * 64,
                        outfile="out", destfile="/tmp/payload.bin")
        self.assertEqual(event.data["direction"], "upload")
        self.assertEqual(event.data["filename"], "payload.bin")
        self.assertIsNone(event.data["url"])

    def test_duration_ms_current_field(self):
        event = self.ev(eventid="cowrie.session.closed", duration_ms=4821)
        self.assertEqual(event.data["duration_ms"], 4821)

    def test_legacy_duration_as_string(self):
        """Removed upstream in Cowrie 3.0.4. The changelog records it as "a
        string for some transports and a float for others", so both have to
        coerce to the same integer milliseconds."""
        event = self.ev(eventid="cowrie.session.closed", duration="4.821")
        self.assertEqual(event.data["duration_ms"], 4821)

    def test_legacy_duration_as_float(self):
        event = self.ev(eventid="cowrie.session.closed", duration=4.821)
        self.assertEqual(event.data["duration_ms"], 4821)

    def test_duration_ms_wins_over_legacy_duration(self):
        event = self.ev(eventid="cowrie.session.closed", duration_ms=5000,
                        duration="99.0")
        self.assertEqual(event.data["duration_ms"], 5000)

    def test_session_closed_without_any_duration(self):
        """Still useful: it tells us when the session ended."""
        event = self.ev(eventid="cowrie.session.closed")
        self.assertIsNone(event.data["duration_ms"])


class TestFlags(unittest.TestCase):
    def test_synthetic_flag(self):
        result = parse_line(line(eventid="cowrie.session.closed",
                                 duration_ms=1, synthetic=True))
        assert result.event is not None
        self.assertTrue(result.event.is_synthetic)

    def test_absent_synthetic_flag_means_real(self):
        result = parse_line(line(eventid="cowrie.session.closed",
                                 duration_ms=1))
        assert result.event is not None
        self.assertFalse(result.event.is_synthetic)

    def test_synthetic_must_be_exactly_true(self):
        """A truthy value is not enough: "synthetic": "no" must not mark a
        session synthetic, and must not mark a real one either."""
        for value in ("yes", 1, "true"):
            with self.subTest(value=value):
                result = parse_line(line(eventid="cowrie.session.closed",
                                         duration_ms=1, synthetic=value))
                assert result.event is not None
                self.assertFalse(result.event.is_synthetic)

    def test_late_flag(self):
        result = parse_line(line(eventid="cowrie.session.file_download",
                                 shasum="a" * 64, late=True))
        assert result.event is not None
        self.assertTrue(result.event.is_late)

    def test_sensor_defaults_when_absent(self):
        raw = json.dumps({"eventid": "cowrie.session.closed",
                          "timestamp": TS, "session": "a1b2c3d4e5f6",
                          "src_ip": "198.51.100.7", "duration_ms": 1})
        result = parse_line(raw)
        assert result.event is not None
        self.assertEqual(result.event.sensor, "unknown")


if __name__ == "__main__":
    unittest.main()

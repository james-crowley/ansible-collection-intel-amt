# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Self-tests for the mock IDE-R server.

Three kinds of coverage:

* Byte-exact frame builder/parser tests (``TestFrameEncoding*``) that need no
  running server at all -- they pin the wire format against hand-built
  expected bytes, independent of any implementation detail.
* End-to-end handshake + SCSI round-trip tests that run the mock against a
  deliberately minimal "fake client" (``_FakeIderClient``, defined below).
  That stand-in is *not* a reference implementation -- its SCSI reply payloads
  are synthetic placeholders, not the canned byte arrays real firmware expects
  (those belong to the real client, copied from ``amt-ider-module.js`` per
  protocol-notes.md §4.5). It exists purely to prove the mock's frame
  mechanics -- chunking, reassembly, sequencing, and the write-path split --
  with no dependency on the collection's own client being correct.
* ``TestRealEngineAgainstMock``, which drives the **real** client
  (``plugins/module_utils/redirection.RedirectionSession`` plus
  ``plugins/module_utils/ider.IderEngine``) against the mock over a real socket.

That third group exists because the first two, on their own, leave a gap that is
easy to miss. This repository contains two independent implementations of one
wire protocol -- the mock plays firmware, ``ider.py`` plays the client -- and
each was tested only against its own hand-built expectations:
``_FakeIderClient`` does not exercise ``ider.py`` at all, and
``tests/unit/plugins/module_utils/test_ider.py`` feeds ``IderEngine`` frames it
builds itself. The two met nowhere below the ``amt_media`` integration target,
which needs a forked daemon and a playbook to run.

``TestRealEngineAgainstMock`` is deliberately thin: a wiring check on the
handshake (including its refusal), on the feature-toggle verdict, and on one
chunked read -- not a second SCSI suite. Keeping it small is the point -- it costs
a socket and no daemon, and it is the cheapest place to notice the two
implementations drifting apart, or to notice that a refusal the mock can express
is one the client does not classify.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import threading
import time

import pytest
from ider_server import (
    AuthenticationFailed,
    CommandEndResponse,
    DataToHostFrame,
    GetDataFromHostRequest,
    IderMockServer,
    ProtocolViolation,
    decode_command_end_response,
    decode_command_written,
    decode_data_from_host,
    decode_data_to_host,
    decode_get_data_from_host,
    decode_header,
    decode_open_session,
    decode_reset_occurred,
    decode_start_session_request,
    decode_status_data,
    encode_command_end_response,
    encode_command_written,
    encode_data_from_host,
    encode_data_to_host,
    encode_error_occurred,
    encode_get_data_from_host,
    encode_header,
    encode_open_session_reply,
    encode_reset_occurred,
    encode_start_session_reply,
    encode_status_data,
)

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ErrorClass, ProtocolError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.ider import DEVICE_FLOPPY, IderEngine, MediaImage
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection import START_SESSION_IDER, RedirectionSession

FAKE_USERNAME = "admin"
FAKE_PASSWORD = "test-password-not-real"
AUTH_URI = "/RedirectionService"

#: A deliberately distinctive non-zero ``0x11`` StartRedirectionSessionReply status.
#: Not ``1``: the test below reads this number back out of the *client's own* error
#: message, so a client that reported a hardcoded ``status=1`` instead of decoding byte 1
#: of the reply would pass with ``1`` and fail here. Nothing else depends on the value --
#: protocol-notes.md §3.1 distinguishes only zero from non-zero.
REFUSED_START_SESSION_STATUS = 2


def _md5(data: str) -> str:
    return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()


def _lp(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return bytes([len(encoded)]) + encoded


def _parse_lp_fields(data: bytes, count: int) -> list[str]:
    fields: list[str] = []
    pos = 0
    for _field_index in range(count):
        length = data[pos]
        pos += 1
        fields.append(data[pos : pos + length].decode("utf-8"))
        pos += length
    return fields


# --------------------------------------------------------------------------
# Byte-exact frame encoding tests
# --------------------------------------------------------------------------


class TestHeaderEncoding:
    def test_basic_header(self):
        assert encode_header(0x41, 5) == bytes([0x41, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00])

    def test_completed_bit_only_set_for_cmdid_over_50(self):
        # completed=True on a cmdid <= 50 must NOT set the bit (protocol-notes.md §4).
        assert encode_header(0x28, 0, completed=True)[3] == 0x00
        assert encode_header(0x54, 0, completed=True)[3] == 0x02

    def test_dma_bit(self):
        assert encode_header(0x54, 0, dma=True)[3] == 0x01
        assert encode_header(0x54, 0, dma=True, completed=True)[3] == 0x03

    def test_sequence_is_little_endian(self):
        header = encode_header(0x50, 0x01020304)
        assert header[4:8] == bytes([0x04, 0x03, 0x02, 0x01])

    def test_round_trip(self):
        header = encode_header(0x49, 12345, completed=True)
        assert decode_header(header) == (0x49, 0x02, 12345)


class TestStartSessionEncoding:
    def test_reply_is_thirteen_bytes_with_no_oem(self):
        reply = encode_start_session_reply(status=0)
        assert reply == bytes([0x11, 0x00]) + bytes(10) + bytes([0x00])
        assert len(reply) == 13

    def test_reply_with_oem_data(self):
        reply = encode_start_session_reply(status=0, oem=b"xy")
        assert len(reply) == 15
        assert reply[12] == 2
        assert reply[13:15] == b"xy"

    def test_decode_start_session_request_magic(self):
        request = bytes([0x10, 0x00, 0x00, 0x00]) + b"IDER"
        assert decode_start_session_request(request) == b"IDER"


class TestOpenSessionReplyEncoding:
    def test_field_offsets_match_protocol_notes(self):
        payload = encode_open_session_reply(major=1, minor=2, fw_major=10, fw_minor=1, readbfr=512, writebfr=1024, proto=0, iana=7)
        # Offsets below are global (including the 8-byte header the caller
        # prepends separately), matching protocol-notes.md §4.1 verbatim.
        frame = encode_header(0x41, 0) + payload
        assert frame[8] == 1  # major
        assert frame[9] == 2  # minor
        assert frame[10] == 10  # fw major
        assert frame[11] == 1  # fw minor
        assert int.from_bytes(frame[16:18], "little") == 512  # readbfr
        assert int.from_bytes(frame[18:20], "little") == 1024  # writebfr
        assert frame[21] == 0  # proto
        assert int.from_bytes(frame[25:29], "little") == 7  # iana
        assert frame[29] == 0  # trailing len
        assert len(frame) == 30

    def test_trailing_data_extends_total_length(self):
        payload = encode_open_session_reply(trailing=b"abc")
        frame = encode_header(0x41, 0) + payload
        assert frame[29] == 3
        assert frame[30:33] == b"abc"
        assert len(frame) == 33

    def test_decode_open_session_request(self):
        payload = (30000).to_bytes(2, "little") + (0).to_bytes(2, "little") + (20000).to_bytes(2, "little") + (1).to_bytes(4, "little")
        assert decode_open_session(payload) == (30000, 0, 20000, 1)


class TestStatusDataEncoding:
    def test_round_trip(self):
        payload = encode_status_data(3, 1)
        assert payload == bytes([0x03, 0x01, 0x00, 0x00, 0x00])
        assert decode_status_data(payload) == (3, 1)


class TestCommandWrittenEncoding:
    def test_field_offsets_match_protocol_notes(self):
        cdb = bytes(range(1, 13))
        payload = encode_command_written(cdb, device_flags=0x10, feature_register=0x01)
        frame = encode_header(0x50, 0) + payload
        assert len(frame) == 28
        assert frame[9] == 0x01  # feature register
        assert frame[14] == 0x10  # device flags (bit 4 -> CD/DVD)
        assert frame[16:28] == cdb

    def test_rejects_wrong_length_cdb(self):
        with pytest.raises(ValueError, match="12 bytes"):
            encode_command_written(bytes(11), device_flags=0)

    def test_decode_round_trip(self):
        cdb = bytes(range(12))
        payload = encode_command_written(cdb, device_flags=0x00, feature_register=0x01)
        device_flags, decoded_cdb, feature_register = decode_command_written(payload)
        assert device_flags == 0x00
        assert decoded_cdb == cdb
        assert feature_register == 0x01


class TestCommandEndResponseEncoding:
    def test_error_form_matches_protocol_notes(self):
        payload = encode_command_end_response(error=True, device=0xA0)
        expected = bytes(12) + bytes([0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, 0xA0, 0x50, 0x00, 0x00, 0x00])
        assert payload == expected
        assert len(payload) == 23

    def test_sense_form_matches_protocol_notes(self):
        payload = encode_command_end_response(error=False, device=0xB0, sense=0x06, asc=0x28, asq=0x00)
        expected = bytes(12) + bytes([0x87, 0x60, 0x03, 0x00, 0x00, 0x00, 0xB0, 0x51, 0x06, 0x28, 0x00])
        assert payload == expected

    def test_decode_error_form(self):
        payload = encode_command_end_response(error=True, device=0xA0)
        assert decode_command_end_response(payload) == CommandEndResponse(error=True, device=0xA0)

    def test_decode_sense_form(self):
        payload = encode_command_end_response(error=False, device=0xB0, sense=0x02, asc=0x3A, asq=0x00)
        assert decode_command_end_response(payload) == CommandEndResponse(error=False, device=0xB0, sense=0x02, asc=0x3A, asq=0x00)

    def test_unrecognised_marker_raises(self):
        with pytest.raises(ProtocolViolation):
            decode_command_end_response(bytes(23))


class TestDataToHostEncoding:
    def test_non_completed_frame_matches_protocol_notes(self):
        data = b"\x01\x02\x03"
        payload = encode_data_to_host(0xA0, data, completed=False)
        expected_prefix = bytes([0x00, 3, 0, 0x00, 0xB5, 0x00, 0x02, 0x00, 3, 0, 0xA0, 0x58])
        expected_tail = bytes(14)
        assert payload == expected_prefix + expected_tail + data

    def test_completed_frame_matches_protocol_notes(self):
        data = b"\xaa\xbb"
        payload = encode_data_to_host(0xB0, data, completed=True)
        expected_prefix = bytes([0x00, 2, 0, 0x00, 0xB5, 0x00, 0x02, 0x00, 2, 0, 0xB0, 0x58])
        expected_tail = bytes([0x85, 0x00, 0x03, 0x00, 0x00, 0x00, 0xB0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        assert payload == expected_prefix + expected_tail + data

    def test_dma_zeroes_dmalen_field(self):
        payload = encode_data_to_host(0xA0, b"\x01\x02", completed=False, dma=True)
        assert payload[4] == 0xB4
        assert payload[8:10] == bytes([0, 0])  # dmalen forced to 0 under DMA

    def test_decode_round_trip(self):
        data = bytes(range(50))
        payload = encode_data_to_host(0xA0, data, completed=True)
        frame = decode_data_to_host(payload)
        assert frame == DataToHostFrame(device=0xA0, data=data, completed=True, dma=False)

    def test_decode_rejects_truncated_payload(self):
        payload = encode_data_to_host(0xA0, b"\x01\x02\x03", completed=True)
        with pytest.raises(ProtocolViolation):
            decode_data_to_host(payload[:-1])


class TestGetDataFromHostEncoding:
    def test_matches_protocol_notes(self):
        payload = encode_get_data_from_host(0xA0, 512)
        expected = bytes([0x00, 0x00, 0x02, 0x00, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x02, 0xA0, 0x58]) + bytes(11)
        assert payload == expected
        assert len(payload) == 23

    def test_decode_round_trip(self):
        payload = encode_get_data_from_host(0xB0, 4096)
        assert decode_get_data_from_host(payload) == GetDataFromHostRequest(device=0xB0, chunk=4096)


class TestDataFromHostEncoding:
    def test_matches_protocol_notes_offsets(self):
        chunk = b"\x01\x02\x03\x04"
        payload = encode_data_from_host(chunk)
        # Global offset 9 (local 1) is the length; global offset 14 (local 6) is data start.
        frame = encode_header(0x53, 0) + payload
        assert int.from_bytes(frame[9:11], "little") == 4
        assert frame[14:18] == chunk
        assert len(frame) == 14 + 4

    def test_decode_round_trip(self):
        chunk = bytes(range(30))
        assert decode_data_from_host(encode_data_from_host(chunk)) == chunk

    def test_decode_rejects_truncated_payload(self):
        payload = encode_data_from_host(b"\x01\x02\x03")
        with pytest.raises(ProtocolViolation):
            decode_data_from_host(payload[:-1])


class TestMiscFrameEncoding:
    def test_reset_occurred_round_trip(self):
        assert decode_reset_occurred(encode_reset_occurred(0x02)) == 0x02

    def test_error_occurred_shape(self):
        assert encode_error_occurred(5) == bytes([5, 0, 0])


# --------------------------------------------------------------------------
# Fake client -- see module docstring for what this is and is not.
# --------------------------------------------------------------------------


class _FakeIderClient:
    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.sock = socket.create_connection((host, port), timeout=5)
        self.out_seq = 0
        self.readbfr = 1024
        # A tiny synthetic "floppy" backing store: 8 sectors of 512 bytes.
        self.media = bytearray(b"".join(bytes([i]) * 512 for i in range(8)))
        self.closed_by_peer = False

    def recv_exact(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise ConnectionError("mock closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def read_supported_auth_types(self) -> tuple[int, ...]:
        self.sock.sendall(bytes([0x10, 0x00, 0x00, 0x00]) + b"IDER")
        start_reply = self.recv_exact(13)
        oem_len = start_reply[12]
        if oem_len:
            self.recv_exact(oem_len)

        self.sock.sendall(bytes([0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        prefix = self.recv_exact(9)
        auth_type = prefix[4]
        data_len = int.from_bytes(prefix[5:9], "little")
        auth_data = self.recv_exact(data_len) if data_len else b""
        assert auth_type == 0
        return tuple(auth_data)

    def handshake(self) -> bool:
        """Full auth handshake. Returns True if authenticated."""
        supported = self.read_supported_auth_types()
        assert 4 in supported, "test relies on the mock advertising digest-with-cnonce"

        user_bytes = self.username.encode()
        uri_bytes = AUTH_URI.encode()
        query_data = bytes([len(user_bytes)]) + user_bytes + bytes(2) + bytes([len(uri_bytes)]) + uri_bytes + bytes(4)
        query_msg = bytes([0x13, 0x00, 0x00, 0x00, 0x04]) + len(query_data).to_bytes(4, "little") + query_data
        self.sock.sendall(query_msg)

        prefix = self.recv_exact(9)
        assert prefix[4] == 4
        data_len = int.from_bytes(prefix[5:9], "little")
        challenge_data = self.recv_exact(data_len)
        realm, nonce, qop = _parse_lp_fields(challenge_data, count=3)

        cnonce = secrets.token_hex(16)
        snc = "00000002"
        ha1 = _md5(f"{self.username}:{realm}:{self.password}")
        ha2 = _md5(f"POST:{AUTH_URI}")
        digest = _md5(f"{ha1}:{nonce}:{snc}:{cnonce}:{qop}:{ha2}")

        fields = _lp(self.username) + _lp(realm) + _lp(nonce) + _lp(AUTH_URI) + _lp(cnonce) + _lp(snc) + _lp(digest) + _lp(qop)
        response_msg = bytes([0x13, 0x00, 0x00, 0x00, 0x04]) + len(fields).to_bytes(4, "little") + fields
        self.sock.sendall(response_msg)

        prefix = self.recv_exact(9)
        status = prefix[1]
        data_len = int.from_bytes(prefix[5:9], "little")
        if data_len:
            self.recv_exact(data_len)
        return status == 0

    def start_ider_session(self) -> None:
        payload = (30000).to_bytes(2, "little") + (0).to_bytes(2, "little") + (20000).to_bytes(2, "little") + (1).to_bytes(4, "little")
        self._send(0x40, payload)

        header = self.recv_exact(8)
        cmdid, _attrs, _seq = decode_header(header)
        assert cmdid == 0x41
        base = self.recv_exact(22)
        trailing_len = base[21]
        if trailing_len:
            self.recv_exact(trailing_len)
        self.readbfr = int.from_bytes(base[8:10], "little")

        self._send(0x48, bytes([0x03]) + (0x01 + 0x08).to_bytes(4, "little"))
        header = self.recv_exact(8)
        cmdid, _attrs, _seq = decode_header(header)
        assert cmdid == 0x49
        self.recv_exact(5)

    def _send(self, cmdid: int, payload: bytes, *, completed: bool = False, dma: bool = False) -> None:
        header = encode_header(cmdid, self.out_seq, completed=completed, dma=dma)
        self.out_seq += 1
        self.sock.sendall(header + payload)

    def send_bad_sequence_frame(self, cmdid: int, payload: bytes = b"") -> None:
        header = encode_header(cmdid, self.out_seq + 999)
        self.sock.sendall(header + payload)

    def respond_to_one_command(self) -> int:
        """Read one inbound frame from the mock and react to it. Returns the command id read."""
        header = self.recv_exact(8)
        cmdid, _attrs, _seq = decode_header(header)
        if cmdid == 0x50:
            payload = self.recv_exact(20)
            device_flags, cdb, _feature_register = decode_command_written(payload)
            device = 0xB0 if (device_flags & 0x10) else 0xA0
            self._handle_scsi(device, cdb)
        elif cmdid == 0x46:
            self.recv_exact(1)
            self._send(0x47, b"")
        elif cmdid == 0x4A:
            self.recv_exact(3)  # ERROR_OCCURRED: logged, session continues
        elif cmdid == 0x43:
            self.closed_by_peer = True
            self.sock.close()
        else:
            raise AssertionError(f"fake client received unexpected command id {cmdid:#x}")
        return cmdid

    def _handle_scsi(self, device: int, cdb: bytes) -> None:
        op = cdb[0]
        if op == 0x00:  # TEST_UNIT_READY
            self._send(0x51, encode_command_end_response(error=False, device=device), completed=True)
        elif op == 0x25:  # READ_CAPACITY
            blocks = (len(self.media) // 512) - 1
            data = blocks.to_bytes(4, "big") + bytes([0, 0, 0x02, 0])
            self._send(0x54, encode_data_to_host(device, data, completed=True), completed=True)
        elif op in (0x1A, 0x5A, 0x46):  # MODE_SENSE_6/_10, GET_CONFIGURATION -- synthetic placeholder payload
            data = bytes(4) if op == 0x1A else bytes(8)
            self._send(0x54, encode_data_to_host(device, data, completed=True), completed=True)
        elif op == 0x28:  # READ_10
            lba = int.from_bytes(cdb[2:6], "big")
            count = int.from_bytes(cdb[7:9], "big")
            start, total = lba * 512, count * 512
            data = bytes(self.media[start : start + total])
            chunk_size = self.readbfr or 512
            for offset in range(0, len(data), chunk_size):
                chunk = data[offset : offset + chunk_size]
                completed = offset + len(chunk) >= len(data)
                self._send(0x54, encode_data_to_host(device, chunk, completed=completed), completed=completed)
        elif op == 0x2A:  # WRITE_10
            lba = int.from_bytes(cdb[2:6], "big")
            count = int.from_bytes(cdb[7:9], "big")
            total = count * 512
            self._send(0x52, encode_get_data_from_host(device, total))
            received = bytearray()
            while len(received) < total:
                header = self.recv_exact(8)
                cmdid, _attrs, _seq = decode_header(header)
                assert cmdid == 0x53
                prefix = self.recv_exact(6)
                chunk_len = int.from_bytes(prefix[1:3], "little")
                received += self.recv_exact(chunk_len)
            start = lba * 512
            self.media[start : start + total] = bytes(received)
            self._send(0x51, encode_command_end_response(error=False, device=device), completed=True)
        else:
            self._send(0x51, encode_command_end_response(error=True, device=device), completed=True)


def _cdb(opcode: int, *rest: int) -> bytes:
    data = bytes([opcode, *rest])
    return data + bytes(12 - len(data))


def _cdb_read_10(lba: int, count: int) -> bytes:
    return bytes([0x28, 0]) + lba.to_bytes(4, "big") + bytes([0]) + count.to_bytes(2, "big") + bytes(3)


def _cdb_write_10(lba: int, count: int) -> bytes:
    return bytes([0x2A, 0]) + lba.to_bytes(4, "big") + bytes([0]) + count.to_bytes(2, "big") + bytes(3)


@pytest.fixture
def server():
    with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, readbfr=512, writebfr=512) as srv:
        yield srv


def _connect_and_handshake(srv: IderMockServer) -> _FakeIderClient:
    client = _FakeIderClient(srv.host, srv.port, FAKE_USERNAME, FAKE_PASSWORD)
    assert client.handshake() is True
    client.start_ider_session()
    srv.wait_for_handshake()
    return client


class TestHandshake:
    def test_correct_credentials_authenticate(self, server):
        client = _connect_and_handshake(server)
        client.sock.close()

    def test_wrong_password_is_rejected(self, server):
        client = _FakeIderClient(server.host, server.port, FAKE_USERNAME, "not-the-real-password")
        authenticated = client.handshake()
        assert authenticated is False
        with pytest.raises(AuthenticationFailed):
            server.wait_for_handshake()
        client.sock.close()

    def test_restricted_auth_types_do_not_advertise_digest_with_cnonce(self):
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, supported_auth_types=(1, 3)) as srv:
            client = _FakeIderClient(srv.host, srv.port, FAKE_USERNAME, FAKE_PASSWORD)
            supported = client.read_supported_auth_types()
            assert 4 not in supported
            assert set(supported) == {1, 3}
            client.sock.close()

    def test_open_session_reply_reports_configured_readbfr_and_proto(self):
        # The mock must be able to emit an out-of-spec reply on demand (an
        # oversized readbfr, or a non-zero proto) so a real client's own
        # validation can later be tested against it.
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, readbfr=9000, proto=1) as srv:
            client = _FakeIderClient(srv.host, srv.port, FAKE_USERNAME, FAKE_PASSWORD)
            assert client.handshake() is True
            payload = (30000).to_bytes(2, "little") + (0).to_bytes(2, "little") + (20000).to_bytes(2, "little") + (1).to_bytes(4, "little")
            client._send(0x40, payload)
            header = client.recv_exact(8)
            cmdid, _attrs, _seq = decode_header(header)
            assert cmdid == 0x41
            base = client.recv_exact(22)
            assert int.from_bytes(base[8:10], "little") == 9000
            assert base[13] == 1
            client.sock.close()


class TestScsiRoundTrip:
    def test_test_unit_ready(self, server):
        client = _connect_and_handshake(server)
        server.issue_scsi(_cdb(0x00))
        client.respond_to_one_command()
        event = server.next_event()
        assert event == CommandEndResponse(error=False, device=0xA0, sense=0, asc=0, asq=0)
        client.sock.close()

    def test_read_capacity(self, server):
        client = _connect_and_handshake(server)
        server.issue_scsi(_cdb(0x25))
        client.respond_to_one_command()
        event = server.next_event()
        assert isinstance(event, DataToHostFrame)
        assert event.completed is True
        blocks = int.from_bytes(event.data[0:4], "big")
        assert blocks == (len(client.media) // 512) - 1

    def test_mode_sense_6_and_10_and_get_configuration(self, server):
        client = _connect_and_handshake(server)
        for cdb in (_cdb(0x1A, 0, 0x3F), _cdb(0x5A, 0, 0x3F), _cdb(0x46)):
            server.issue_scsi(cdb)
            client.respond_to_one_command()
            event = server.next_event()
            assert isinstance(event, DataToHostFrame)
            assert event.completed is True

    def test_read_10_is_chunked_and_reassembled_with_completed_only_on_last_frame(self, server):
        # readbfr=512 (fixture) forces a 4-sector read to split into 4 frames.
        client = _connect_and_handshake(server)
        server.issue_scsi(_cdb_read_10(lba=0, count=4))
        client.respond_to_one_command()
        data, completed_flags = server.read_data_to_host_stream()
        assert data == bytes(client.media[0 : 4 * 512])
        assert completed_flags == [False, False, False, True]

    def test_write_10_multi_frame_split_lands_in_backing_store(self, server):
        client = _connect_and_handshake(server)
        payload = bytes(range(256)) * 4  # 1024 bytes == 2 sectors
        server.issue_scsi(_cdb_write_10(lba=2, count=2))

        # The fake client's WRITE_10 handling is one synchronous call that
        # sends 0x52 and then blocks reading 0x53 frames -- run it in the
        # background so this thread can drive the mock's side of that same
        # exchange (read the 0x52, send the 0x53 frames) concurrently.
        client_thread = threading.Thread(target=client.respond_to_one_command)
        client_thread.start()

        request = server.next_event()
        assert isinstance(request, GetDataFromHostRequest)
        assert request.chunk == len(payload)

        # Split deliberately across multiple frames smaller than the payload
        # -- the exact scenario protocol-notes.md §5.2 calls out as the most
        # likely place for a client bug.
        server.send_data_from_host(payload, frame_size=200)
        client_thread.join(timeout=5)
        assert not client_thread.is_alive()

        event = server.next_event()
        assert event == CommandEndResponse(error=False, device=0xA0, sense=0, asc=0, asq=0)
        assert bytes(client.media[2 * 512 : 2 * 512 + len(payload)]) == payload

    def test_unknown_scsi_command_gets_error_response(self, server):
        client = _connect_and_handshake(server)
        server.issue_scsi(_cdb(0xFF))
        client.respond_to_one_command()
        event = server.next_event()
        assert event == CommandEndResponse(error=True, device=0xA0)


class TestFaultInjection:
    def test_reset_occurred_mid_read_gets_acked(self, server):
        # Scope note: this proves the mock can inject 0x46 during an active
        # exchange and correctly receive/decode the client's 0x47 ack. It does
        # NOT prove a real client defers the ack until its read queue drains
        # (protocol-notes.md §4.6) -- that behaviour lives in the real client
        # module and is untestable until it exists.
        client = _connect_and_handshake(server)
        server.issue_scsi(_cdb_read_10(lba=0, count=1))
        server.inject_reset_occurred(reset_mask=0)

        client.respond_to_one_command()  # handles the READ_10
        data, completed_flags = server.read_data_to_host_stream()
        assert data == bytes(client.media[0:512])
        assert completed_flags == [True]

        client.respond_to_one_command()  # handles the pending RESET_OCCURRED
        from ider_server import _ResetOccurredResponse

        assert isinstance(server.next_event(), _ResetOccurredResponse)

    def test_error_occurred_does_not_stop_the_session(self, server):
        client = _connect_and_handshake(server)
        server.inject_error_occurred(code=7)
        client.respond_to_one_command()  # logs, does not stop

        server.issue_scsi(_cdb(0x00))
        client.respond_to_one_command()
        assert server.next_event() == CommandEndResponse(error=False, device=0xA0, sense=0, asc=0, asq=0)

    def test_close_injection_ends_the_session(self, server):
        client = _connect_and_handshake(server)
        server.inject_close()
        cmdid = client.respond_to_one_command()
        assert cmdid == 0x43
        assert client.closed_by_peer is True
        assert server.session_closed(timeout=2) is True

    def test_out_of_sequence_frame_from_client_tears_down_session(self, server):
        client = _connect_and_handshake(server)
        client.send_bad_sequence_frame(0x51, encode_command_end_response(error=False, device=0xA0))
        event = server.next_event()
        assert isinstance(event, ProtocolViolation)
        assert server.session_closed(timeout=2) is True
        client.sock.close()


class TestCleanShutdown:
    def test_no_leaked_threads_or_sockets_after_exit(self):
        before = set(threading.enumerate())
        srv = IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD).start()
        port = srv.port
        client = _FakeIderClient(srv.host, srv.port, FAKE_USERNAME, FAKE_PASSWORD)
        assert client.handshake() is True
        client.sock.close()
        srv.stop()

        after = set(threading.enumerate())
        leaked = after - before
        assert not leaked, f"threads leaked after shutdown: {leaked}"

        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)


# --------------------------------------------------------------------------
# The real client against the mock -- see the module docstring for why this
# group exists separately from the _FakeIderClient tests above.
# --------------------------------------------------------------------------


class _RealClientHarness:
    """The real ``RedirectionSession`` + ``IderEngine`` pair, pumped by hand.

    Deliberately mirrors what ``media_session._run_daemon`` does -- connect, build an
    engine, attach media, ``start()``, feed the handshake leftover -- minus the fork,
    the state file and the signal handling, none of which are protocol concerns. That
    keeps this a test of the two protocol implementations agreeing, not a second test
    of the daemon.

    The receive pump comes in two forms because the tests need both:

    * :meth:`pump_until` runs on the calling thread. Used when the test only waits on
      the *client's* own state (session open, toggle verdict), so a failure surfaces as
      an ordinary assertion with an ordinary traceback.
    * :meth:`start_pump` runs it on a background thread. Required as soon as the mock
      drives SCSI, because then both sides are waiting on each other: the mock's
      ``read_data_to_host_stream`` blocks on its event queue while the engine still
      needs feeding, and one thread cannot do both.

    One ordering constraint, easy to get backwards: a test must **pump before** calling
    ``srv.wait_for_handshake()``, never the other way round. The mock does not consider
    its handshake finished until it has read the client's ``0x48``
    DISABLE_ENABLE_FEATURES, and the real engine only sends that in reaction to being
    fed the mock's ``0x41`` OPEN_SESSION_REPLY. Waiting first therefore deadlocks -- the
    mock waits for a frame only the pump can cause -- and it surfaces as a bare
    handshake timeout that reads like a protocol bug rather than a test-ordering
    mistake. ``_FakeIderClient`` hides this because its ``start_ider_session()`` reads
    and replies inline on the calling thread.
    """

    def __init__(self, srv: IderMockServer, image_path, *, writable: bool = False) -> None:
        self.session = RedirectionSession(
            srv.host,
            username=FAKE_USERNAME,
            password=FAKE_PASSWORD,
            use_tls=False,
            port=srv.port,
            connect_timeout=5.0,
            start_frame=START_SESSION_IDER,
        )
        leftover = self.session.connect()
        self.image = MediaImage(image_path, device_code=DEVICE_FLOPPY, writable=writable)
        self.engine = IderEngine(send=self.session.send)
        self.engine.attach_device(self.image)
        self.engine.start()
        if leftover:
            self.engine.feed(leftover)
        # Short enough that pump_until's bound is the thing that actually decides how
        # long a test waits, rather than one blocking recv overshooting it.
        self.session.set_recv_timeout(0.25)
        self.pump_error: BaseException | None = None
        self._pumping = False
        self._thread: threading.Thread | None = None

    def _feed_once(self) -> bool:
        """Receive and feed one chunk. Returns False when the connection is done."""
        try:
            chunk = self.session.recv()
        except TimeoutError:
            return True
        except OSError:
            return False
        if not chunk:
            return False
        self.engine.feed(chunk)
        return True

    def pump_until(self, predicate, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline or not self._feed_once():
                break
        return bool(predicate())

    def start_pump(self) -> None:
        self._pumping = True
        self._thread = threading.Thread(target=self._pump_forever, name="real-engine-pump", daemon=True)
        self._thread.start()

    def _pump_forever(self) -> None:
        # Any exception is captured rather than raised: this runs off the test thread,
        # where a raise would be swallowed into a bare "exception in thread" on stderr
        # and the test would fail later with an unrelated timeout. stop_pump() re-raises.
        try:
            while self._pumping and self._feed_once():
                pass
        except BaseException as exc:  # re-raised on the test thread by stop_pump()
            self.pump_error = exc

    def stop_pump(self) -> None:
        self._pumping = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if self.pump_error is not None:
            raise self.pump_error

    def close(self) -> None:
        self.image.close()
        self.session.close()


def _floppy_image(tmp_path, sectors: int = 4):
    """A backing file whose every sector is a distinct repeated byte.

    Distinct per sector so an assertion on the bytes read back proves the *right*
    sectors came back, not merely that the right number of bytes did -- an off-by-one
    LBA would return the correct length of the wrong data.
    """
    path = tmp_path / "answer.img"
    path.write_bytes(b"".join(bytes([index]) * 512 for index in range(sectors)))
    return path


class TestRealEngineAgainstMock:
    def test_refused_session_start_is_classified_and_names_the_status(self):
        """``0x11`` comes back with a non-zero status: reachable firmware that will not open a session.

        Deliberately does **not** use :class:`_RealClientHarness`. This fault fires inside
        ``RedirectionSession.connect()``, which the harness calls in its own constructor, so
        there is no harness to build -- and that is the substance of the test rather than an
        inconvenience. The refusal lands upstream of ``IderEngine`` entirely: no media is
        opened, no engine exists, and neither the digest exchange nor ``media_session``'s
        attach gate is involved in reaching the verdict. It is the only endpoint fault the
        mock can inject where that is true.

        Three things must hold at once, and each is a distinct way a redirection client can
        get this wrong:

        * **It must raise, not hang.** A client that kept reading past the refusal would
          block until the socket timed out. ``connect_timeout`` is also the socket's recv
          timeout (see ``RedirectionSession._default_socket_factory``), so that outcome
          arrives as ``TimeoutError_`` -- a different type, which this ``pytest.raises`` does
          not accept, so a hang fails rather than passes slowly.
        * **It must not be reported as an authentication failure.** The credentials were
          never offered; the session was refused before the auth-type query went out.
          Classifying this as ``authentication`` would send an operator to check a password
          that had nothing to do with it.
        * **It must carry the status firmware actually sent**, decoded from the reply, so the
          code can be looked up rather than the caller being told only that "something
          failed".
        """
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, start_session_status=REFUSED_START_SESSION_STATUS) as srv:
            session = RedirectionSession(
                srv.host,
                username=FAKE_USERNAME,
                password=FAKE_PASSWORD,
                use_tls=False,
                port=srv.port,
                connect_timeout=5.0,
                start_frame=START_SESSION_IDER,
            )
            try:
                with pytest.raises(ProtocolError) as excinfo:
                    session.connect()
            finally:
                session.close()

            assert excinfo.value.error_class == ErrorClass.PROTOCOL
            assert f"status={REFUSED_START_SESSION_STATUS}" in str(excinfo.value)
            assert excinfo.value.endpoint == f"{srv.host}:{srv.port}"
            # Every error this module raises is built with secrets=self._password; this path
            # is no exception, and a redaction hole would be least likely to be noticed on a
            # failure path nothing previously exercised.
            assert FAKE_PASSWORD not in str(excinfo.value)

            # Pin *which* fault fired. Without this, the assertions above would pass equally
            # well if the mock had aborted for some unrelated reason and the client had merely
            # read a garbled reply -- the same vacuity that scenario E's handshake check
            # exists to rule out on the integration side.
            with pytest.raises(ProtocolViolation, match="start-session status configured non-zero"):
                srv.wait_for_handshake(timeout=5.0)

    def test_handshake_completes_and_the_toggle_is_accepted(self, tmp_path):
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, readbfr=512, writebfr=512) as srv:
            harness = _RealClientHarness(srv, _floppy_image(tmp_path))
            try:
                assert harness.pump_until(lambda: harness.engine.feature_toggle_ok is not None)
                srv.wait_for_handshake(timeout=5.0)
                assert harness.engine.session_open is True
                assert harness.engine.feature_toggle_ok is True
                # The mock's advertised buffer size reached the real client intact, which
                # is what it will chunk DATA_TO_HOST by. A mismatch here is silent until
                # a read is large enough to need splitting.
                assert harness.engine.session_info.readbfr == 512
            finally:
                harness.close()

    def test_refused_toggle_is_observed_as_a_definite_false(self, tmp_path):
        """The refusal path issue #69's attach gate exists for, at the engine level.

        ``False`` and ``None`` are different answers to different questions -- "firmware
        said no" versus "firmware has not said" -- and the gate in
        ``media_session._run_daemon`` branches on exactly that difference, so a client
        that reported the refusal as an absent verdict would make the gate wait out its
        timeout and misclassify a definite refusal as a timeout.
        """
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, feature_toggle_status=0) as srv:
            harness = _RealClientHarness(srv, _floppy_image(tmp_path))
            try:
                assert harness.pump_until(lambda: harness.engine.feature_toggle_ok is not None)
                srv.wait_for_handshake(timeout=5.0)
                assert harness.engine.session_open is True
                assert harness.engine.feature_toggle_ok is False
            finally:
                harness.close()

    def test_withheld_toggle_leaves_the_verdict_unanswered(self, tmp_path):
        """The mock can express "never answers", and the engine reports it as unknown.

        Asserting ``is None`` after a bounded pump is the whole point: the engine must
        not default an unanswered toggle to either verdict. Defaulting to ``True`` is
        the pre-#69 defect (media reported as served when nothing is serving it);
        defaulting to ``False`` would report a definite refusal that never happened.
        """
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, feature_toggle_status=None) as srv:
            harness = _RealClientHarness(srv, _floppy_image(tmp_path))
            try:
                # The session genuinely opens -- this is not a broken handshake.
                assert harness.pump_until(lambda: harness.engine.session_open is True)
                srv.wait_for_handshake(timeout=5.0)
                # And then nothing arrives. Pump well past any plausible in-flight delay.
                assert harness.pump_until(lambda: harness.engine.feature_toggle_ok is not None, timeout=1.5) is False
                assert harness.engine.feature_toggle_ok is None
                assert harness.engine.stopped is False
            finally:
                harness.close()

    def test_read_10_serves_the_real_media_bytes_the_mock_asked_for(self, tmp_path):
        """A full SCSI read across the seam, with a payload that must be split.

        ``readbfr=512`` against a two-sector (1024-byte) read forces the real engine to
        chunk DATA_TO_HOST, so this asserts the two implementations agree on the frame
        prefix, the declared length, the completed bit and the chunk boundary -- not just
        on the happy single-frame case.
        """
        image_path = _floppy_image(tmp_path, sectors=4)
        expected = image_path.read_bytes()[512 : 512 + 1024]  # LBA 1, two sectors
        with IderMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, readbfr=512, writebfr=512) as srv:
            harness = _RealClientHarness(srv, image_path)
            try:
                assert harness.pump_until(lambda: harness.engine.feature_toggle_ok is True)
                srv.wait_for_handshake(timeout=5.0)
                harness.start_pump()
                srv.issue_scsi(_cdb_read_10(1, 2), device=DEVICE_FLOPPY)
                data, completed_flags = srv.read_data_to_host_stream(timeout=5.0)
                assert data == expected
                # Only the final frame may claim completion; anything else would let a
                # peer stop reassembling early.
                assert completed_flags[-1] is True
                assert completed_flags[:-1] == [False] * (len(completed_flags) - 1)
                assert harness.image.bytes_read == len(expected)
            finally:
                harness.stop_pump()
                harness.close()

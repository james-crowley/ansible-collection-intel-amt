# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Self-tests for the mock IDE-R server.

Two kinds of coverage:

* Byte-exact frame builder/parser tests (``TestFrameEncoding*``) that need no
  running server at all -- they pin the wire format against hand-built
  expected bytes, independent of any implementation detail.
* End-to-end handshake + SCSI round-trip tests that run the mock against a
  deliberately minimal "fake client" (``_FakeIderClient``, defined below).
  That stand-in exists only because ``plugins/module_utils/ider.py`` (the
  real client) is being written in parallel and does not exist yet; it is
  *not* a reference implementation -- its SCSI reply payloads are synthetic
  placeholders, not the canned byte arrays real firmware expects (those
  belong to the real client, copied from ``amt-ider-module.js`` per
  protocol-notes.md §4.5). It exists purely to prove the mock's frame
  mechanics: chunking, reassembly, sequencing, and the write-path split.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import threading

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

FAKE_USERNAME = "admin"
FAKE_PASSWORD = "test-password-not-real"
AUTH_URI = "/RedirectionService"


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

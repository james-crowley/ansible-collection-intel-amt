# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deterministic mock IDE-R / redirection endpoint for integration testing.

This plays **firmware**, which makes it the mirror image of the client this
collection ships (``plugins/module_utils/ider.py``, and its reference,
Apache-2.0 ``amt-ider-module.js``): firmware issues SCSI commands and consumes
media data; the client serves media. Concretely, once a session is
authenticated:

* the mock **sends** ``0x50`` COMMAND_WRITTEN (a SCSI CDB) at the client and
  reads back ``0x51`` COMMAND_END_RESPONSE / ``0x54`` DATA_TO_HOST;
* for writes, the mock **receives** the client's ``0x52`` GET_DATA_FROM_HOST
  and **sends** the payload back as one or more ``0x53`` DATA_FROM_HOST
  frames -- deliberately split across frames, because that split is real
  firmware behaviour and the most likely place for a client bug.

See ``docs/protocol-notes.md`` §3-§5 for the normative byte layouts; every
``encode_*``/``decode_*`` function here implements exactly one row of those
tables and is unit-testable in isolation (``tests/unit/mock_servers/test_ider_server.py``
asserts several of them byte-for-byte against hand-built expected output).

Standard library only. TLS mode reuses the same throw-away self-signed
certificate helper as the WS-Man mock (see ``wsman_server.py`` for why that
shells out to the ``openssl`` CLI rather than depending on ``cryptography``).
"""

from __future__ import annotations

import hashlib
import hmac
import queue
import secrets
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass

from wsman_server import generate_self_signed_tls_context

#: Fixed inbound payload lengths (bytes, *excluding* the 8-byte generic
#: header) for command IDs the mock may receive once the session is
#: authenticated. 0x54 DATA_TO_HOST is intentionally absent: its length is
#: variable and is decoded from its own prefix (see ``_reader_loop``).
_FIXED_INBOUND_PAYLOAD_LENGTH: dict[int, int] = {
    0x43: 0,  # CLOSE
    0x44: 0,  # KEEPALIVE_PING
    0x45: 0,  # KEEPALIVE_PONG
    0x46: 1,  # RESET_OCCURRED
    0x47: 0,  # RESET_OCCURRED_RESPONSE
    0x4A: 3,  # ERROR_OCCURRED
    0x51: 23,  # COMMAND_END_RESPONSE
    0x52: 23,  # GET_DATA_FROM_HOST
}


class ProtocolViolation(Exception):
    """The peer sent something that does not conform to protocol-notes.md."""


class AuthenticationFailed(Exception):
    """The redirection-plane digest response did not match."""


# --------------------------------------------------------------------------
# Frame builders / parsers -- one function per protocol-notes.md row.
# Pure functions so self-tests can assert byte-exact output independent of
# any running server.
# --------------------------------------------------------------------------


def encode_header(cmdid: int, seq: int, *, completed: bool = False, dma: bool = False) -> bytes:
    """The 8-byte header every post-authentication IDE-R message uses."""
    attributes = 0
    if dma:
        attributes |= 0x01
    if completed and cmdid > 50:
        attributes |= 0x02
    return bytes([cmdid & 0xFF, 0x00, 0x00, attributes]) + seq.to_bytes(4, "little")


def decode_header(data: bytes) -> tuple[int, int, int]:
    """Returns (cmdid, attributes, sequence)."""
    if len(data) != 8:
        raise ValueError(f"IDE-R header must be exactly 8 bytes, got {len(data)}")
    return data[0], data[3], int.from_bytes(data[4:8], "little")


def encode_start_session_reply(*, status: int = 0, reserved: bytes = bytes(10), oem: bytes = b"") -> bytes:
    """``0x11`` StartRedirectionSessionReply (protocol-notes.md §3.1)."""
    if len(reserved) != 10:
        raise ValueError("reserved block must be exactly 10 bytes")
    return bytes([0x11, status]) + reserved + bytes([len(oem)]) + oem


def decode_start_session_request(data: bytes) -> bytes:
    """Returns the 4-byte magic (``IDER``, ``SOL `` or ``KVMR``) from an 8-byte start-session request."""
    if len(data) != 8:
        raise ValueError("start-session request must be exactly 8 bytes")
    return data[4:8]


def encode_authenticate_reply(*, status: int, auth_type: int, auth_data: bytes = b"") -> bytes:
    """``0x14`` AuthenticateSessionReply (protocol-notes.md §3.2)."""
    return bytes([0x14, status, 0x00, 0x00, auth_type]) + len(auth_data).to_bytes(4, "little") + auth_data


def encode_open_session_reply(
    *,
    major: int = 1,
    minor: int = 0,
    fw_major: int = 10,
    fw_minor: int = 0,
    readbfr: int = 1024,
    writebfr: int = 1024,
    proto: int = 0,
    iana: int = 0,
    trailing: bytes = b"",
) -> bytes:
    """Payload (post-header) for ``0x41`` OPEN_SESSION_REPLY (protocol-notes.md §4.1).

    Offsets below are given relative to the start of the *payload* (i.e.
    global offset minus 8, since the caller prepends the 8-byte header
    separately via :func:`encode_header`).
    """
    payload = bytearray(22)
    payload[0] = major  # global 8
    payload[1] = minor  # global 9
    payload[2] = fw_major  # global 10
    payload[3] = fw_minor  # global 11
    # global 12-15 reserved
    payload[8:10] = readbfr.to_bytes(2, "little")  # global 16-17
    payload[10:12] = writebfr.to_bytes(2, "little")  # global 18-19
    # global 20 reserved
    payload[13] = proto  # global 21
    # global 22-24 reserved
    payload[17:21] = iana.to_bytes(4, "little")  # global 25-28
    payload[21] = len(trailing)  # global 29
    return bytes(payload) + trailing


def decode_open_session(payload: bytes) -> tuple[int, int, int, int]:
    """Parse the client's ``0x40`` OPEN_SESSION payload: (rx_timeout, tx_timeout, heartbeat, version)."""
    if len(payload) != 10:
        raise ValueError(f"OPEN_SESSION payload must be 10 bytes, got {len(payload)}")
    rx = int.from_bytes(payload[0:2], "little")
    tx = int.from_bytes(payload[2:4], "little")
    heartbeat = int.from_bytes(payload[4:6], "little")
    version = int.from_bytes(payload[6:10], "little")
    return rx, tx, heartbeat, version


def encode_status_data(type_: int, value: int) -> bytes:
    """``0x49`` STATUS_DATA payload."""
    return bytes([type_]) + value.to_bytes(4, "little")


def decode_status_data(payload: bytes) -> tuple[int, int]:
    if len(payload) != 5:
        raise ValueError(f"STATUS_DATA payload must be 5 bytes, got {len(payload)}")
    return payload[0], int.from_bytes(payload[1:5], "little")


def encode_command_written(cdb: bytes, *, device_flags: int, feature_register: int = 0) -> bytes:
    """``0x50`` COMMAND_WRITTEN payload (protocol-notes.md §4.2): a 12-byte SCSI CDB plus flags."""
    if len(cdb) != 12:
        raise ValueError(f"SCSI CDB must be exactly 12 bytes, got {len(cdb)}")
    payload = bytearray(20)
    payload[1] = feature_register  # global 9
    payload[6] = device_flags  # global 14
    payload[8:20] = cdb  # global 16..27
    return bytes(payload)


def decode_command_written(payload: bytes) -> tuple[int, bytes, int]:
    """Returns (device_flags, cdb, feature_register) from a COMMAND_WRITTEN payload."""
    if len(payload) != 20:
        raise ValueError(f"COMMAND_WRITTEN payload must be 20 bytes, got {len(payload)}")
    return payload[6], bytes(payload[8:20]), payload[1]


@dataclass(frozen=True)
class CommandEndResponse:
    """Decoded ``0x51`` COMMAND_END_RESPONSE."""

    error: bool
    device: int
    sense: int | None = None
    asc: int | None = None
    asq: int | None = None


def encode_command_end_response(*, error: bool, device: int, sense: int = 0, asc: int = 0, asq: int = 0) -> bytes:
    """``0x51`` COMMAND_END_RESPONSE payload (protocol-notes.md §4.3), 23 bytes."""
    if error:
        return bytes(12) + bytes([0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, device, 0x50, 0x00, 0x00, 0x00])
    return bytes(12) + bytes([0x87, (sense << 4) & 0xFF, 0x03, 0x00, 0x00, 0x00, device, 0x51, sense, asc, asq])


def decode_command_end_response(payload: bytes) -> CommandEndResponse:
    if len(payload) != 23:
        raise ValueError(f"COMMAND_END_RESPONSE payload must be 23 bytes, got {len(payload)}")
    marker = payload[12]
    if marker == 0xC5:
        return CommandEndResponse(error=True, device=payload[18])
    if marker == 0x87:
        return CommandEndResponse(error=False, device=payload[18], sense=payload[20], asc=payload[21], asq=payload[22])
    raise ProtocolViolation(f"unrecognised COMMAND_END_RESPONSE marker byte {marker:#x}")


@dataclass(frozen=True)
class DataToHostFrame:
    """Decoded ``0x54`` DATA_TO_HOST frame."""

    device: int
    data: bytes
    completed: bool
    dma: bool


def encode_data_to_host(device: int, data: bytes, *, completed: bool, dma: bool = False) -> bytes:
    """``0x54`` DATA_TO_HOST payload (protocol-notes.md §4.3): 26-byte prefix then the data."""
    length = len(data)
    dmalen = 0 if dma else length
    prefix = bytes(
        [
            0x00,
            length & 0xFF,
            (length >> 8) & 0xFF,
            0x00,
            0xB4 if dma else 0xB5,
            0x00,
            0x02,
            0x00,
            dmalen & 0xFF,
            (dmalen >> 8) & 0xFF,
            device & 0xFF,
            0x58,
        ]
    )
    tail = bytes([0x85, 0x00, 0x03, 0x00, 0x00, 0x00, device & 0xFF, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) if completed else bytes(14)
    return prefix + tail + data


def decode_data_to_host(payload: bytes) -> DataToHostFrame:
    if len(payload) < 26:
        raise ProtocolViolation("DATA_TO_HOST payload shorter than its 26-byte prefix")
    length = payload[1] | (payload[2] << 8)
    data = payload[26 : 26 + length]
    if len(data) != length:
        raise ProtocolViolation("DATA_TO_HOST payload truncated: declared length exceeds available data")
    return DataToHostFrame(device=payload[10], data=bytes(data), completed=payload[12] == 0x85, dma=payload[4] == 0xB4)


@dataclass(frozen=True)
class GetDataFromHostRequest:
    """Decoded ``0x52`` GET_DATA_FROM_HOST."""

    device: int
    chunk: int


def encode_get_data_from_host(device: int, chunk: int) -> bytes:
    """``0x52`` GET_DATA_FROM_HOST payload (protocol-notes.md §4.3), 23 bytes."""
    prefix = bytes([0x00, chunk & 0xFF, (chunk >> 8) & 0xFF, 0x00, 0xB5, 0x00, 0x00, 0x00, chunk & 0xFF, (chunk >> 8) & 0xFF, device & 0xFF, 0x58])
    return prefix + bytes(11)


def decode_get_data_from_host(payload: bytes) -> GetDataFromHostRequest:
    if len(payload) != 23:
        raise ValueError(f"GET_DATA_FROM_HOST payload must be 23 bytes, got {len(payload)}")
    return GetDataFromHostRequest(device=payload[10], chunk=payload[1] | (payload[2] << 8))


def encode_data_from_host(chunk: bytes) -> bytes:
    """``0x53`` DATA_FROM_HOST payload (protocol-notes.md §5.2): 6-byte prefix then the data."""
    return bytes([0x00]) + len(chunk).to_bytes(2, "little") + bytes(3) + chunk


def decode_data_from_host(payload: bytes) -> bytes:
    if len(payload) < 6:
        raise ProtocolViolation("DATA_FROM_HOST payload shorter than its 6-byte prefix")
    length = int.from_bytes(payload[1:3], "little")
    data = payload[6 : 6 + length]
    if len(data) != length:
        raise ProtocolViolation("DATA_FROM_HOST payload truncated: declared length exceeds available data")
    return bytes(data)


def encode_reset_occurred(reset_mask: int = 0) -> bytes:
    """``0x46`` RESET_OCCURRED payload: 1 byte."""
    return bytes([reset_mask])


def decode_reset_occurred(payload: bytes) -> int:
    if len(payload) != 1:
        raise ValueError(f"RESET_OCCURRED payload must be 1 byte, got {len(payload)}")
    return payload[0]


def encode_error_occurred(code: int = 0) -> bytes:
    """``0x4A`` ERROR_OCCURRED payload: 3 bytes, only the first is load-bearing here."""
    return bytes([code & 0xFF, 0x00, 0x00])


class _ResetOccurredResponse:
    """Sentinel event type: the client's ``0x47`` in reply to our ``0x46``."""


class _UnknownFrame:
    def __init__(self, cmdid: int, payload: bytes) -> None:
        self.cmdid = cmdid
        self.payload = payload

    def __repr__(self) -> str:
        return f"_UnknownFrame(cmdid={self.cmdid:#x}, payload={self.payload!r})"


def _md5(data: str) -> str:
    # MD5 is mandated by RFC 2617 digest auth as adapted for the redirection
    # plane (protocol-notes.md §3.2) -- not a security choice available to us.
    return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()


def _lp(value: str) -> bytes:
    """Encode a length-prefixed string: [1-byte len][utf-8 bytes]."""
    encoded = value.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError("length-prefixed field too long for a 1-byte length")
    return bytes([len(encoded)]) + encoded


def _parse_lp_fields(data: bytes, count: int) -> list[str]:
    fields: list[str] = []
    pos = 0
    for _field_index in range(count):
        length = data[pos]
        pos += 1
        fields.append(data[pos : pos + length].decode("utf-8", errors="replace"))
        pos += length
    return fields


class _FrameReader:
    """Blocking exact-length reads over a socket, mirroring the accumulator
    pattern in amt-ider-module.js but without needing to buffer the whole
    stream -- each handshake step and each dispatch loop iteration already
    knows exactly how many bytes it needs next."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def recv_exact(self, n: int) -> bytes:
        if n == 0:
            return b""
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise ConnectionError("peer closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


class IderMockServer:
    """Threaded mock IDE-R / redirection endpoint, playing firmware.

    Use as a context manager::

        with IderMockServer(password="test-password-not-real", readbfr=512) as server:
            connect_a_test_client(server.port)
            server.wait_for_handshake()
            server.issue_scsi(test_unit_ready_cdb())
            reply = server.next_event()

    Binds an ephemeral TCP port on 127.0.0.1 only, one session at a time.
    """

    AUTH_URI = "/RedirectionService"

    def __init__(
        self,
        *,
        username: str = "admin",
        password: str = "test-password-not-real",  # noqa: S107 -- obviously-fake fixture default
        realm: str = "mock-ider-realm",
        use_tls: bool = False,
        host: str = "127.0.0.1",
        supported_auth_types: tuple[int, ...] = (1, 3, 4),
        readbfr: int = 1024,
        writebfr: int = 1024,
        proto: int = 0,
        start_session_status: int = 0,
        feature_toggle_status: int = 1,
    ) -> None:
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        self.host = host
        self.supported_auth_types = supported_auth_types
        self.readbfr = readbfr
        self.writebfr = writebfr
        self.proto = proto
        self.start_session_status = start_session_status
        self.feature_toggle_status = feature_toggle_status

        self.port: int | None = None
        self.cert_fingerprint: str | None = None

        self._listen_sock: socket.socket | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._tls_tmpdir: tempfile.TemporaryDirectory | None = None
        self._accept_thread: threading.Thread | None = None
        self._session_thread: threading.Thread | None = None
        self._conn: socket.socket | None = None
        self._stop_event = threading.Event()

        self._events: queue.Queue = queue.Queue()
        self._handshake_event = threading.Event()
        self._handshake_error: Exception | None = None
        self._session_closed = threading.Event()

        self._out_seq = 0
        self._expected_in_seq = 0

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> IderMockServer:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, 0))
        raw_sock.listen(1)
        self.port = raw_sock.getsockname()[1]

        if self.use_tls:
            ctx, fingerprint, tmpdir = generate_self_signed_tls_context(self.host)
            self._ssl_context = ctx
            self.cert_fingerprint = fingerprint
            self._tls_tmpdir = tmpdir

        self._listen_sock = raw_sock
        self._accept_thread = threading.Thread(target=self._accept_loop, name="ider-mock-accept", daemon=True)
        self._accept_thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        for sock in (self._conn, self._listen_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5)
        if self._session_thread is not None:
            self._session_thread.join(timeout=5)
        if self._tls_tmpdir is not None:
            self._tls_tmpdir.cleanup()
            self._tls_tmpdir = None
        self._listen_sock = None
        self._accept_thread = None
        self._session_thread = None

    def __enter__(self) -> IderMockServer:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = self._listen_sock.accept()  # type: ignore[union-attr]
            except OSError:
                return
            if self._ssl_context is not None:
                try:
                    conn = self._ssl_context.wrap_socket(conn, server_side=True)
                except ssl.SSLError:
                    conn.close()
                    continue
            self._conn = conn
            self._session_thread = threading.Thread(target=self._run_session, args=(conn,), name="ider-mock-session", daemon=True)
            self._session_thread.start()
            self._session_thread.join()
            if self._stop_event.is_set():
                return

    # -- handshake -------------------------------------------------------------

    def _run_session(self, conn: socket.socket) -> None:
        self._conn = conn
        reader = _FrameReader(conn)
        try:
            self._do_handshake(conn, reader)
        except (ProtocolViolation, AuthenticationFailed, OSError, ValueError) as exc:
            self._handshake_error = exc
            self._handshake_event.set()
            self._session_closed.set()
            self._close(conn)
            return
        self._handshake_event.set()
        try:
            self._reader_loop(reader)
        finally:
            self._session_closed.set()
            self._close(conn)

    @staticmethod
    def _close(conn: socket.socket) -> None:
        try:
            conn.close()
        except OSError:
            pass

    def _read_auth_message(self, reader: _FrameReader) -> bytes:
        prefix = reader.recv_exact(9)
        data_len = int.from_bytes(prefix[5:9], "little")
        data = reader.recv_exact(data_len) if data_len else b""
        return prefix + data

    def _do_handshake(self, conn: socket.socket, reader: _FrameReader) -> None:
        # 1. Start session (protocol-notes.md §3.1).
        start = reader.recv_exact(8)
        magic = decode_start_session_request(start)
        if magic not in (b"IDER", b"SOL ", b"KVMR"):
            raise ProtocolViolation(f"unrecognised start-session magic {magic!r}")
        conn.sendall(encode_start_session_reply(status=self.start_session_status))
        if self.start_session_status != 0:
            raise ProtocolViolation("start-session status configured non-zero; handshake aborted")

        # 2. Auth-type query (protocol-notes.md §3.2).
        query = reader.recv_exact(9)
        if query[0] != 0x13:
            raise ProtocolViolation(f"expected auth-type query (0x13), got {query[0]:#x}")
        conn.sendall(encode_authenticate_reply(status=0, auth_type=0, auth_data=bytes(self.supported_auth_types)))

        # 3. Client requests digest auth (type 4).
        digest_query = self._read_auth_message(reader)
        if digest_query[4] != 0x04:
            raise ProtocolViolation("client did not request digest authentication (type 4)")

        # 4. Challenge.
        nonce = secrets.token_hex(16)
        qop = "auth"
        challenge_data = _lp(self.realm) + _lp(nonce) + _lp(qop)
        conn.sendall(encode_authenticate_reply(status=1, auth_type=4, auth_data=challenge_data))

        # 5. Verify the client's digest response.
        response_msg = self._read_auth_message(reader)
        fields = _parse_lp_fields(response_msg[9:], count=8)
        user, _realm_echo, _nonce_echo, _uri_echo, cnonce, snc, digest, qop_echo = fields
        ha1 = _md5(f"{self.username}:{self.realm}:{self.password}")
        ha2 = _md5(f"POST:{self.AUTH_URI}")
        expected = _md5(f"{ha1}:{nonce}:{snc}:{cnonce}:{qop_echo}:{ha2}")
        if user != self.username or not hmac.compare_digest(expected, digest):
            conn.sendall(encode_authenticate_reply(status=1, auth_type=4, auth_data=b""))
            raise AuthenticationFailed("redirection-plane digest response did not match")
        conn.sendall(encode_authenticate_reply(status=0, auth_type=4, auth_data=b""))

        # 6. IDE-R engine starts: general 8-byte-header framing, sequence
        # numbers reset to 0 for both directions (protocol-notes.md §4).
        header = reader.recv_exact(8)
        cmdid, _attrs, seq = decode_header(header)
        if cmdid != 0x40 or seq != 0:
            raise ProtocolViolation(f"expected OPEN_SESSION (0x40) at seq 0, got cmd={cmdid:#x} seq={seq}")
        reader.recv_exact(10)  # OPEN_SESSION payload; contents not load-bearing for the mock
        self._expected_in_seq = 1
        self._send_frame(0x41, encode_open_session_reply(readbfr=self.readbfr, writebfr=self.writebfr, proto=self.proto))

        header = reader.recv_exact(8)
        cmdid, _attrs, seq = decode_header(header)
        if cmdid != 0x48 or seq != self._expected_in_seq:
            raise ProtocolViolation(f"expected DISABLE_ENABLE_FEATURES (0x48) at seq {self._expected_in_seq}, got cmd={cmdid:#x} seq={seq}")
        reader.recv_exact(5)
        self._expected_in_seq = 2
        self._send_frame(0x49, encode_status_data(3, self.feature_toggle_status))

    def wait_for_handshake(self, timeout: float = 5.0) -> None:
        if not self._handshake_event.wait(timeout):
            raise TimeoutError("IDE-R handshake did not complete in time")
        if self._handshake_error is not None:
            raise self._handshake_error

    # -- post-handshake reader loop -------------------------------------------

    def _reader_loop(self, reader: _FrameReader) -> None:
        try:
            while not self._stop_event.is_set():
                header = reader.recv_exact(8)
                cmdid, _attrs, seq = decode_header(header)
                if seq != self._expected_in_seq:
                    self._events.put(ProtocolViolation(f"out-of-sequence frame: expected seq {self._expected_in_seq}, got {seq}"))
                    return
                self._expected_in_seq += 1

                if cmdid == 0x54:
                    prefix = reader.recv_exact(26)
                    length = prefix[1] | (prefix[2] << 8)
                    data = reader.recv_exact(length) if length else b""
                    self._events.put(decode_data_to_host(prefix + data))
                    continue

                plen = _FIXED_INBOUND_PAYLOAD_LENGTH.get(cmdid)
                if plen is None:
                    # Unknown command id: we don't know its length, so we
                    # cannot safely keep reading the stream. Surface it and stop.
                    self._events.put(_UnknownFrame(cmdid, b""))
                    return
                payload = reader.recv_exact(plen) if plen else b""

                if cmdid == 0x43:
                    return
                if cmdid == 0x44:
                    self._send_frame(0x45, b"")
                elif cmdid == 0x45:
                    pass
                elif cmdid == 0x47:
                    self._events.put(_ResetOccurredResponse())
                elif cmdid == 0x51:
                    self._events.put(decode_command_end_response(payload))
                elif cmdid == 0x52:
                    self._events.put(decode_get_data_from_host(payload))
                else:
                    self._events.put(_UnknownFrame(cmdid, payload))
        except OSError:
            return

    def _send_frame(self, cmdid: int, payload: bytes, *, completed: bool = False, dma: bool = False) -> None:
        conn = self._conn
        if conn is None:
            raise RuntimeError("no active IDE-R connection")
        header = encode_header(cmdid, self._out_seq, completed=completed, dma=dma)
        conn.sendall(header + payload)
        self._out_seq += 1

    # -- public driving API ---------------------------------------------------

    def issue_scsi(self, cdb: bytes, *, device: int = 0xA0, feature_register: int = 0) -> None:
        """Send a ``0x50`` COMMAND_WRITTEN frame at the client: ``device`` is
        ``0xA0`` (floppy/USB-R) or ``0xB0`` (CD/DVD)."""
        device_flags = 0x10 if device == 0xB0 else 0x00
        self._send_frame(0x50, encode_command_written(cdb, device_flags=device_flags, feature_register=feature_register))

    def send_data_from_host(self, data: bytes, *, frame_size: int) -> None:
        """Send ``data`` as one or more ``0x53`` DATA_FROM_HOST frames, split
        every ``frame_size`` bytes -- the multi-frame write-payload split
        described in protocol-notes.md §5.2."""
        if frame_size <= 0:
            raise ValueError("frame_size must be positive")
        if not data:
            self._send_frame(0x53, encode_data_from_host(b""))
            return
        for offset in range(0, len(data), frame_size):
            chunk = data[offset : offset + frame_size]
            self._send_frame(0x53, encode_data_from_host(chunk))

    def inject_reset_occurred(self, reset_mask: int = 0) -> None:
        self._send_frame(0x46, encode_reset_occurred(reset_mask))

    def inject_error_occurred(self, code: int = 0) -> None:
        self._send_frame(0x4A, encode_error_occurred(code))

    def inject_close(self) -> None:
        self._send_frame(0x43, b"")

    def send_bad_sequence_frame(self, cmdid: int, payload: bytes = b"") -> None:
        """Send a frame whose sequence number skips ahead, to test that a peer
        tears the session down rather than resyncing. Does not disturb the
        mock's own sequence counter."""
        conn = self._conn
        if conn is None:
            raise RuntimeError("no active IDE-R connection")
        header = encode_header(cmdid, self._out_seq + 999)
        conn.sendall(header + payload)

    def next_event(self, timeout: float = 5.0) -> object:
        """Pop the next decoded inbound event (one of ``CommandEndResponse``,
        ``DataToHostFrame``, ``GetDataFromHostRequest``, the reset-ack
        sentinel, or an exception instance if something went wrong)."""
        try:
            return self._events.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError("no IDE-R event received in time") from exc

    def read_data_to_host_stream(self, timeout: float = 5.0) -> tuple[bytes, list[bool]]:
        """Reassemble consecutive DATA_TO_HOST frames into one byte stream.

        Returns ``(data, completed_flags)`` where ``completed_flags[i]`` is
        whether frame ``i`` had the completed bit set -- a test can assert
        that only the last entry is ``True``.
        """
        chunks: list[bytes] = []
        completed_flags: list[bool] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            event = self.next_event(timeout=remaining)
            if isinstance(event, Exception):
                raise event
            if not isinstance(event, DataToHostFrame):
                raise ProtocolViolation(f"expected DATA_TO_HOST, got {event!r}")
            chunks.append(event.data)
            completed_flags.append(event.completed)
            if event.completed:
                return b"".join(chunks), completed_flags

    def session_closed(self, timeout: float = 5.0) -> bool:
        return self._session_closed.wait(timeout)

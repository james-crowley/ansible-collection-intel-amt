# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import struct

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    AuthenticationError,
    ConnectionError_,
    ProtocolError,
    TlsValidationError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection import AUTH_URI, RedirectionSession

USERNAME = "admin"
PASSWORD = "Sup3rSecret!"
REALM = "Digest:A4020000001B95000000"
NONCE = "AABBCCDD"
QOP = "auth"
FIXED_CNONCE = "0123456789abcdef0123456789abcdef"


def _lp(value: bytes) -> bytes:
    return bytes([len(value)]) + value


def _start_session_reply(*, status: int = 0, oem: bytes = b"") -> bytes:
    return bytes([0x11, status]) + bytes(10) + bytes([len(oem)]) + oem


def _auth_reply(*, status: int, auth_type: int, auth_data: bytes) -> bytes:
    return bytes([0x14, status, 0x00, 0x00, auth_type]) + struct.pack("<I", len(auth_data)) + auth_data


def _challenge_auth_data(*, realm: str = REALM, nonce: str = NONCE, qop: str = QOP) -> bytes:
    return _lp(realm.encode()) + _lp(nonce.encode()) + _lp(qop.encode())


def _success_reply() -> bytes:
    return _auth_reply(status=0, auth_type=4, auth_data=b"")


class FakeSocket:
    """An in-memory stand-in for a real socket, fed pre-scripted recv() chunks.

    ``chunks`` may split a logical message across arbitrarily many pieces to
    exercise partial-read reassembly; any bytes left unconsumed when the
    script runs out raise on the next recv() rather than blocking forever, so
    a test with a bug in its expected byte count fails loudly.
    """

    def __init__(self, chunks: list[bytes], *, peer_cert: bytes | None = None) -> None:
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False
        self._peer_cert = peer_cert

    def recv(self, bufsize: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        return chunk[:bufsize]

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def close(self) -> None:
        self.closed = True

    def getpeercert(self, binary_form: bool = False):
        return self._peer_cert


def _full_handshake_chunks(*, auth_data_after_query: bytes = b"") -> list[bytes]:
    """Byte-for-byte script for a normal type-4 handshake, as a list of whole
    messages (tests may re-chunk this to exercise fragmentation)."""
    return [
        _start_session_reply(),
        _auth_reply(status=0, auth_type=0, auth_data=bytes([1, 3, 4])),
        _auth_reply(status=1, auth_type=4, auth_data=_challenge_auth_data()),
        _success_reply(),
    ]


def _session(sock: FakeSocket, **kwargs) -> RedirectionSession:
    return RedirectionSession(
        "10.0.0.5",
        username=USERNAME,
        password=PASSWORD,
        socket_factory=lambda host, port, timeout: sock,
        **kwargs,
    )


class TestDigestComputation:
    def test_digest_matches_independently_computed_vector(self, monkeypatch):
        # Hand-computed (via hashlib directly, not through the module under
        # test) for the fixed REALM/NONCE/QOP/PASSWORD/cnonce above:
        #   HA1    = md5("admin:Digest:A4020000001B95000000:Sup3rSecret!")
        #   HA2    = md5("POST:/RedirectionService")
        #   digest = md5(HA1 + ":" + NONCE + ":00000002:" + cnonce + ":auth:" + HA2)
        ha1 = hashlib.md5(f"{USERNAME}:{REALM}:{PASSWORD}".encode(), usedforsecurity=False).hexdigest()
        ha2 = hashlib.md5(f"POST:{AUTH_URI}".encode(), usedforsecurity=False).hexdigest()
        expected_digest = hashlib.md5(f"{ha1}:{NONCE}:00000002:{FIXED_CNONCE}:{QOP}:{ha2}".encode(), usedforsecurity=False).hexdigest()
        assert expected_digest == "36bea08c3e4af74ede280bcb16f28030"  # pinned known-good value

        monkeypatch.setattr("ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection.secrets.token_hex", lambda n: FIXED_CNONCE[: n * 2])

        sock = FakeSocket(_full_handshake_chunks())
        session = _session(sock)
        session.connect()

        digest_request = sock.sent[-1]
        assert digest_request[:5] == bytes([0x13, 0x00, 0x00, 0x00, 0x04])
        fields = digest_request[9:]

        def read_field(buf: bytes, pos: int) -> tuple[str, int]:
            length = buf[pos]
            value = buf[pos + 1 : pos + 1 + length].decode()
            return value, pos + 1 + length

        pos = 0
        user, pos = read_field(fields, pos)
        realm, pos = read_field(fields, pos)
        nonce, pos = read_field(fields, pos)
        uri, pos = read_field(fields, pos)
        cnonce, pos = read_field(fields, pos)
        snc, pos = read_field(fields, pos)
        digest, pos = read_field(fields, pos)
        qop, _ = read_field(fields, pos)

        assert user == USERNAME
        assert realm == REALM
        assert nonce == NONCE
        assert uri == AUTH_URI
        assert cnonce == FIXED_CNONCE
        assert snc == "00000002"
        assert qop == QOP
        assert digest == expected_digest


class TestAuthTypeRefusal:
    def test_refuses_when_type_4_not_offered(self):
        sock = FakeSocket(
            [
                _start_session_reply(),
                _auth_reply(status=0, auth_type=0, auth_data=bytes([1, 3])),
            ]
        )
        session = _session(sock)
        with pytest.raises(AuthenticationError) as excinfo:
            session.connect()
        assert PASSWORD not in str(excinfo.value)
        assert "type 4" in excinfo.value.message or "digest" in excinfo.value.message.lower()

    @pytest.mark.parametrize("insecure_type", [1, 3])
    def test_refuses_direct_insecure_auth_type(self, insecure_type):
        # Firmware skips the type-0 capability list entirely and just
        # answers with an insecure type. Must still be refused.
        sock = FakeSocket(
            [
                _start_session_reply(),
                _auth_reply(status=1, auth_type=insecure_type, auth_data=b""),
            ]
        )
        session = _session(sock)
        with pytest.raises(AuthenticationError):
            session.connect()

    def test_never_sends_cleartext_password_frame(self):
        # Regression guard: even if refusal logic were broken, the plaintext
        # password must never appear on the wire.
        sock = FakeSocket(
            [
                _start_session_reply(),
                _auth_reply(status=0, auth_type=0, auth_data=bytes([1])),
            ]
        )
        session = _session(sock)
        with pytest.raises(AuthenticationError):
            session.connect()
        for frame in sock.sent:
            assert PASSWORD.encode() not in frame


class TestFragmentedReads:
    def test_handshake_survives_byte_at_a_time_fragmentation(self, monkeypatch):
        monkeypatch.setattr("ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection.secrets.token_hex", lambda n: FIXED_CNONCE[: n * 2])
        whole = b"".join(_full_handshake_chunks())
        # Split into single bytes to force the accumulator through every
        # possible partial-message boundary.
        sock = FakeSocket([whole[i : i + 1] for i in range(len(whole))])
        session = _session(sock)
        leftover = session.connect()
        assert leftover == b""
        assert len(sock.sent) == 4  # start frame, auth-type query, digest-type query, digest response

    def test_leftover_bytes_past_auth_success_are_returned(self, monkeypatch):
        monkeypatch.setattr("ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection.secrets.token_hex", lambda n: FIXED_CNONCE[: n * 2])
        trailing = bytes([0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # a KEEPALIVE_PING
        chunks = _full_handshake_chunks()
        chunks[-1] = chunks[-1] + trailing
        sock = FakeSocket(chunks)
        session = _session(sock)
        leftover = session.connect()
        assert leftover == trailing

    def test_oddly_split_messages_still_reassemble(self, monkeypatch):
        monkeypatch.setattr("ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection.secrets.token_hex", lambda n: FIXED_CNONCE[: n * 2])
        whole = b"".join(_full_handshake_chunks())
        # Arbitrary uneven split sizes, deliberately crossing message
        # boundaries mid-field.
        splits = [3, 1, 9, 2, 40, 5, 1000]
        chunks: list[bytes] = []
        pos = 0
        for size in splits:
            chunks.append(whole[pos : pos + size])
            pos += size
        if pos < len(whole):
            chunks.append(whole[pos:])
        sock = FakeSocket(chunks)
        session = _session(sock)
        assert session.connect() == b""


class TestStartSessionReply:
    def test_non_zero_status_aborts(self):
        sock = FakeSocket([_start_session_reply(status=1)])
        session = _session(sock)
        with pytest.raises(ProtocolError):
            session.connect()

    def test_unexpected_leading_byte_aborts(self):
        sock = FakeSocket([bytes([0x99]) + bytes(12)])
        session = _session(sock)
        with pytest.raises(ProtocolError):
            session.connect()


class TestConnectionHandling:
    def test_connection_closed_mid_handshake_raises_connection_error(self):
        sock = FakeSocket([bytes([0x11, 0x00])])  # short, then EOF
        session = _session(sock)
        with pytest.raises(ConnectionError_):
            session.connect()

    def test_default_ports(self):
        plain = RedirectionSession("h", username="u", password="p", use_tls=False, socket_factory=lambda *a: None)
        tls = RedirectionSession("h", username="u", password="p", use_tls=True, socket_factory=lambda *a: None)
        assert plain.endpoint == "h:16994"
        assert tls.endpoint == "h:16995"


class TestTlsPinning:
    def test_matching_pin_proceeds(self, monkeypatch):
        monkeypatch.setattr("ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection.secrets.token_hex", lambda n: FIXED_CNONCE[: n * 2])
        cert_der = b"fake-der-bytes"
        pin = hashlib.sha256(cert_der).hexdigest()
        sock = FakeSocket(_full_handshake_chunks(), peer_cert=cert_der)
        session = _session(sock, use_tls=True, tls_pin_sha256=pin)
        session.connect()
        assert len(sock.sent) >= 1  # handshake proceeded past the pin check

    def test_mismatched_pin_aborts_before_any_byte_is_sent(self):
        cert_der = b"fake-der-bytes"
        wrong_pin = hashlib.sha256(b"different-cert").hexdigest()
        sock = FakeSocket(_full_handshake_chunks(), peer_cert=cert_der)
        session = _session(sock, use_tls=True, tls_pin_sha256=wrong_pin)
        with pytest.raises(TlsValidationError):
            session.connect()
        assert sock.sent == []  # the non-negotiable: nothing sent before the pin check


class TestErrorsCarryNoSecrets:
    def test_every_raised_error_is_an_amt_error_with_redacted_password(self):
        sock = FakeSocket([_start_session_reply(status=1)])
        session = _session(sock)
        with pytest.raises(AmtError) as excinfo:
            session.connect()
        assert PASSWORD not in str(excinfo.value)
        assert PASSWORD not in repr(excinfo.value.to_result())

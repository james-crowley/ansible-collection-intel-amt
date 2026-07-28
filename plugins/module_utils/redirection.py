# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Intel AMT redirection-plane session handshake (SOL/IDE-R/KVM transport).

This module owns exactly the stateful handshake described in
``docs/protocol-notes.md`` section 3: connect (optionally TLS) to the
redirection port, start a redirection session, and authenticate with HTTP
Digest carried over the binary framing (RFC 2617's algorithm, not HTTP). Once
:meth:`RedirectionSession.connect` returns, the caller owns a live, authenticated
byte pipe and is expected to hand received bytes to a protocol engine such as
:mod:`ansible_collections.james_crowley.intel_amt.plugins.module_utils.ider`.

Design note on testability: everything that touches a real socket goes through
a small structural protocol (:class:`SocketLike`) and an injectable factory, so
unit tests drive the entire handshake -- including the TLS certificate pin
check -- with an in-memory fake and never open a real socket.
"""

from __future__ import annotations

import hashlib
import secrets
import socket as socket_module
import ssl
import struct
from collections.abc import Callable
from typing import Protocol

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AuthenticationError,
    ConnectionError_,
    ProtocolError,
    TimeoutError_,
    TlsValidationError,
)

#: Plain-TCP redirection port (SOL/IDE-R/KVM), no confidentiality.
REDIRECTION_PORT_PLAIN = 16994

#: TLS-wrapped redirection port.
REDIRECTION_PORT_TLS = 16995

#: The resource path Intel AMT's redirection digest uses as the "URI" in its
#: HA2 computation. It is a fixed literal, not a real HTTP request target --
#: the redirection protocol borrows RFC 2617's algorithm but is not HTTP.
AUTH_URI = "/RedirectionService"

#: Only this auth type (digest with cnonce and qop) is acceptable. Types 1
#: (cleartext) and 3 (digest without cnonce) exist on the wire and must be
#: refused, never silently used as a fallback.
_REQUIRED_AUTH_TYPE = 4
_INSECURE_AUTH_TYPES = (1, 3)

#: 8-byte StartRedirectionSession request bodies (protocol-notes.md section 3.1).
START_SESSION_IDER = bytes([0x10, 0x00, 0x00, 0x00]) + b"IDER"
START_SESSION_SOL = bytes([0x10, 0x00, 0x00, 0x00]) + b"SOL "
START_SESSION_KVM = bytes([0x10, 0x01, 0x00, 0x00]) + b"KVMR"

#: The fixed 9-byte "query supported auth types" request.
_AUTH_TYPE_QUERY = bytes([0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

#: Literal "sequence counter" for the digest reply. Per protocol-notes.md this
#: is a fixed string, not an incrementing nonce-count -- Intel AMT's
#: redirection digest never issues a second challenge in the same session.
_SNC = "00000002"

_RECV_CHUNK = 4096


class SocketLike(Protocol):
    """The minimal socket surface this module needs.

    A real ``socket.socket`` (or an ``ssl.SSLSocket`` wrapping one) satisfies
    this structurally. Tests satisfy it with an in-memory fake so the entire
    handshake can be driven without a network.
    """

    def recv(self, bufsize: int) -> bytes:
        """Receive up to ``bufsize`` bytes, or b"" once the peer has closed."""

    def sendall(self, data: bytes) -> None:
        """Send all of ``data``, blocking until it has been handed to the kernel."""

    def close(self) -> None:
        """Release the underlying descriptor. Must tolerate being called twice."""


class TlsSocketLike(SocketLike, Protocol):
    """A :class:`SocketLike` that can also produce its peer's certificate.

    Only relevant when TLS pinning is configured; matched structurally so a
    fake in tests need not subclass ``ssl.SSLSocket``.
    """

    def getpeercert(self, binary_form: bool = ...) -> object:
        """Return the peer certificate; DER bytes when ``binary_form`` is true."""


SocketFactory = Callable[[str, int, float], SocketLike]


def _md5_hex(value: str) -> str:
    """MD5 hex digest of ``value``.

    MD5 here is mandated by the RFC 2617 HTTP Digest algorithm that Intel
    AMT's redirection plane implements verbatim -- it is a wire-protocol
    requirement, not a security choice available to us. ``usedforsecurity``
    keeps this from tripping FIPS-mode OpenSSL builds or security linters that
    otherwise (correctly, in every other context) flag MD5.
    """
    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def _length_prefixed(value: bytes) -> bytes:
    """``[1-byte length][bytes]`` as used throughout the redirection wire format."""
    if len(value) > 0xFF:
        raise ProtocolError(f"value of length {len(value)} cannot be length-prefixed with a single byte")
    return bytes([len(value)]) + value


class RedirectionSession:
    """A stateful redirection-plane connection: transport + handshake only.

    This class does not speak IDE-R, SOL, or KVM itself. :meth:`connect`
    performs the session start and digest authentication, then returns any
    bytes already buffered past the authentication success message (the
    firmware is free to pack the first protocol-engine message into the same
    TCP segment as the auth reply). The caller feeds that leftover, plus
    everything subsequently read via :meth:`recv`, into a protocol engine and
    writes outbound protocol bytes with :meth:`send`.
    """

    def __init__(
        self,
        host: str,
        *,
        username: str,
        password: str,
        use_tls: bool = True,
        tls_pin_sha256: str | None = None,
        port: int | None = None,
        connect_timeout: float = 10.0,
        start_frame: bytes = START_SESSION_IDER,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._tls_pin_sha256 = tls_pin_sha256.lower().replace(":", "") if tls_pin_sha256 else None
        self._port = port if port is not None else (REDIRECTION_PORT_TLS if use_tls else REDIRECTION_PORT_PLAIN)
        self._connect_timeout = connect_timeout
        self._start_frame = start_frame
        self._socket_factory = socket_factory or self._default_socket_factory
        self._sock: SocketLike | None = None
        self._buf = bytearray()

    @property
    def endpoint(self) -> str:
        return f"{self._host}:{self._port}"

    # -- lifecycle -----------------------------------------------------

    def connect(self) -> bytes:
        """Connect, verify TLS pin (if any), start the session, and authenticate.

        Returns whatever bytes were received past the authentication-success
        message, for the caller to hand to a protocol engine before entering
        its normal receive loop.
        """
        self._sock = self._socket_factory(self._host, self._port, self._connect_timeout)
        if self._use_tls and self._tls_pin_sha256:
            # Non-negotiable: verify before a single protocol byte goes out.
            self._verify_tls_pin()
        self._send(self._start_frame)
        self._read_start_session_reply()
        self._authenticate()
        leftover = bytes(self._buf)
        self._buf.clear()
        return leftover

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    @property
    def _connected_socket(self) -> SocketLike:
        """The live socket, or a classified error if the session is not connected.

        Replaces bare ``assert`` statements: ansible-test's no-assert sanity
        rule rejects them in production code, and rightly so -- ``python -O``
        strips them, which would turn a clear invariant violation into an
        AttributeError on None much further from the cause.
        """
        if self._sock is None:
            raise ConnectionError_(
                f"redirection session to {self.endpoint} is not connected; connect() must be called first",
                endpoint=self.endpoint,
                secrets=self._password,
            )
        return self._sock

    def send(self, data: bytes) -> None:
        self._send(data)

    def recv(self, bufsize: int = _RECV_CHUNK) -> bytes:
        return self._connected_socket.recv(bufsize)

    def set_recv_timeout(self, timeout: float | None) -> None:
        """Set (or clear, with ``None``) a timeout on the underlying socket's ``recv``.

        Not needed by the handshake itself (:meth:`connect` blocks until each expected
        message arrives), but a long-lived caller that pumps :meth:`recv` in a loop --
        such as ``amt_media``'s background session process -- needs a way to wake up
        periodically (to check for a stop request, refresh a heartbeat, ...) without
        busy-polling or blocking forever on a quiet connection. A timeout firing raises
        the standard library's ``TimeoutError`` (``socket.timeout`` is an alias of it as
        of Python 3.10), which the caller distinguishes from a real transport failure.
        """
        sock = self._connected_socket
        settimeout = getattr(sock, "settimeout", None)
        if settimeout is None:
            raise ProtocolError(
                "the connected socket does not support settimeout(); cannot set a recv timeout",
                endpoint=self.endpoint,
                secrets=self._password,
            )
        settimeout(timeout)

    def peer_certificate_sha256(self) -> str | None:
        """Best-effort SHA-256 fingerprint (hex) of the connected peer's TLS leaf certificate.

        Returns ``None`` whenever the evidence is unavailable -- a plaintext connection,
        a fake socket in tests, or any extraction failure -- exactly like
        :func:`tls.peer_certificate_evidence`, whose duck-typed ``getpeercert`` access this
        mirrors. This is diagnostic colour for an operation receipt, never something to
        raise over, and it is intentionally independent of whether pinning was configured:
        :meth:`_verify_tls_pin` already did the security-relevant comparison (if any) before
        a single protocol byte was sent; this is only for a caller that wants to report what
        was actually observed.
        """
        if self._sock is None:
            return None
        getpeercert = getattr(self._sock, "getpeercert", None)
        if getpeercert is None:
            return None
        try:
            der = getpeercert(binary_form=True)
        except (ValueError, OSError):
            return None
        if not der:
            return None
        return hashlib.sha256(der).hexdigest()

    # -- socket plumbing -------------------------------------------------

    def _default_socket_factory(self, host: str, port: int, timeout: float) -> SocketLike:
        try:
            raw = socket_module.create_connection((host, port), timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError_(f"connection to {host}:{port} timed out", endpoint=f"{host}:{port}", secrets=self._password) from exc
        except OSError as exc:
            raise ConnectionError_(f"failed to connect to {host}:{port}: {exc}", endpoint=f"{host}:{port}", secrets=self._password) from exc

        if not self._use_tls:
            return raw

        ctx = ssl.create_default_context()
        if self._tls_pin_sha256:
            # AMT redirection certificates are frequently self-signed/device
            # provisioned; when the caller supplies a pin we trust that pin as
            # the sole authority and deliberately skip chain/hostname checks --
            # verified explicitly in _verify_tls_pin() before any data is sent.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            return ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLError as exc:
            raw.close()
            raise TlsValidationError(f"TLS handshake with {host}:{port} failed: {exc}", endpoint=f"{host}:{port}", secrets=self._password) from exc

    def _verify_tls_pin(self) -> None:
        sock = self._connected_socket
        getpeercert = getattr(sock, "getpeercert", None)
        if getpeercert is None:
            raise TlsValidationError(
                "TLS certificate pin was configured but the connected socket does not expose a peer certificate",
                endpoint=self.endpoint,
                secrets=self._password,
            )
        der = getpeercert(binary_form=True)
        if not der:
            raise TlsValidationError("TLS handshake completed but no peer certificate was presented", endpoint=self.endpoint, secrets=self._password)
        actual = hashlib.sha256(der).hexdigest()
        if actual != self._tls_pin_sha256:
            raise TlsValidationError(
                f"TLS peer certificate fingerprint mismatch: expected {self._tls_pin_sha256}, got {actual}",
                endpoint=self.endpoint,
                secrets=self._password,
            )

    def _send(self, data: bytes) -> None:
        sock = self._connected_socket
        try:
            sock.sendall(data)
        except TimeoutError as exc:
            raise TimeoutError_(f"sending to {self.endpoint} timed out", endpoint=self.endpoint, secrets=self._password, indeterminate=True) from exc
        except OSError as exc:
            raise ConnectionError_(f"failed sending to {self.endpoint}: {exc}", endpoint=self.endpoint, secrets=self._password) from exc

    def _fill(self, min_bytes: int) -> None:
        sock = self._connected_socket
        while len(self._buf) < min_bytes:
            try:
                chunk = sock.recv(_RECV_CHUNK)
            except TimeoutError as exc:
                raise TimeoutError_(f"timed out waiting for data from {self.endpoint}", endpoint=self.endpoint, secrets=self._password) from exc
            except OSError as exc:
                raise ConnectionError_(f"connection to {self.endpoint} failed: {exc}", endpoint=self.endpoint, secrets=self._password) from exc
            if not chunk:
                raise ConnectionError_(f"connection to {self.endpoint} closed unexpectedly", endpoint=self.endpoint, secrets=self._password)
            self._buf.extend(chunk)

    # -- session start ---------------------------------------------------

    def _read_start_session_reply(self) -> None:
        self._fill(13)
        if self._buf[0] != 0x11:
            raise ProtocolError(
                f"expected StartRedirectionSessionReply (0x11), got {self._buf[0]:#x}",
                endpoint=self.endpoint,
                secrets=self._password,
            )
        status = self._buf[1]
        if status != 0:
            raise ProtocolError(f"redirection session start rejected, status={status}", endpoint=self.endpoint, secrets=self._password)
        oemlen = self._buf[12]
        self._fill(13 + oemlen)
        del self._buf[: 13 + oemlen]

    # -- authentication ---------------------------------------------------

    def _read_auth_reply(self) -> tuple[int, int, bytes]:
        self._fill(9)
        if self._buf[0] != 0x14:
            raise ProtocolError(
                f"expected AuthenticateSessionReply (0x14), got {self._buf[0]:#x}",
                endpoint=self.endpoint,
                secrets=self._password,
            )
        status = self._buf[1]
        auth_type = self._buf[4]
        auth_data_len = struct.unpack_from("<I", self._buf, 5)[0]
        total = 9 + auth_data_len
        self._fill(total)
        auth_data = bytes(self._buf[9:total])
        del self._buf[:total]
        return status, auth_type, auth_data

    def _digest_type_query(self) -> bytes:
        user_b = self._username.encode("utf-8")
        uri_b = AUTH_URI.encode("utf-8")
        length = len(user_b) + len(uri_b) + 8
        payload = _length_prefixed(user_b) + b"\x00\x00" + _length_prefixed(uri_b) + b"\x00\x00\x00\x00"
        return bytes([0x13, 0x00, 0x00, 0x00, 0x04]) + struct.pack("<I", length) + payload

    @staticmethod
    def _parse_challenge(auth_data: bytes) -> tuple[str, str, str]:
        pos = 0

        def read_field() -> str:
            nonlocal pos
            length = auth_data[pos]
            pos += 1
            value = auth_data[pos : pos + length].decode("utf-8")
            pos += length
            return value

        realm = read_field()
        nonce = read_field()
        qop = read_field()
        return realm, nonce, qop

    def _digest_response(self, realm: str, nonce: str, qop: str) -> bytes:
        cnonce = secrets.token_hex(16)  # 32 hex characters
        ha1 = _md5_hex(f"{self._username}:{realm}:{self._password}")
        ha2 = _md5_hex(f"POST:{AUTH_URI}")
        digest = _md5_hex(f"{ha1}:{nonce}:{_SNC}:{cnonce}:{qop}:{ha2}")

        user_b = self._username.encode("utf-8")
        realm_b = realm.encode("utf-8")
        nonce_b = nonce.encode("utf-8")
        uri_b = AUTH_URI.encode("utf-8")
        cnonce_b = cnonce.encode("utf-8")
        snc_b = _SNC.encode("utf-8")
        digest_b = digest.encode("utf-8")
        qop_b = qop.encode("utf-8")

        total_len = len(user_b) + len(realm_b) + len(nonce_b) + len(uri_b) + len(cnonce_b) + len(snc_b) + len(digest_b) + 7
        total_len += len(qop_b) + 1

        payload = (
            _length_prefixed(user_b)
            + _length_prefixed(realm_b)
            + _length_prefixed(nonce_b)
            + _length_prefixed(uri_b)
            + _length_prefixed(cnonce_b)
            + _length_prefixed(snc_b)
            + _length_prefixed(digest_b)
            + _length_prefixed(qop_b)
        )
        return bytes([0x13, 0x00, 0x00, 0x00, 0x04]) + struct.pack("<I", total_len) + payload

    def _authenticate(self) -> None:
        self._send(_AUTH_TYPE_QUERY)
        status, auth_type, auth_data = self._read_auth_reply()

        if auth_type == 0:
            if _REQUIRED_AUTH_TYPE not in auth_data:
                raise AuthenticationError(
                    "firmware does not offer redirection auth type 4 (digest with cnonce/qop); "
                    "refusing to fall back to type 1 (cleartext) or type 3 (digest without cnonce)",
                    endpoint=self.endpoint,
                    secrets=self._password,
                )
            self._send(self._digest_type_query())
            status, auth_type, auth_data = self._read_auth_reply()

        if auth_type in _INSECURE_AUTH_TYPES:
            raise AuthenticationError(
                f"refusing insecure redirection auth type {auth_type} (only type 4 is accepted)",
                endpoint=self.endpoint,
                secrets=self._password,
            )

        if status == 1 and auth_type == _REQUIRED_AUTH_TYPE:
            realm, nonce, qop = self._parse_challenge(auth_data)
            self._send(self._digest_response(realm, nonce, qop))
            status, auth_type, auth_data = self._read_auth_reply()

        if status != 0:
            raise AuthenticationError("redirection digest authentication was rejected by firmware", endpoint=self.endpoint, secrets=self._password)

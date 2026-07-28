# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""TLS trust policy for the Intel AMT WS-Man management plane.

Intel AMT presents two very different TLS situations. Enterprise-provisioned
firmware can be given a CA-issued certificate and a resolvable hostname, in
which case ordinary chain and hostname verification (``ca`` mode) works the
same way it does for any other HTTPS endpoint. Everything else -- which in
practice means most AMT deployments -- has a self-signed certificate served
on a bare management IP, where chain and hostname verification cannot
succeed no matter how it is configured. For that case this module implements
exact SHA-256 leaf-certificate pinning (``fingerprint`` mode).

The two modes are mutually exclusive: a caller picks one trust decision, not
a blend of two. There is also a separate, independent gate for running
without TLS at all, because some AMT provisioning modes (see
``docs/protocol-notes.md`` s1.1) never open the TLS port and plaintext is the
only way to reach them. That gate is deliberately loud and never automatic.
"""

from __future__ import annotations

import hashlib
import re
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from requests.adapters import HTTPAdapter

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import TlsValidationError

if TYPE_CHECKING:
    import requests

#: Default WS-Man ports, per docs/protocol-notes.md s1.
DEFAULT_TLS_PORT = 16993
DEFAULT_PLAINTEXT_PORT = 16992

#: A SHA-256 digest is exactly 32 bytes, i.e. 64 hex characters.
_FINGERPRINT_HEX_LENGTH = 64
_HEX_RE = re.compile(r"^[0-9a-f]+$")

#: Short-name mapping for the RDN attribute OIDs that actually show up in AMT
#: and ordinary web-server certificates. Anything else is rendered as
#: "OID.<hex>" rather than dropped, so unexpected attributes are still visible
#: for diagnosis instead of silently disappearing.
_RDN_OID_SHORT_NAMES: dict[str, str] = {
    "550403": "CN",
    "550406": "C",
    "550407": "L",
    "550408": "ST",
    "55040a": "O",
    "55040b": "OU",
}


def normalize_fingerprint(raw: str) -> str:
    """Normalize a caller-supplied SHA-256 fingerprint to bare lowercase hex.

    Accepts colon-separated or bare hex, any case, and an optional
    ``sha256:`` prefix, because that is the range of formats a human is likely
    to copy out of a browser, ``openssl x509 -fingerprint``, or firmware's own
    admin page. Anything that is not exactly 32 bytes of hex after that
    normalisation is rejected -- a wrong-length value is almost certainly the
    wrong digest algorithm (e.g. a SHA-1 fingerprint), and accepting it would
    silently pin against something other than what the caller intended.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TlsValidationError("tls_fingerprint must be a non-empty string containing a SHA-256 hex digest")

    candidate = raw.strip().lower()
    if candidate.startswith("sha256:"):
        candidate = candidate[len("sha256:") :]
    candidate = candidate.replace(":", "").replace(" ", "")

    if len(candidate) != _FINGERPRINT_HEX_LENGTH or not _HEX_RE.match(candidate):
        raise TlsValidationError(
            "tls_fingerprint must normalize to exactly 32 bytes of hex (a SHA-256 digest); "
            f"got {len(candidate)} hex character(s) after stripping colons/whitespace and any 'sha256:' prefix"
        )
    return candidate


def resolve_port(*, port: int | None, use_tls: bool) -> int:
    """Resolve the effective WS-Man port: explicit ``port`` always wins."""
    if port is not None:
        return port
    return DEFAULT_TLS_PORT if use_tls else DEFAULT_PLAINTEXT_PORT


def enforce_transport_policy(*, use_tls: bool, allow_insecure_transport: bool) -> None:
    """Refuse plaintext WS-Man unless the caller explicitly opted in.

    ``use_tls=False`` is a legitimate, supported configuration -- some AMT
    provisioning modes never open the TLS port at all -- but it must never be
    the accidental result of a default or a typo, because HTTP Digest still
    sends credential material that an on-path attacker can recover from
    plaintext traffic. There is deliberately no probing of the TLS port to
    decide this automatically: silently downgrading would defeat the point of
    requiring acknowledgement in the first place.
    """
    if use_tls or allow_insecure_transport:
        return
    raise TlsValidationError(
        "use_tls=false requires allow_insecure_transport=true. Without TLS, HTTP Digest "
        "credentials cross the network in a form an on-path attacker can recover. Set "
        "allow_insecure_transport=true only if this endpoint is reachable solely over an "
        "isolated management VLAN and cannot be upgraded to TLS."
    )


@dataclass(frozen=True, slots=True)
class PeerCertificateEvidence:
    """Peer leaf-certificate evidence safe to embed in an operation receipt.

    Deliberately excludes anything private-key-adjacent or the full DER blob
    -- callers get exactly the fields a human or an identity check needs
    (what was observed, whose name, whose issuer, when it expires) and
    nothing that could itself be sensitive.
    """

    sha256_fingerprint: str
    subject: str | None
    issuer: str | None
    not_after: str | None


@dataclass(frozen=True, slots=True)
class TlsTrustPolicy:
    """A resolved, validated trust decision for one connection.

    Construct via :meth:`create`, not the constructor directly, so the
    mutual-exclusion check and fingerprint normalisation always run.
    """

    validate_certs: bool = True
    ca_path: str | None = None
    fingerprint: str | None = None  # normalized lowercase hex, no separators

    @classmethod
    def create(
        cls,
        *,
        validate_certs: bool = True,
        ca_path: str | None = None,
        tls_fingerprint: str | None = None,
    ) -> TlsTrustPolicy:
        if ca_path and tls_fingerprint:
            raise TlsValidationError(
                "ca_path and tls_fingerprint select mutually exclusive TLS trust modes; set only one. "
                "Use tls_fingerprint for the common case of a self-signed AMT certificate on a bare IP, "
                "or ca_path when the endpoint has a certificate issued by a CA you can supply a bundle for."
            )
        fingerprint = normalize_fingerprint(tls_fingerprint) if tls_fingerprint else None
        return cls(validate_certs=validate_certs, ca_path=ca_path, fingerprint=fingerprint)

    @property
    def pinned(self) -> bool:
        return self.fingerprint is not None

    def requests_verify(self) -> bool | str:
        """The value to hand to ``requests``' ``verify=`` keyword."""
        if self.pinned:
            # The pin *is* the trust decision; asking requests/urllib3 to also
            # demand a valid chain would just reject the self-signed
            # certificates this mode exists for.
            return False
        if not self.validate_certs:
            # Reflect the weakened posture honestly rather than silently
            # keeping a ca_path-based check alive underneath it.
            return False
        if self.ca_path:
            return self.ca_path
        return True

    def build_adapter(self) -> HTTPAdapter:
        """A ``requests`` transport adapter enforcing this policy's pinning, if any."""
        if self.fingerprint is not None:
            return FingerprintPinningAdapter(self.fingerprint)
        return HTTPAdapter()


class FingerprintPinningAdapter(HTTPAdapter):
    """A ``requests`` HTTPAdapter that pins connections to one certificate fingerprint.

    The pin is enforced *during* the TLS handshake by urllib3's
    ``assert_fingerprint`` pool option -- a mismatch aborts the connection
    before any request data is sent. This is deliberately not implemented as
    "connect, then read back the peer certificate and compare": that pattern
    authenticates nothing, because the attacker's certificate would already
    have been used to complete the handshake by the time the comparison runs.
    """

    def __init__(self, fingerprint: str, *args: Any, **kwargs: Any) -> None:
        self._fingerprint = fingerprint
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs["assert_fingerprint"] = self._fingerprint
        # Chain/hostname verification is off: the fingerprint is the trust
        # decision, and AMT's self-signed certificates would otherwise fail
        # chain validation regardless of the pin outcome.
        kwargs["cert_reqs"] = ssl.CERT_NONE
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy: str, **kwargs: Any) -> Any:
        kwargs["assert_fingerprint"] = self._fingerprint
        kwargs["cert_reqs"] = ssl.CERT_NONE
        return super().proxy_manager_for(proxy, **kwargs)


def peer_certificate_evidence(response: requests.Response) -> PeerCertificateEvidence | None:
    """Best-effort peer-certificate evidence for the connection behind ``response``.

    Returns ``None`` whenever the evidence is unavailable (plaintext
    connection, a mocked transport in tests, or any extraction failure) --
    this is diagnostic colour for a receipt, not something worth failing an
    operation over.
    """
    sock = _peer_socket(response)
    if sock is None:
        return None
    try:
        der = sock.getpeercert(binary_form=True)
    except (ValueError, OSError):
        return None
    if not der:
        return None

    fingerprint = hashlib.sha256(der).hexdigest()
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None

    try:
        validated = sock.getpeercert()
    except ValueError:
        # Raised by the ssl module when the peer certificate was never
        # validated (our own pinned mode runs with cert_reqs=CERT_NONE) --
        # fall back to parsing the raw DER bytes below.
        validated = None

    if validated:
        subject = _format_rdn_sequence(validated.get("subject"))
        issuer = _format_rdn_sequence(validated.get("issuer"))
        not_after = validated.get("notAfter")
    else:
        parsed = _parse_der_certificate(der)
        if parsed is not None:
            subject, issuer, not_after = parsed

    return PeerCertificateEvidence(sha256_fingerprint=fingerprint, subject=subject, issuer=issuer, not_after=not_after)


def _peer_socket(response: requests.Response) -> Any:
    # Duck-typed on `getpeercert` rather than `isinstance(sock, ssl.SSLSocket)`:
    # a plaintext connection's raw socket has no such method, which is
    # exactly the signal needed here, and it lets tests substitute a
    # lightweight fake without constructing a real TLS socket.
    raw = getattr(response, "raw", None)
    connection = getattr(raw, "_connection", None) if raw is not None else None
    sock = getattr(connection, "sock", None)
    return sock if callable(getattr(sock, "getpeercert", None)) else None


def _format_rdn_sequence(rdns: Any) -> str | None:
    """Render the dict-form ``getpeercert()`` subject/issuer tuples as ``CN=x,O=y``."""
    if not rdns:
        return None
    short_names = {
        "commonName": "CN",
        "organizationName": "O",
        "organizationalUnitName": "OU",
        "countryName": "C",
        "stateOrProvinceName": "ST",
        "localityName": "L",
    }
    parts = [f"{short_names.get(key, key)}={value}" for rdn in rdns for key, value in rdn]
    return ",".join(parts)


# --- Minimal DER/X.509 decoding -------------------------------------------
#
# Only used when chain validation is off (fingerprint-pinned connections), in
# which case the ssl module refuses to hand back the parsed dict form of the
# peer certificate. This collection deliberately depends on nothing beyond
# the standard library (see requirements.txt), so rather than add a
# certificate-parsing dependency for three display fields, this decodes just
# enough of the ASN.1 DER structure of an X.509 certificate to read the
# issuer, subject, and notAfter. Any failure degrades to `None` fields --
# this is informational evidence for a receipt, not something to raise over.


def _der_read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value at ``offset``; return (tag, value, next_offset)."""
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte & 0x80:
        num_length_bytes = length_byte & 0x7F
        length = int.from_bytes(data[offset : offset + num_length_bytes], "big")
        offset += num_length_bytes
    else:
        length = length_byte
    value = data[offset : offset + length]
    return tag, value, offset + length


def _der_iter_children(content: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, value, offset = _der_read_tlv(content, offset)
        children.append((tag, value))
    return children


def _der_decode_string(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace")


def _der_decode_time(tag: int, value: bytes) -> str | None:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    try:
        if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            rest = text[2:]
        else:  # GeneralizedTime: YYYYMMDDHHMMSSZ
            year = int(text[0:4])
            rest = text[4:]
        month, day, hour, minute, second = (int(rest[i : i + 2]) for i in (0, 2, 4, 6, 8))
    except (ValueError, IndexError):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"


def _parse_name(name_content: bytes) -> str:
    parts: list[str] = []
    for _rdn_tag, rdn_value in _der_iter_children(name_content):  # each RDN is a SET
        for _atv_tag, atv_value in _der_iter_children(rdn_value):  # each attribute is a SEQUENCE
            attribute = _der_iter_children(atv_value)
            if len(attribute) != 2:
                continue
            (_oid_tag, oid_value), (_str_tag, str_value) = attribute
            short_name = _RDN_OID_SHORT_NAMES.get(oid_value.hex(), f"OID.{oid_value.hex()}")
            parts.append(f"{short_name}={_der_decode_string(str_value)}")
    return ",".join(parts)


def _parse_der_certificate(der: bytes) -> tuple[str | None, str | None, str | None] | None:
    """Best-effort extraction of (subject, issuer, not_after) from a DER X.509 certificate."""
    try:
        _, certificate_content, _ = _der_read_tlv(der, 0)
        _, tbs_content, _ = _der_read_tlv(certificate_content, 0)
        fields = _der_iter_children(tbs_content)

        index = 0
        if fields[index][0] == 0xA0:  # optional [0] version
            index += 1
        index += 2  # serialNumber, signature AlgorithmIdentifier
        issuer_tag, issuer_content = fields[index]
        index += 1
        _validity_tag, validity_content = fields[index]
        index += 1
        subject_tag, subject_content = fields[index]

        if issuer_tag != 0x30 or subject_tag != 0x30:
            return None

        issuer = _parse_name(issuer_content)
        subject = _parse_name(subject_content)

        validity_fields = _der_iter_children(validity_content)
        not_after_tag, not_after_value = validity_fields[1]
        not_after = _der_decode_time(not_after_tag, not_after_value)
    except (IndexError, ValueError):
        return None
    return subject or None, issuer or None, not_after

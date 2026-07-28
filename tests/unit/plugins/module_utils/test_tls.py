# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import ssl
from unittest.mock import Mock

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import TlsValidationError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.tls import (
    DEFAULT_PLAINTEXT_PORT,
    DEFAULT_TLS_PORT,
    FingerprintPinningAdapter,
    PeerCertificateEvidence,
    TlsTrustPolicy,
    enforce_transport_policy,
    normalize_fingerprint,
    peer_certificate_evidence,
    resolve_port,
)

VALID_FINGERPRINT = "aa" * 32  # 32 bytes of hex, i.e. a plausible SHA-256 digest


def _der(tag: int, content: bytes) -> bytes:
    """Minimal DER TLV encoder, just enough to build a fake certificate for tests."""
    length = len(content)
    if length < 0x80:
        length_bytes = bytes([length])
    else:
        size = (length.bit_length() + 7) // 8
        length_bytes = bytes([0x80 | size]) + length.to_bytes(size, "big")
    return bytes([tag]) + length_bytes + content


def _rdn(oid_hex: str, value: str) -> bytes:
    attribute = _der(0x30, _der(0x06, bytes.fromhex(oid_hex)) + _der(0x0C, value.encode()))
    return _der(0x31, attribute)  # RDN is a SET containing one AttributeTypeAndValue


def build_fake_der_certificate(*, subject_cn: str, issuer_cn: str, not_after: str) -> bytes:
    """Hand-build a minimal DER X.509 certificate for exercising the fallback parser.

    Real certificates are far larger; this includes only the fields
    tls._parse_der_certificate reads (issuer, validity, subject), which is
    exactly the situation the parser must cope with when chain validation is
    off and the ssl module refuses to hand back the parsed dict form.
    """
    serial = _der(0x02, b"\x01")
    signature_algorithm = _der(0x30, b"")
    issuer = _der(0x30, _rdn("550403", issuer_cn))  # 2.5.4.3 = commonName
    subject = _der(0x30, _rdn("550403", subject_cn))
    validity = _der(0x30, _der(0x17, b"250101000000Z") + _der(0x17, not_after.encode()))
    subject_public_key_info = _der(0x30, b"")
    tbs_certificate = _der(0x30, serial + signature_algorithm + issuer + validity + subject + subject_public_key_info)
    return _der(0x30, tbs_certificate)


def _fake_response(sock: object) -> Mock:
    response = Mock()
    response.raw._connection.sock = sock
    return response


class TestNormalizeFingerprint:
    @pytest.mark.parametrize(
        "raw",
        [
            "aa" * 32,
            "AA" * 32,
            ":".join(["aa"] * 32),
            "sha256:" + "aa" * 32,
            "SHA256:" + ("AA:" * 31 + "AA"),
            "  " + "aa" * 32 + "  ",
        ],
    )
    def test_accepted_forms_normalize_to_bare_lowercase_hex(self, raw):
        # All of these are the same 32-byte digest spelled the way a human
        # might actually copy it from a browser, openssl, or firmware's UI.
        assert normalize_fingerprint(raw) == "aa" * 32

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "zz" * 32,  # not hex
            "aa" * 20,  # SHA-1 length (40 hex chars) -- wrong algorithm, not just wrong length
            "aa" * 31,  # one byte short
            "aa" * 33,  # one byte long
            "sha256:",  # prefix with nothing after it
            "aa" * 32 + "!",
        ],
    )
    def test_malformed_input_is_rejected(self, raw):
        with pytest.raises(TlsValidationError):
            normalize_fingerprint(raw)

    @pytest.mark.parametrize("raw", [None, 12345, [1, 2, 3]])
    def test_non_string_input_is_rejected(self, raw):
        with pytest.raises(TlsValidationError):
            normalize_fingerprint(raw)


class TestResolvePort:
    def test_explicit_port_always_wins(self):
        assert resolve_port(port=9999, use_tls=True) == 9999
        assert resolve_port(port=9999, use_tls=False) == 9999

    def test_default_tls_port(self):
        assert resolve_port(port=None, use_tls=True) == DEFAULT_TLS_PORT == 16993

    def test_default_plaintext_port(self):
        assert resolve_port(port=None, use_tls=False) == DEFAULT_PLAINTEXT_PORT == 16992


class TestInsecureTransportGate:
    def test_tls_enabled_never_checks_the_flag(self):
        # use_tls=True is always fine, regardless of allow_insecure_transport.
        enforce_transport_policy(use_tls=True, allow_insecure_transport=False)

    def test_plaintext_acknowledged_is_permitted(self):
        enforce_transport_policy(use_tls=False, allow_insecure_transport=True)

    def test_plaintext_without_acknowledgement_is_refused(self):
        with pytest.raises(TlsValidationError) as excinfo:
            enforce_transport_policy(use_tls=False, allow_insecure_transport=False)
        # The message must name the exact flag to set, not just describe the
        # problem -- an operator debugging this needs the fix, not a riddle.
        assert "allow_insecure_transport" in str(excinfo.value)
        assert excinfo.value.error_class == "tls_validation"


class TestTlsTrustPolicy:
    def test_ca_path_and_fingerprint_are_mutually_exclusive(self):
        with pytest.raises(TlsValidationError):
            TlsTrustPolicy.create(ca_path="/etc/ssl/amt-ca.pem", tls_fingerprint=VALID_FINGERPRINT)

    def test_fingerprint_mode_is_normalized_and_marks_pinned(self):
        policy = TlsTrustPolicy.create(tls_fingerprint="AA:" * 31 + "AA")
        assert policy.pinned
        assert policy.fingerprint == "aa" * 32

    def test_ca_mode_is_not_pinned(self):
        policy = TlsTrustPolicy.create(ca_path="/etc/ssl/amt-ca.pem")
        assert not policy.pinned

    def test_default_mode_uses_system_trust(self):
        policy = TlsTrustPolicy.create()
        assert policy.requests_verify() is True

    def test_pinned_mode_disables_requests_own_verification(self):
        # The pin *is* the trust decision -- asking requests to also demand a
        # valid chain would reject exactly the self-signed certs this mode
        # exists for.
        policy = TlsTrustPolicy.create(tls_fingerprint=VALID_FINGERPRINT)
        assert policy.requests_verify() is False

    def test_ca_path_is_passed_through_as_verify_bundle(self):
        policy = TlsTrustPolicy.create(ca_path="/etc/ssl/amt-ca.pem")
        assert policy.requests_verify() == "/etc/ssl/amt-ca.pem"

    def test_validate_certs_false_honestly_disables_verification_even_with_ca_path(self):
        # validate_certs=False must weaken the policy, not be silently
        # overridden by a ca_path that happens to also be set.
        policy = TlsTrustPolicy.create(validate_certs=False, ca_path="/etc/ssl/amt-ca.pem")
        assert policy.requests_verify() is False

    def test_build_adapter_returns_fingerprint_adapter_only_when_pinned(self):
        pinned = TlsTrustPolicy.create(tls_fingerprint=VALID_FINGERPRINT)
        unpinned = TlsTrustPolicy.create()
        assert isinstance(pinned.build_adapter(), FingerprintPinningAdapter)
        assert not isinstance(unpinned.build_adapter(), FingerprintPinningAdapter)


class TestFingerprintPinningAdapter:
    def test_assert_fingerprint_reaches_the_pool_manager(self):
        # This is the actual security property: the pin must be handed to
        # urllib3's PoolManager so it authenticates the handshake itself,
        # not something we check after the fact.
        adapter = FingerprintPinningAdapter(VALID_FINGERPRINT)
        assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == VALID_FINGERPRINT
        assert adapter.poolmanager.connection_pool_kw["cert_reqs"] == ssl.CERT_NONE

    def test_proxy_manager_also_receives_the_pin(self):
        adapter = FingerprintPinningAdapter(VALID_FINGERPRINT)
        proxy_manager = adapter.proxy_manager_for("http://proxy.example:3128")
        assert proxy_manager.connection_pool_kw["assert_fingerprint"] == VALID_FINGERPRINT


class TestPeerCertificateEvidence:
    def test_plaintext_socket_yields_no_evidence(self):
        # A plain socket has no getpeercert method at all; this must degrade
        # to None rather than raise.
        response = _fake_response(sock=object())
        assert peer_certificate_evidence(response) is None

    def test_missing_raw_response_yields_no_evidence(self):
        response = Mock(spec=[])
        assert peer_certificate_evidence(response) is None

    def test_empty_certificate_yields_no_evidence(self):
        sock = Mock()
        sock.getpeercert.side_effect = lambda binary_form=False: b"" if binary_form else {}
        response = _fake_response(sock)
        assert peer_certificate_evidence(response) is None

    def test_validated_chain_uses_the_parsed_dict_form(self):
        # CA mode: chain validation succeeded, so ssl's own parsed dict form
        # is available and preferred over DER parsing.
        der = build_fake_der_certificate(subject_cn="amt.example", issuer_cn="Example CA", not_after="300101000000Z")

        def fake_getpeercert(binary_form=False):
            if binary_form:
                return der
            return {
                "subject": ((("commonName", "amt.example"),),),
                "issuer": ((("commonName", "Example CA"),),),
                "notAfter": "Jan  1 00:00:00 2030 GMT",
            }

        sock = Mock()
        sock.getpeercert.side_effect = fake_getpeercert
        response = _fake_response(sock)

        evidence = peer_certificate_evidence(response)
        assert isinstance(evidence, PeerCertificateEvidence)
        assert evidence.subject == "CN=amt.example"
        assert evidence.issuer == "CN=Example CA"
        assert evidence.not_after == "Jan  1 00:00:00 2030 GMT"
        assert evidence.sha256_fingerprint  # exact value covered by the DER-fallback test below

    def test_pinned_unvalidated_connection_falls_back_to_der_parsing(self):
        # Fingerprint mode runs with cert_reqs=CERT_NONE, so ssl.getpeercert()
        # (dict form) raises ValueError -- ssl actually does this for an
        # unverified peer. This is the path that matters most: it is
        # precisely the AMT self-signed/bare-IP case this collection targets.
        der = build_fake_der_certificate(subject_cn="10.0.0.5", issuer_cn="10.0.0.5", not_after="300615120000Z")

        def fake_getpeercert(binary_form=False):
            if binary_form:
                return der
            raise ValueError("certificate is not available for verify_mode CERT_NONE")

        sock = Mock()
        sock.getpeercert.side_effect = fake_getpeercert
        response = _fake_response(sock)

        evidence = peer_certificate_evidence(response)
        assert evidence is not None
        assert evidence.subject == "CN=10.0.0.5"
        assert evidence.issuer == "CN=10.0.0.5"
        assert evidence.not_after == "2030-06-15T12:00:00Z"

        import hashlib

        assert evidence.sha256_fingerprint == hashlib.sha256(der).hexdigest()

    def test_der_parse_failure_degrades_to_none_fields_not_an_exception(self):
        garbage = b"\x00\x01\x02not-a-certificate"

        def fake_getpeercert(binary_form=False):
            if binary_form:
                return garbage
            raise ValueError("unverified")

        sock = Mock()
        sock.getpeercert.side_effect = fake_getpeercert
        response = _fake_response(sock)

        evidence = peer_certificate_evidence(response)
        # The fingerprint is still computable (it is just a hash of the
        # bytes), even though nothing else could be parsed out of garbage.
        assert evidence is not None
        assert evidence.subject is None
        assert evidence.issuer is None
        assert evidence.not_after is None

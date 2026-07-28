# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Stable error classification and secret redaction for Intel AMT operations.

Every failure surfaced by this collection carries one of the classes in
:class:`ErrorClass`. Callers -- including the surrounding lifecycle automation
that drives bare-metal installs -- branch on these strings, so they are part of
the public contract and must not be renamed or repurposed.

The other job of this module is redaction. AMT failures are diagnosed from SOAP
bodies, HTTP headers, and raw protocol dumps, all of which routinely contain
credentials. Nothing in this collection should ever construct a user-visible
message without passing it through :func:`redact`.
"""

from __future__ import annotations

import re


class ErrorClass:
    """Stable, machine-readable failure classes.

    Deliberately a plain class of string constants rather than an enum: these
    values cross the boundary into Ansible module results as JSON strings, and
    an enum only adds conversion noise at every return site.
    """

    CONNECTION = "connection"
    TLS_VALIDATION = "tls_validation"
    AUTHENTICATION = "authentication"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    INVALID_STATE = "invalid_state"
    TIMEOUT = "timeout"
    PROTOCOL = "protocol"
    REMOTE_OPERATION = "remote_operation"
    IDENTITY_MISMATCH = "identity_mismatch"

    ALL = (
        CONNECTION,
        TLS_VALIDATION,
        AUTHENTICATION,
        UNSUPPORTED_CAPABILITY,
        INVALID_STATE,
        TIMEOUT,
        PROTOCOL,
        REMOTE_OPERATION,
        IDENTITY_MISMATCH,
    )


#: Maximum length of any diagnostic excerpt embedded in an error. AMT can return
#: large SOAP faults and IDE-R dumps are unbounded; neither belongs in a task
#: result in full.
MAX_DIAGNOSTIC_BYTES = 2048

_REDACTED = "[REDACTED]"

# Patterns are applied in order. Each must keep the surrounding structure intact
# so the redacted text is still useful for diagnosis -- we want to preserve
# "which field was present", while destroying its value.
_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Credential-bearing headers, quoted form first (e.g. inside a repr'd dict:
    # {'Authorization': 'Digest ...'}). Consuming only to the matching quote
    # keeps the surrounding structure readable.
    (
        re.compile(r"(?i)\b(authorization|proxy-authorization|set-cookie|cookie)(\W{0,3}\s*[:=]\s*)(['\"])(?:(?!\3).)*\3"),
        r"\1\2\3" + _REDACTED + r"\3",
    ),
    # Unquoted header form (e.g. a raw HTTP header line). The entire value is
    # taken to end of line: an Authorization value has no non-secret prefix worth
    # preserving, and stopping early is how partial credentials leak.
    (
        re.compile(r"(?i)^(\s*)(authorization|proxy-authorization|set-cookie|cookie)(\s*:\s*)[^\r\n]+", re.MULTILINE),
        r"\1\2\3" + _REDACTED,
    ),
    (
        re.compile(r"(?i)\b(authorization|proxy-authorization|set-cookie|cookie)(\s*:\s*)[^\r\n]+"),
        r"\1\2" + _REDACTED,
    ),
    # Digest auth sub-fields that individually leak credential material. The
    # optional quote before the separator handles a quoted key, as produced by
    # repr() of a dict: {'response': '...'}.
    (
        re.compile(r"(?i)\b(response|cnonce|nonce|opaque)(['\"]?\s*[:=]\s*)(['\"]?)[^\s,;'\"]+\3"),
        r"\1\2\3" + _REDACTED + r"\3",
    ),
    # Generic secret-bearing keys in JSON, kwargs, or query strings. The optional
    # quote before the separator is what makes the quoted-key form work, e.g.
    # repr() output like {'password': 'x'} -- without it the pattern only matched
    # bare-key forms such as password=x.
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|passphrase|api[_-]?key|token|apikey)(['\"]?\s*[:=]\s*)(['\"]?)[^\s,;&}'\"]*\3"),
        r"\1\2\3" + _REDACTED + r"\3",
    ),
    # XML/SOAP elements whose names suggest secrets, e.g. <AdminPassword>x</AdminPassword>
    # and Intel's DigestPassword / MEBxPassword properties.
    (
        re.compile(r"(?is)<([a-z0-9_:.-]*(?:password|secret|passphrase|token|key)[a-z0-9_:.-]*)>.*?</\1>"),
        r"<\1>" + _REDACTED + r"</\1>",
    ),
    # userinfo embedded in a URL: scheme://user:pass@host
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@"),
        r"\1\2:" + _REDACTED + "@",
    ),
)


def redact(text: object, extra_secrets: object = None) -> str:
    """Return ``text`` with credential material removed and length bounded.

    Args:
        text: Any object; coerced with :func:`str`. ``None`` becomes ``""``.
        extra_secrets: Optional literal value, or iterable of values, to remove
            by exact substring match. Pass the actual password here so that a
            credential echoed verbatim by firmware in an unexpected shape is
            still caught, rather than relying only on the patterns above.

    The literal replacement happens *first*, so a password that happens to look
    like structure cannot survive by being reshaped by a later pattern.
    """
    if text is None:
        return ""

    result = text if isinstance(text, str) else str(text)

    if extra_secrets:
        secrets: list[str] = []
        if isinstance(extra_secrets, (str, bytes)):
            secrets = [extra_secrets if isinstance(extra_secrets, str) else extra_secrets.decode("utf-8", "replace")]
        else:
            try:
                for item in extra_secrets:
                    if item is None:
                        continue
                    secrets.append(item if isinstance(item, str) else str(item))
            except TypeError:
                secrets = [str(extra_secrets)]

        # Longest first: replacing a short secret that is a substring of a longer
        # one would otherwise leave fragments of the longer secret behind.
        for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
            result = result.replace(secret, _REDACTED)

    for pattern, replacement in _REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)

    if len(result) > MAX_DIAGNOSTIC_BYTES:
        omitted = len(result) - MAX_DIAGNOSTIC_BYTES
        result = f"{result[:MAX_DIAGNOSTIC_BYTES]}... [truncated, {omitted} more characters]"

    return result


class AmtError(Exception):
    """Base failure carrying everything a module needs for ``fail_json``.

    Modules should catch this, then hand :meth:`to_result` straight to
    ``fail_json`` rather than reformatting, so classification and redaction stay
    consistent across every module.
    """

    #: Subclasses override this. The base class is intentionally the vaguest
    #: class rather than something more specific that could be wrong.
    error_class = ErrorClass.PROTOCOL

    def __init__(
        self,
        message: str,
        *,
        endpoint: str | None = None,
        operation: str | None = None,
        diagnostic: object = None,
        secrets: object = None,
        indeterminate: bool = False,
        return_value: int | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.operation = operation
        self.indeterminate = indeterminate
        self.return_value = return_value
        self.message = redact(message, secrets)
        self.diagnostic = redact(diagnostic, secrets) if diagnostic is not None else None
        super().__init__(self.message)

    def to_result(self) -> dict[str, object]:
        """Render as a dict suitable for ``AnsibleModule.fail_json(**result)``."""
        result: dict[str, object] = {
            "msg": self.message,
            "error_class": self.error_class,
        }
        if self.endpoint is not None:
            result["endpoint"] = self.endpoint
        if self.operation is not None:
            result["operation"] = self.operation
        if self.diagnostic:
            result["diagnostic"] = self.diagnostic
        if self.return_value is not None:
            result["return_value"] = self.return_value
        if self.indeterminate:
            # Signals to the caller that the mutation may have taken effect and
            # must be re-probed rather than retried.
            result["indeterminate"] = True
        return result

    def __repr__(self) -> str:
        return f"{type(self).__name__}(error_class={self.error_class!r}, message={self.message!r})"


class ConnectionError_(AmtError):
    """TCP or DNS level failure: refused, unreachable, unresolvable, port closed.

    Named with a trailing underscore to avoid shadowing the builtin
    ``ConnectionError``, which callers may still want to catch separately.
    """

    error_class = ErrorClass.CONNECTION


class TlsValidationError(AmtError):
    """Certificate chain or hostname verification failed, fingerprint mismatched,
    or plaintext transport was requested without explicit acknowledgement."""

    error_class = ErrorClass.TLS_VALIDATION


class AuthenticationError(AmtError):
    """Credentials rejected: HTTP 401, or redirection-plane digest refusal."""

    error_class = ErrorClass.AUTHENTICATION


class UnsupportedCapabilityError(AmtError):
    """Firmware does not implement the requested feature, or a required
    instance (such as a boot source) is absent or ambiguous."""

    error_class = ErrorClass.UNSUPPORTED_CAPABILITY


class InvalidStateError(AmtError):
    """The operation is not legal from the endpoint's current state."""

    error_class = ErrorClass.INVALID_STATE


class TimeoutError_(AmtError):
    """Operation timed out.

    ``indeterminate`` distinguishes the two cases that matter operationally: a
    timeout *before* the request was transmitted is a safe, retryable failure,
    while a timeout *after* transmission means the mutation may have been
    applied. Only the caller can decide what to do about the latter, and it must
    re-probe rather than retry.
    """

    error_class = ErrorClass.TIMEOUT


class ProtocolError(AmtError):
    """Malformed SOAP, bad IDE-R framing, or an out-of-sequence message."""

    error_class = ErrorClass.PROTOCOL


class RemoteOperationError(AmtError):
    """The request was well-formed and accepted, but AMT returned a non-zero
    ``ReturnValue``."""

    error_class = ErrorClass.REMOTE_OPERATION


class IdentityMismatchError(AmtError):
    """Observed endpoint evidence disagrees with the reviewed inventory binding.

    Raised before any mutation. Guards against power-cycling the wrong machine
    when inventory and reality have drifted apart.
    """

    error_class = ErrorClass.IDENTITY_MISMATCH


#: Mapping from class string back to exception type, for reconstructing an error
#: from a serialized receipt.
ERROR_CLASS_TO_EXCEPTION: dict[str, type[AmtError]] = {
    ErrorClass.CONNECTION: ConnectionError_,
    ErrorClass.TLS_VALIDATION: TlsValidationError,
    ErrorClass.AUTHENTICATION: AuthenticationError,
    ErrorClass.UNSUPPORTED_CAPABILITY: UnsupportedCapabilityError,
    ErrorClass.INVALID_STATE: InvalidStateError,
    ErrorClass.TIMEOUT: TimeoutError_,
    ErrorClass.PROTOCOL: ProtocolError,
    ErrorClass.REMOTE_OPERATION: RemoteOperationError,
    ErrorClass.IDENTITY_MISMATCH: IdentityMismatchError,
}

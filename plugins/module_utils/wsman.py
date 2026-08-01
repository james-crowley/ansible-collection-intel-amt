# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""WS-Man transport for the Intel AMT management plane.

Implements the SOAP envelope shape, resource URI conventions, and
Get/Put/Enumerate-Pull/method-invoke operations described in
``docs/protocol-notes.md`` s2. This module owns exactly one thing: turning
Ansible-module-shaped requests ("get me AMT_BootSettingData", "invoke
RequestPowerStateChange with these parameters") into SOAP over HTTP Digest,
and turning the SOAP response (or transport failure) back into either a
parsed result or one of :mod:`errors`'s classified exceptions.

Deliberately stdlib-only for XML (``xml.etree.ElementTree``) per
``requirements.txt`` -- AMT's WS-Man responses are small and come from an
already-authenticated endpoint, so the extra dependency surface of lxml buys
nothing here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree as ET

try:
    import requests
    from requests.auth import HTTPDigestAuth

    HAS_REQUESTS = True
    REQUESTS_IMPORT_ERROR: str | None = None
except ImportError as _import_error:  # pragma: no cover - exercised by the import sanity test
    # See the equivalent guard in tls.py. Modules must check HAS_REQUESTS and
    # fail with missing_required_lib('requests') so the user gets an actionable
    # message instead of a traceback.
    requests = None  # type: ignore[assignment]
    HTTPDigestAuth = None  # type: ignore[assignment,misc]
    HAS_REQUESTS = False
    REQUESTS_IMPORT_ERROR = str(_import_error)

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import tls
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    AuthenticationError,
    ConnectionError_,
    ProtocolError,
    RemoteOperationError,
    TimeoutError_,
    TlsValidationError,
)

NS_SOAP = "http://www.w3.org/2003/05/soap-envelope"
NS_ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
NS_WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_ENUMERATION = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

#: The DMTF "common" namespace that wraps a CIM ``datetime`` value. Not one of the
#: three class-resource bases above, and not derivable from a class name -- it is
#: the namespace of the *inner* ``<Datetime>``/``<Interval>`` elements that a CIM
#: datetime property is built from, per docs/protocol-notes.md s2.10.
NS_CIM_COMMON = "http://schemas.dmtf.org/wbem/wscim/1/common"

ACTION_GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
ACTION_PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
ACTION_DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"

_REPLY_TO_ANONYMOUS = f"{NS_ADDRESSING}/role/anonymous"

#: Resource URI base per class prefix. See docs/protocol-notes.md s2.2.
_RESOURCE_URI_BASE: dict[str, str] = {
    "CIM": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/",
    "AMT": "http://intel.com/wbem/wscim/1/amt-schema/1/",
    "IPS": "http://intel.com/wbem/wscim/1/ips-schema/1/",
}

#: How many items to request per Pull. AMT's WS-Man implementation is small
#: and local; there is no benefit to tuning this per class.
_PULL_MAX_ELEMENTS = 64

ET.register_namespace("s", NS_SOAP)
ET.register_namespace("a", NS_ADDRESSING)
ET.register_namespace("w", NS_WSMAN)
ET.register_namespace("wsen", NS_ENUMERATION)


def resource_uri(class_name: str) -> str:
    """Resolve the full ResourceURI for a ``CIM_``/``AMT_``/``IPS_`` class name."""
    prefix = class_name.split("_", 1)[0]
    base = _RESOURCE_URI_BASE.get(prefix)
    if base is None:
        raise ValueError(f"unrecognised resource class {class_name!r}: expected a CIM_, AMT_, or IPS_ prefixed name")
    return f"{base}{class_name}"


@dataclass(frozen=True, slots=True)
class EndpointReference:
    """A WS-Addressing EPR naming one instance, for use as a method input parameter.

    Matches the exact body shape in docs/protocol-notes.md s2.5 (Address +
    ReferenceParameters/ResourceURI/SelectorSet), which ``amt_boot`` needs for
    ``ChangeBootOrder`` and ``RequestPowerStateChange``'s ``ManagedElement``.
    """

    resource_class: str
    selectors: dict[str, str]

    def build_elements(self) -> list[ET.Element]:
        address = ET.Element(f"{{{NS_ADDRESSING}}}Address")
        address.text = NS_ADDRESSING
        reference_parameters = ET.Element(f"{{{NS_ADDRESSING}}}ReferenceParameters")
        resource_uri_el = ET.SubElement(reference_parameters, f"{{{NS_WSMAN}}}ResourceURI")
        resource_uri_el.text = resource_uri(self.resource_class)
        selector_set_el = ET.SubElement(reference_parameters, f"{{{NS_WSMAN}}}SelectorSet")
        for name, value in self.selectors.items():
            selector_el = ET.SubElement(selector_set_el, f"{{{NS_WSMAN}}}Selector")
            selector_el.set("Name", name)
            selector_el.text = value
        return [address, reference_parameters]


@dataclass(frozen=True, slots=True)
class EmbeddedInstance:
    """A method parameter that is a nested property bag, not a scalar.

    Some AMT methods take an **embedded instance** rather than flat scalars:
    ``AMT_AlarmClockService.AddAlarm``'s only input is an ``AlarmTemplate`` whose
    children are ``IPS_AlarmClockOccurrence`` properties, two of which
    (``StartTime``, ``Interval``) are themselves wrappers around a
    :data:`NS_CIM_COMMON` element. See docs/protocol-notes.md s2.10.

    ``namespace`` governs this instance's **children**, not its own tag -- the tag
    is named by whatever namespace the enclosing element used, exactly as
    :class:`EndpointReference` returns children and lets the caller name the
    wrapper. That is what makes the three-namespace ``AddAlarm`` body expressible
    by nesting these: the outer parameter's tag is in the ``AMT_`` method
    namespace, its children in the ``IPS_`` one, and their children in the DMTF
    common one.

    A property whose value is ``None`` is **omitted entirely**, matching
    :meth:`WsmanClient._append_params`' existing rule for flat parameters and for
    the same hardware-verified reason recorded there: firmware rejects an empty
    element where it accepts an absent one.
    """

    namespace: str
    properties: dict[str, Any]


def build_selector_set(selectors: dict[str, str]) -> ET.Element:
    """Build a ``<w:SelectorSet>`` header element from a name->value mapping."""
    selector_set = ET.Element(f"{{{NS_WSMAN}}}SelectorSet")
    for name, value in selectors.items():
        selector = ET.SubElement(selector_set, f"{{{NS_WSMAN}}}Selector")
        selector.set("Name", name)
        selector.text = value
    return selector_set


def build_envelope(
    *,
    action: str,
    to: str,
    resource_uri_value: str,
    body: ET.Element | None = None,
    selectors: dict[str, str] | None = None,
    message_id: str | None = None,
    operation_timeout: str = "PT60S",
) -> ET.Element:
    """Build a SOAP envelope matching docs/protocol-notes.md s2.3 exactly."""
    envelope = ET.Element(f"{{{NS_SOAP}}}Envelope")
    header = ET.SubElement(envelope, f"{{{NS_SOAP}}}Header")

    action_el = ET.SubElement(header, f"{{{NS_ADDRESSING}}}Action")
    action_el.set(f"{{{NS_SOAP}}}mustUnderstand", "true")
    action_el.text = action

    to_el = ET.SubElement(header, f"{{{NS_ADDRESSING}}}To")
    to_el.set(f"{{{NS_SOAP}}}mustUnderstand", "true")
    to_el.text = to

    resource_uri_el = ET.SubElement(header, f"{{{NS_WSMAN}}}ResourceURI")
    resource_uri_el.set(f"{{{NS_SOAP}}}mustUnderstand", "true")
    resource_uri_el.text = resource_uri_value

    message_id_el = ET.SubElement(header, f"{{{NS_ADDRESSING}}}MessageID")
    message_id_el.set(f"{{{NS_SOAP}}}mustUnderstand", "true")
    # Fresh per request, per the note that reusing a constant is "sloppy" --
    # deliberately not defaulted to a module-level constant.
    message_id_el.text = message_id if message_id is not None else f"uuid:{uuid.uuid4()}"

    reply_to_el = ET.SubElement(header, f"{{{NS_ADDRESSING}}}ReplyTo")
    address_el = ET.SubElement(reply_to_el, f"{{{NS_ADDRESSING}}}Address")
    address_el.text = _REPLY_TO_ANONYMOUS

    timeout_el = ET.SubElement(header, f"{{{NS_WSMAN}}}OperationTimeout")
    timeout_el.text = operation_timeout

    if selectors:
        header.append(build_selector_set(selectors))

    body_el = ET.SubElement(envelope, f"{{{NS_SOAP}}}Body")
    if body is not None:
        body_el.append(body)

    return envelope


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _namespace(tag: str) -> str | None:
    return tag[1 : tag.index("}")] if tag.startswith("{") else None


def _iter_by_local_name(element: ET.Element, name: str) -> Any:
    return (child for child in element.iter() if _local_name(child.tag) == name)


def _find_by_local_name(element: ET.Element, name: str) -> ET.Element | None:
    return next(_iter_by_local_name(element, name), None)


def _element_to_value(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        return (element.text or "").strip()
    result: dict[str, Any] = {}
    for child in children:
        key = _local_name(child.tag)
        value = _element_to_value(child)
        if key not in result:
            result[key] = value
        elif isinstance(result[key], list):
            result[key].append(value)
        else:
            result[key] = [result[key], value]
    return result


def _coerce_param_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class WsmanClient:
    """A WS-Man client for one Intel AMT endpoint's management plane.

    Owns the ``requests.Session``, HTTP Digest auth, and TLS trust
    enforcement for that session. Use :meth:`from_connection_options` to
    build one directly from the option names in
    ``plugins/doc_fragments/connection.py``, or the constructor directly (as
    the unit tests do) when a pre-built :class:`tls.TlsTrustPolicy` is
    already in hand.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool = True,
        allow_insecure_transport: bool = False,
        trust_policy: tls.TlsTrustPolicy | None = None,
        connect_timeout: float = 10.0,
        timeout: float = 30.0,
        max_retries: int = 2,
        session: requests.Session | None = None,
    ) -> None:
        # Enforced here rather than only in from_connection_options() so the gate
        # cannot be sidestepped by constructing the client directly. The point of
        # the policy is that plaintext is never selected implicitly, and a gate
        # that only guards one of two entry points does not achieve that.
        tls.enforce_transport_policy(use_tls=use_tls, allow_insecure_transport=allow_insecure_transport)

        self._endpoint = f"{host}:{port}"
        scheme = "https" if use_tls else "http"
        self._url = f"{scheme}://{host}:{port}/wsman"
        self._password = password
        self._connect_timeout = connect_timeout
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._headers = {"Content-Type": "application/soap+xml;charset=UTF-8"}

        self._session = session if session is not None else requests.Session()
        self._session.auth = HTTPDigestAuth(username, password)

        policy = trust_policy if trust_policy is not None else tls.TlsTrustPolicy.create()
        if use_tls:
            self._session.mount("https://", policy.build_adapter())
            self._session.verify = policy.requests_verify()

        #: Evidence from the most recently completed request, for callers
        #: building an OperationReceipt. `None` until a request has
        #: completed, or if the transport gave no way to observe it (e.g.
        #: plaintext, or a mocked session in tests).
        self.last_peer_certificate: tls.PeerCertificateEvidence | None = None

    @classmethod
    def from_connection_options(
        cls,
        *,
        host: str,
        port: int | None,
        username: str,
        password: str,
        use_tls: bool = True,
        allow_insecure_transport: bool = False,
        validate_certs: bool = True,
        ca_path: str | None = None,
        tls_fingerprint: str | None = None,
        timeout: float = 30.0,
        connect_timeout: float = 10.0,
        max_retries: int = 2,
        session: requests.Session | None = None,
    ) -> WsmanClient:
        """Build a client directly from the ``connection.py`` doc-fragment option names.

        Resolves the trust policy and port before any connection is attempted, so
        a misconfiguration fails before a single byte goes on the wire. The
        insecure-transport gate is enforced by ``__init__``.
        """
        policy = tls.TlsTrustPolicy.create(validate_certs=validate_certs, ca_path=ca_path, tls_fingerprint=tls_fingerprint)
        resolved_port = tls.resolve_port(port=port, use_tls=use_tls)
        return cls(
            host=host,
            port=resolved_port,
            username=username,
            password=password,
            use_tls=use_tls,
            allow_insecure_transport=allow_insecure_transport,
            trust_policy=policy,
            connect_timeout=connect_timeout,
            timeout=timeout,
            max_retries=max_retries,
            session=session,
        )

    @property
    def endpoint(self) -> str:
        """The ``host:port`` this client talks to, for embedding in operation receipts."""
        return self._endpoint

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> WsmanClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- Public operations --------------------------------------------------

    def get(self, resource_class: str, *, selectors: dict[str, str] | None = None) -> dict[str, Any]:
        """``Get`` -- read one instance. Safe to retry: no state is mutated."""
        body_el = self._execute(
            action=ACTION_GET,
            resource_uri_value=resource_uri(resource_class),
            selectors=selectors,
            body=None,
            operation=f"Get {resource_class}",
            retryable=True,
        )
        return self._single_instance(body_el)

    def put(self, resource_class: str, properties: dict[str, Any], *, selectors: dict[str, str] | None = None) -> dict[str, Any]:
        """``Put`` -- replace one instance. Never retried: it is a mutation."""
        uri = resource_uri(resource_class)
        body = ET.Element(f"{{{uri}}}{resource_class}")
        self._append_params(body, uri, properties)
        body_el = self._execute(
            action=ACTION_PUT,
            resource_uri_value=uri,
            selectors=selectors,
            body=body,
            operation=f"Put {resource_class}",
            retryable=False,
        )
        return self._single_instance(body_el)

    def delete(self, resource_class: str, *, selectors: dict[str, str] | None = None) -> None:
        """``Delete`` -- destroy the one instance ``selectors`` names. Never retried.

        WS-Transfer ``Delete`` carries an **empty SOAP Body**; the instance is named
        entirely by the ``SelectorSet`` header, which is why ``selectors`` is the only
        input. A firmware that answers at all answers with an empty body too (the
        vendor's captured ``DeleteResponse`` has ``<a:Body></a:Body>``), so there is
        nothing to parse and nothing to return -- a caller that wants to know the
        instance is gone must re-read, exactly as with every other mutation here.

        Not retryable, for the ordinary mutation reason: a retry after a response was
        lost would delete an instance a *different* caller had since recreated under
        the same key.
        """
        self._execute(
            action=ACTION_DELETE,
            resource_uri_value=resource_uri(resource_class),
            selectors=selectors,
            body=None,
            operation=f"Delete {resource_class}",
            retryable=False,
        )

    def enumerate(self, resource_class: str, *, selectors: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """``Enumerate`` then ``Pull`` until exhausted. Safe to retry per request."""
        uri = resource_uri(resource_class)
        enumerate_body = ET.Element(f"{{{NS_ENUMERATION}}}Enumerate")
        body_el = self._execute(
            action=ACTION_ENUMERATE,
            resource_uri_value=uri,
            selectors=selectors,
            body=enumerate_body,
            operation=f"Enumerate {resource_class}",
            retryable=True,
        )
        context_el = _find_by_local_name(body_el, "EnumerationContext")
        context = context_el.text if context_el is not None else None

        items: list[dict[str, Any]] = []
        while context:
            pull_body = ET.Element(f"{{{NS_ENUMERATION}}}Pull")
            context_param = ET.SubElement(pull_body, f"{{{NS_ENUMERATION}}}EnumerationContext")
            context_param.text = context
            max_elements = ET.SubElement(pull_body, f"{{{NS_ENUMERATION}}}MaxElements")
            max_elements.text = str(_PULL_MAX_ELEMENTS)

            pull_response = self._execute(
                action=ACTION_PULL,
                resource_uri_value=uri,
                body=pull_body,
                operation=f"Pull {resource_class}",
                retryable=True,
            )
            items_el = _find_by_local_name(pull_response, "Items")
            if items_el is not None:
                items.extend(_element_to_value(child) for child in items_el)

            end_of_sequence = _find_by_local_name(pull_response, "EndOfSequence")
            next_context_el = _find_by_local_name(pull_response, "EnumerationContext")
            context = next_context_el.text if (end_of_sequence is None and next_context_el is not None) else None

        return items

    def invoke(
        self,
        resource_class: str,
        method_name: str,
        params: dict[str, Any] | None = None,
        *,
        selectors: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Invoke a method. Never retried: methods change firmware state.

        Raises :class:`RemoteOperationError` if AMT accepts the request but
        reports a non-zero ``ReturnValue``. On success, returns
        ``(output_parameters, 0)``.
        """
        uri = resource_uri(resource_class)
        input_el = ET.Element(f"{{{uri}}}{method_name}_INPUT")
        self._append_params(input_el, uri, params or {})

        body_el = self._execute(
            action=f"{uri}/{method_name}",
            resource_uri_value=uri,
            selectors=selectors,
            body=input_el,
            operation=f"{resource_class}.{method_name}",
            retryable=False,
        )
        output = self._single_instance(body_el)
        return_value = self._extract_return_value(output)
        if return_value != 0:
            raise RemoteOperationError(
                f"{resource_class}.{method_name} returned ReturnValue={return_value}",
                endpoint=self._endpoint,
                operation=f"{resource_class}.{method_name}",
                return_value=return_value,
                secrets=self._password,
            )
        return output, return_value

    # -- Internals ------------------------------------------------------------

    def _append_params(self, parent: ET.Element, uri: str, params: dict[str, Any]) -> None:
        for name, value in params.items():
            if isinstance(value, EndpointReference):
                param_el = ET.SubElement(parent, f"{{{uri}}}{name}")
                for child in value.build_elements():
                    param_el.append(child)
            elif isinstance(value, EmbeddedInstance):
                # The element is named in the *enclosing* namespace (`uri`); its
                # children are named in the instance's own. See EmbeddedInstance.
                param_el = ET.SubElement(parent, f"{{{uri}}}{name}")
                self._append_params(param_el, value.namespace, value.properties)
            elif value is None:
                # Omitted entirely, not emitted empty. Real AMT 16.1.30 rejects
                # ChangeBootOrder with an empty <Source/> element:
                #
                #   HTTP 400 -- "The supplied SOAP violates the corresponding
                #   XML schema definition."
                #
                # Source is typed as an endpoint reference, so it requires
                # Address and ReferenceParameters children; an empty element is
                # schema-invalid, whereas an absent one is fine because these
                # method parameters are optional (minOccurs=0). "Pass a null
                # Source" in the protocol notes means send no element at all,
                # which is also what MeshCmd does when it passes null.
                continue
            else:
                param_el = ET.SubElement(parent, f"{{{uri}}}{name}")
                param_el.text = _coerce_param_text(value)

    def _single_instance(self, body_el: ET.Element) -> dict[str, Any]:
        children = list(body_el)
        if not children:
            return {}
        value = _element_to_value(children[0])
        return value if isinstance(value, dict) else {}

    def _extract_return_value(self, output: dict[str, Any]) -> int:
        raw = output.get("ReturnValue")
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    def _execute(
        self,
        *,
        action: str,
        resource_uri_value: str,
        body: ET.Element | None,
        operation: str,
        selectors: dict[str, str] | None = None,
        retryable: bool = False,
    ) -> ET.Element:
        envelope = build_envelope(action=action, to=self._url, resource_uri_value=resource_uri_value, body=body, selectors=selectors)
        payload = ET.tostring(envelope, encoding="utf-8")

        attempts_allowed = self._max_retries + 1 if retryable else 1
        attempt = 0
        while True:
            attempt += 1
            try:
                response = self._session.post(
                    self._url,
                    data=payload,
                    headers=self._headers,
                    timeout=(self._connect_timeout, self._timeout),
                )
            except requests.exceptions.ReadTimeout as exc:
                # The body was already on the wire when this fired: AMT may
                # have applied a mutation before failing to reply. Never
                # retried, regardless of `retryable` -- a caller must re-probe
                # state, not resend a possibly-already-applied request.
                raise TimeoutError_(
                    f"{operation} timed out waiting for a response after the request was sent",
                    endpoint=self._endpoint,
                    operation=operation,
                    indeterminate=True,
                    secrets=self._password,
                ) from exc
            except requests.exceptions.SSLError as exc:
                raise TlsValidationError(
                    f"TLS handshake failed for {operation}: {exc}",
                    endpoint=self._endpoint,
                    operation=operation,
                    secrets=self._password,
                ) from exc
            except requests.exceptions.ConnectTimeout as exc:
                classified: AmtError = TimeoutError_(
                    f"{operation} timed out connecting before the request was sent",
                    endpoint=self._endpoint,
                    operation=operation,
                    indeterminate=False,
                    secrets=self._password,
                )
                if attempt >= attempts_allowed:
                    raise classified from exc
                continue
            except requests.exceptions.ConnectionError as exc:
                classified = ConnectionError_(
                    f"{operation} failed to connect: {exc}",
                    endpoint=self._endpoint,
                    operation=operation,
                    secrets=self._password,
                )
                if attempt >= attempts_allowed:
                    raise classified from exc
                continue
            else:
                return self._handle_response(response, operation=operation)

    def _handle_response(self, response: requests.Response, *, operation: str) -> ET.Element:
        # Best-effort: never let evidence collection break the operation
        # whose result it is merely annotating.
        try:
            self.last_peer_certificate = tls.peer_certificate_evidence(response)
        except Exception:
            # Diagnostic best-effort: a failure here must never mask the real
            # result of the operation (see pyproject.toml's BLE001 rationale).
            self.last_peer_certificate = None

        if response.status_code == 401:
            raise AuthenticationError(
                f"AMT rejected the credentials for {operation} (HTTP 401)",
                endpoint=self._endpoint,
                operation=operation,
                secrets=self._password,
            )
        if not response.ok:
            raise ProtocolError(
                f"{operation} received unexpected HTTP status {response.status_code}",
                endpoint=self._endpoint,
                operation=operation,
                diagnostic=response.text,
                secrets=self._password,
            )

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            raise ProtocolError(
                f"{operation} received malformed SOAP: {exc}",
                endpoint=self._endpoint,
                operation=operation,
                diagnostic=response.text,
                secrets=self._password,
            ) from exc

        if _local_name(root.tag) != "Envelope" or _namespace(root.tag) != NS_SOAP:
            raise ProtocolError(
                f"{operation} response root is not a SOAP Envelope",
                endpoint=self._endpoint,
                operation=operation,
                diagnostic=response.text,
                secrets=self._password,
            )

        body_el = root.find(f"{{{NS_SOAP}}}Body")
        if body_el is None:
            raise ProtocolError(
                f"{operation} response has no SOAP Body",
                endpoint=self._endpoint,
                operation=operation,
                diagnostic=response.text,
                secrets=self._password,
            )

        self._raise_for_fault(body_el, operation=operation)
        return body_el

    def _raise_for_fault(self, body_el: ET.Element, *, operation: str) -> None:
        fault = _find_by_local_name(body_el, "Fault")
        if fault is None:
            return
        code_el = _find_by_local_name(fault, "Value")
        reason_el = _find_by_local_name(fault, "Text")
        code = code_el.text if code_el is not None else "unknown"
        reason = reason_el.text if reason_el is not None else "unknown"
        raise ProtocolError(
            f"{operation}: SOAP Fault code={code} reason={reason}",
            endpoint=self._endpoint,
            operation=operation,
            diagnostic=ET.tostring(fault, encoding="unicode"),
            secrets=self._password,
        )

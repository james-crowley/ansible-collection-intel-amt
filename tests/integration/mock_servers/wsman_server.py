# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deterministic mock WS-Man endpoint for integration testing.

There is no Intel AMT hardware in CI (see ``docs/testing.md``), so this server
stands in for firmware's WS-Management plane (``docs/protocol-notes.md`` §2).
It is deliberately standard-library only: ``http.server`` for the HTTP/TLS
listener, ``xml.etree.ElementTree`` for SOAP, ``hashlib``/``hmac`` for HTTP
Digest. Test-side HTTP clients (``requests``) are fine; the *server* itself
must not gain a runtime dependency the collection does not already have.

External dependency: TLS mode shells out to the ``openssl`` CLI to generate a
throw-away self-signed certificate at start-up. Pure-stdlib certificate
generation is not practical (the ``ssl`` module can consume certs but not
mint them), and adding the ``cryptography`` package as a dependency here
would leak into ``tests/integration/requirements.txt`` for a capability we
only need transiently. ``openssl`` is assumed present on the CI image
(it is, on ``cimg/python``) and on any reasonable developer machine.

Design notes for reviewers:

* Every fault-injection knob lives on ``WsmanMockServer.faults`` (a
  :class:`FaultConfig`) and ``WsmanMockServer.state`` (an :class:`AmtState`),
  both mutable for the lifetime of the running server, so a test can arm a
  fault, make one request, then disarm it and keep using the same server.
* ``timeout_before_read`` / ``timeout_after_read`` and ``force_status`` are
  one-shot: they fire once then reset themselves, matching how a test uses
  them ("the next request should see X"). Per-resource faults
  (``return_value_for``, ``soap_fault_for``, ``malformed_xml_for``,
  ``http_status_for``) are persistent sets/dicts a test adds to and removes
  from explicitly, because they are usually armed for the duration of one
  assertion block rather than "the next call".
* State mutations happen under a single lock because ``ThreadingHTTPServer``
  dispatches concurrent requests onto separate threads and the whole point of
  the boot-settings/power-state fixtures is that they are observable
  cross-request state, not per-request scratch data.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------
# WS-Man / SOAP constants (docs/protocol-notes.md §2.2-2.3)
# --------------------------------------------------------------------------

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_A = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
NS_W = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

ACTION_GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
ACTION_GET_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
ACTION_PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
ACTION_PUT_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse"
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
ACTION_PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
ACTION_PULL_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse"
ACTION_FAULT = "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault"

CIM_BASE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2"
AMT_BASE = "http://intel.com/wbem/wscim/1/amt-schema/1"

CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE = f"{CIM_BASE}/CIM_AssociatedPowerManagementService"
CIM_POWER_MANAGEMENT_SERVICE = f"{CIM_BASE}/CIM_PowerManagementService"
CIM_BOOT_CONFIG_SETTING = f"{CIM_BASE}/CIM_BootConfigSetting"
CIM_BOOT_SERVICE = f"{CIM_BASE}/CIM_BootService"
CIM_BOOT_SOURCE_SETTING = f"{CIM_BASE}/CIM_BootSourceSetting"
CIM_COMPUTER_SYSTEM = f"{CIM_BASE}/CIM_ComputerSystem"
AMT_BOOT_SETTING_DATA = f"{AMT_BASE}/AMT_BootSettingData"
AMT_BOOT_CAPABILITIES = f"{AMT_BASE}/AMT_BootCapabilities"
AMT_REDIRECTION_SERVICE = f"{AMT_BASE}/AMT_RedirectionService"
AMT_GENERAL_SETTINGS = f"{AMT_BASE}/AMT_GeneralSettings"
AMT_SETUP_AND_CONFIGURATION_SERVICE = f"{AMT_BASE}/AMT_SetupAndConfigurationService"

#: Fields firmware reports on Get but rejects if echoed back on Put
#: (docs/protocol-notes.md §2.5). This is the single most important fault this
#: mock implements: it is the only way to test that a client actually applies
#: the delete-list rather than doing a naive read-modify-write.
READONLY_BOOT_FIELDS = frozenset(
    {
        "WinREBootEnabled",
        "UEFILocalPBABootEnabled",
        "UEFIHTTPSBootEnabled",
        "SecureBootControlEnabled",
        "BootguardStatus",
        "OptionsCleared",
        "BIOSLastStatus",
        "UefiBootParametersArray",
    }
)

BOOT_SOURCE_NAMES = (
    "Intel(r) AMT: Force PXE Boot",
    "Intel(r) AMT: Force Hard-drive Boot",
    "Intel(r) AMT: Force CD/DVD Boot",
    "Intel(r) AMT: Force Diagnostic Boot",
    "Intel(r) AMT: Force USB Boot",
)

#: RequestPowerStateChange action code -> resulting CIM_AssociatedPowerManagementService.PowerState
#: (docs/protocol-notes.md §2.4). Codes 5 (power cycle) and 10 (reset) both end powered-on.
POWER_ACTION_TO_STATE = {2: 2, 3: 3, 4: 4, 5: 2, 7: 7, 8: 8, 10: 2}


class _UnknownResource(Exception):
    """Raised internally when no handler exists for a (ResourceURI, Action) pair."""


def _default_boot_setting_data() -> dict[str, object]:
    """The instance a freshly-started mock reports for ``AMT_BootSettingData``.

    Includes the read-only fields real firmware reports on Get (see
    ``READONLY_BOOT_FIELDS``) so that a client under test must actively strip
    them, exactly as it would have to against real hardware.
    """
    return {
        "InstanceID": "Intel(r) AMT: Boot Configuration 0",
        "ElementName": "Intel(r) AMT Boot Configuration Data",
        "ConfigurationDataReset": False,
        "BIOSPause": False,
        "BIOSSetup": False,
        "BootMediaIndex": 0,
        "EnforceSecureBoot": False,
        "FirmwareVerbosity": 0,
        "ForcedProgressEvents": False,
        "IDERBootDevice": 0,
        "LockKeyboard": False,
        "LockPowerButton": False,
        "LockResetButton": False,
        "LockSleepButton": False,
        "ReflashBIOS": False,
        "UseIDER": False,
        "UseSOL": False,
        "UseSafeMode": False,
        "UserPasswordBypass": False,
        "SecureErase": False,
        "PlatformErase": False,
        # Read-only on real firmware -- must be deleted before Put.
        "WinREBootEnabled": False,
        "UEFILocalPBABootEnabled": False,
        "UEFIHTTPSBootEnabled": False,
        "SecureBootControlEnabled": False,
        "BootguardStatus": 0,
        "OptionsCleared": True,
        "BIOSLastStatus": [0, 0],
        "UefiBootParametersArray": [],
        "UefiBootNumberOfParams": 0,
    }


@dataclass
class AmtState:
    """Mutable firmware-like state. A `Put` or method call here is what makes
    a later `Get` observe the change -- the whole reason this is a stateful
    mock rather than a table of canned strings."""

    power_state: int = 2  # CIM PowerState: 2 = On
    redirection_enabled_state: int = 32768  # disabled
    redirection_listener_enabled: bool = False
    boot_config_role: int = 0
    boot_order_source: str | None = None
    boot_source_count: int = 5
    digest_realm: str = "Digest:A4000000000000000000000000000000"
    boot_setting_data: dict[str, object] = field(default_factory=_default_boot_setting_data)


@dataclass
class FaultConfig:
    """Every fault-injection knob the mock understands. All mutable in place
    on a running server -- see the module docstring for the one-shot vs.
    persistent distinction."""

    #: Toggle for the read-only-field Put rejection. Default on: this is what
    #: real firmware does, and turning it off is the exception, not the rule.
    reject_boot_readonly_fields: bool = True

    #: One-shot: hang before ever reading the request body.
    timeout_before_read: bool = False
    #: One-shot: read the full body, then hang before writing any response.
    timeout_after_read: bool = False
    #: Set by the handler after a timeout fault fires, so a test can assert
    #: which of the two actually happened.
    last_timeout_body_was_read: bool | None = None

    #: One-shot: short-circuit the very next request to this HTTP status,
    #: bypassing auth and dispatch entirely.
    force_status: int | None = None

    #: Persistent, keyed by (resource_uri, action): force this AMT ReturnValue
    #: on a method call instead of running its normal side effect.
    return_value_for: dict[tuple[str, str], int] = field(default_factory=dict)
    #: Persistent: respond with a SOAP s:Fault instead of the normal body.
    soap_fault_for: set[tuple[str, str]] = field(default_factory=set)
    #: Persistent: respond 200 with deliberately truncated/invalid XML.
    malformed_xml_for: set[tuple[str, str]] = field(default_factory=set)
    #: Persistent: respond with an arbitrary HTTP status (e.g. 401, 500) for a
    #: specific (resource_uri, action) once authenticated and parsed.
    http_status_for: dict[tuple[str, str], int] = field(default_factory=dict)


def _child_text(elem: ET.Element | None, local_name: str) -> str | None:
    """Find the first descendant whose tag local-name matches, return its text.

    WS-Man method INPUT bodies are namespaced by resource URI, which varies
    per call site, so matching on local name (ignoring the namespace) is far
    less brittle here than building a namespace map per resource.
    """
    if elem is None:
        return None
    for child in elem.iter():
        if child.tag.rsplit("}", 1)[-1] == local_name:
            return child.text
    return None


def _extract_instance_id(elem: ET.Element | None) -> str | None:
    """Find a ``<Selector Name="InstanceID">`` inside an endpoint reference."""
    if elem is None:
        return None
    for candidate in elem.iter():
        if candidate.tag.rsplit("}", 1)[-1] == "Selector" and candidate.attrib.get("Name") == "InstanceID":
            return candidate.text
    return None


def _value_to_xml(tag: str, value: object) -> str:
    """Render one AMT/CIM property as XML, matching the shapes firmware uses.

    Booleans render lowercase; array properties render as repeated elements
    (or nothing, if empty, which is how firmware represents an absent array);
    everything else renders as escaped text.
    """
    if isinstance(value, bool):
        return f"<r:{tag}>{'true' if value else 'false'}</r:{tag}>"
    if isinstance(value, (list, tuple)):
        return "".join(f"<r:{tag}>{escape(str(v))}</r:{tag}>" for v in value)
    if value is None:
        return ""
    return f"<r:{tag}>{escape(str(value))}</r:{tag}>"


def _fields_to_instance_xml(resource_uri: str, fields: dict[str, object]) -> str:
    class_name = resource_uri.rsplit("/", 1)[-1]
    inner = "".join(_value_to_xml(k, v) for k, v in fields.items())
    return f'<r:{class_name} xmlns:r="{resource_uri}">{inner}</r:{class_name}>'


def _envelope(action: str, relates_to: str | None, body: str, *, resource_uri: str | None = None) -> str:
    new_id = f"uuid:{uuid.uuid4()}"
    resource_hdr = f"<w:ResourceURI>{escape(resource_uri)}</w:ResourceURI>" if resource_uri else ""
    relates_hdr = f"<a:RelatesTo>{escape(relates_to)}</a:RelatesTo>" if relates_to else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{NS_S}" xmlns:a="{NS_A}" xmlns:w="{NS_W}">'
        "<s:Header>"
        f'<a:Action s:mustUnderstand="true">{escape(action)}</a:Action>'
        f"<a:To>{NS_A}/role/anonymous</a:To>"
        f"{resource_hdr}"
        f"<a:MessageID>{new_id}</a:MessageID>"
        f"{relates_hdr}"
        "</s:Header>"
        f"<s:Body>{body}</s:Body>"
        "</s:Envelope>"
    )


def _fault_body(subcode: str, reason: str) -> str:
    return (
        "<s:Fault>"
        "<s:Code><s:Value>s:Receiver</s:Value>"
        f"<s:Subcode><s:Value>w:{escape(subcode)}</s:Value></s:Subcode></s:Code>"
        f'<s:Reason><s:Text xml:lang="en-US">{escape(reason)}</s:Text></s:Reason>'
        "</s:Fault>"
    )


# --------------------------------------------------------------------------
# Resource GET handlers
# --------------------------------------------------------------------------


def _get_power(state: AmtState) -> dict[str, object]:
    return {
        "PowerState": state.power_state,
        "ElementName": "ManagedSystem Power Management Service",
    }


def _get_boot_capabilities(_state: AmtState) -> dict[str, object]:
    return {
        "ElementName": "Intel(r) AMT Boot Capabilities",
        "IDER": True,
        "SOL": True,
        "BIOSReflash": False,
        "BIOSSetup": True,
        "BIOSPause": True,
        "ForcePXEBoot": True,
        "ForceHardDriveBoot": True,
        "ForceHardDriveSafeModeBoot": False,
        "ForceDiagnosticBoot": True,
        "ForceCDorDVDBoot": True,
        "VerbosityScreenBlank": True,
        "PowerButtonLock": True,
        "ResetButtonLock": True,
        "KeyboardLock": True,
        "SleepButtonLock": True,
        "UserPasswordBypass": True,
        "ForcedProgressEvents": True,
        "SecureErase": False,
    }


def _get_redirection(state: AmtState) -> dict[str, object]:
    return {
        "ElementName": "Intel(r) AMT Redirection Service",
        "EnabledState": state.redirection_enabled_state,
        "ListenerEnabled": state.redirection_listener_enabled,
    }


def _get_general_settings(state: AmtState) -> dict[str, object]:
    return {
        "ElementName": "Intel(r) AMT General Settings",
        "InstanceID": "Intel(r) AMT: General Settings",
        "NetworkInterfaceEnabled": True,
        "DigestRealm": state.digest_realm,
        "HostName": "mock-amt-host",
        "DomainName": "example.invalid",
        "PingResponseEnabled": True,
        "SharedFQDN": True,
        "AMTNetworkEnabled": 1,
        "RmcpPingResponseEnabled": True,
        "PreferredAddressFamily": 0,
    }


def _get_setup_and_configuration_service(_state: AmtState) -> dict[str, object]:
    return {
        "ElementName": "Intel(r) AMT Setup and Configuration Service",
        "InstanceID": "Intel(r) AMT: Setup and Configuration Service",
        "ProvisioningState": 2,
        "ZeroTouchConfigurationEnabled": False,
        "ProvisioningMode": 1,
        "ProvisioningServerOTP": "",
        "PasswordModel": 0,
        "DhcpDNSSuffix": "",
    }


def _get_computer_system(_state: AmtState) -> dict[str, object]:
    return {
        "ElementName": "ManagedSystem",
        "Name": "ManagedSystem",
        "Caption": "Computer System",
        "EnabledState": 2,
        "RequestedState": 12,
    }


GET_HANDLERS: dict[str, Callable[[AmtState], dict[str, object]]] = {
    CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE: _get_power,
    AMT_BOOT_SETTING_DATA: lambda state: dict(state.boot_setting_data),
    AMT_BOOT_CAPABILITIES: _get_boot_capabilities,
    AMT_REDIRECTION_SERVICE: _get_redirection,
    AMT_GENERAL_SETTINGS: _get_general_settings,
    AMT_SETUP_AND_CONFIGURATION_SERVICE: _get_setup_and_configuration_service,
    CIM_COMPUTER_SYSTEM: _get_computer_system,
}


# --------------------------------------------------------------------------
# Method (CIM/AMT Method_INPUT) handlers -- return (ReturnValue, extra body xml)
# --------------------------------------------------------------------------


def _method_request_power_state_change(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    requested = _child_text(body_elem, "PowerState")
    if requested is None:
        return 2, ""
    try:
        code = int(requested)
    except ValueError:
        return 2, ""
    new_state = POWER_ACTION_TO_STATE.get(code)
    if new_state is None:
        return 2, ""
    state.power_state = new_state
    return 0, ""


def _method_change_boot_order(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    source_elem = None
    if body_elem is not None:
        for child in body_elem:
            if child.tag.rsplit("}", 1)[-1] == "Source":
                source_elem = child
                break
    state.boot_order_source = _extract_instance_id(source_elem)
    return 0, ""


def _method_set_boot_config_role(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    role_text = _child_text(body_elem, "Role")
    if role_text is not None:
        try:
            state.boot_config_role = int(role_text)
        except ValueError:
            return 2, ""
    return 0, ""


def _method_request_redirection_state_change(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    requested = _child_text(body_elem, "RequestedState")
    if requested is None:
        return 2, ""
    try:
        value = int(requested)
    except ValueError:
        return 2, ""
    if value not in (32768, 32769, 32770, 32771):
        return 2, ""
    state.redirection_enabled_state = value
    state.redirection_listener_enabled = value != 32768
    return 0, ""


METHOD_HANDLERS: dict[tuple[str, str], Callable[[AmtState, ET.Element | None], tuple[int, str]]] = {
    (CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange"): _method_request_power_state_change,
    (CIM_BOOT_CONFIG_SETTING, "ChangeBootOrder"): _method_change_boot_order,
    (CIM_BOOT_SERVICE, "SetBootConfigRole"): _method_set_boot_config_role,
    (AMT_REDIRECTION_SERVICE, "RequestStateChange"): _method_request_redirection_state_change,
}


# --------------------------------------------------------------------------
# Enumerate/Pull item generators
# --------------------------------------------------------------------------


def _boot_source_items(state: AmtState) -> list[str]:
    count = state.boot_source_count
    names = [BOOT_SOURCE_NAMES[i % len(BOOT_SOURCE_NAMES)] for i in range(count)]
    items = []
    for idx, name in enumerate(names):
        label = name if idx < len(BOOT_SOURCE_NAMES) else f"{name} ({idx})"
        items.append(
            f'<r:CIM_BootSourceSetting xmlns:r="{CIM_BOOT_SOURCE_SETTING}">'
            f"<r:InstanceID>{escape(label)}</r:InstanceID>"
            f"<r:ElementName>{escape(label)}</r:ElementName>"
            f"<r:StructuredBootString>{escape(label)}</r:StructuredBootString>"
            f"<r:BootSourceIndex>{idx}</r:BootSourceIndex>"
            "</r:CIM_BootSourceSetting>"
        )
    return items


ENUMERATE_HANDLERS: dict[str, Callable[[AmtState], list[str]]] = {
    CIM_BOOT_SOURCE_SETTING: _boot_source_items,
}


def generate_self_signed_tls_context(host: str) -> tuple[ssl.SSLContext, str, tempfile.TemporaryDirectory]:
    """Generate a throw-away self-signed cert/key via the ``openssl`` CLI.

    Returns the loaded server-side TLS context, the leaf certificate's
    SHA-256 fingerprint (hex), and the TemporaryDirectory holding the files
    (kept alive so the paths stay valid; caller is responsible for
    ``cleanup()`` when the server stops).
    """
    openssl_bin = shutil.which("openssl")
    if openssl_bin is None:
        raise RuntimeError(
            "openssl CLI not found in PATH. TLS mode for the mock WS-Man server shells out to "
            "openssl to generate a throw-away self-signed certificate (see wsman_server.py module "
            "docstring); install it or use use_tls=False."
        )
    tmpdir = tempfile.TemporaryDirectory(prefix="amt-mock-wsman-tls-")
    key_path = os.path.join(tmpdir.name, "key.pem")
    cert_path = os.path.join(tmpdir.name, "cert.pem")
    subprocess.run(  # noqa: S603 -- fixed argv, no shell, no untrusted input
        [
            openssl_bin,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "2",
            "-nodes",
            "-subj",
            f"/CN={host}",
        ],
        check=True,
        capture_output=True,
    )
    with open(cert_path, encoding="ascii") as fh:
        pem = fh.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    fingerprint = hashlib.sha256(der).hexdigest()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx, fingerprint, tmpdir


class DigestAuth:
    """Real HTTP Digest (RFC 2617) challenge/verify, ``qop=auth`` only.

    This is not a rubber stamp: :meth:`verify` recomputes the expected
    response from the username/realm/password plus the request method and
    actual request-target, and compares against what the client sent. A
    client with a wrong password, or one that just replays a previous
    response, will fail.
    """

    def __init__(self, realm: str, credentials: dict[str, str]) -> None:
        self.realm = realm
        self.credentials = dict(credentials)
        self._nonces: set[str] = set()
        self._lock = threading.Lock()

    def challenge(self) -> str:
        import secrets

        nonce = secrets.token_hex(16)
        opaque = secrets.token_hex(8)
        with self._lock:
            self._nonces.add(nonce)
        return f'Digest realm="{self.realm}", qop="auth", nonce="{nonce}", opaque="{opaque}", algorithm=MD5'

    def verify(self, header: str | None, method: str, uri: str) -> bool:
        if not header or not header.lower().startswith("digest "):
            return False
        params = _parse_digest_header(header[len("Digest ") :])
        username = params.get("username")
        if username is None:
            return False
        password = self.credentials.get(username)
        if password is None:
            return False
        nonce = params.get("nonce")
        if not nonce:
            return False
        with self._lock:
            if nonce not in self._nonces:
                return False
        response = params.get("response")
        if not response:
            return False
        qop = params.get("qop", "auth")
        nc = params.get("nc", "")
        cnonce = params.get("cnonce", "")
        ha1 = _md5(f"{username}:{self.realm}:{password}")
        ha2 = _md5(f"{method}:{uri}")
        if qop:
            expected = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        else:
            expected = _md5(f"{ha1}:{nonce}:{ha2}")
        return hmac.compare_digest(expected, response)


def _md5(data: str) -> str:
    # MD5 is mandated by RFC 2617 digest auth, not a security choice we get to
    # make -- see plugins/module_utils/redirection.py for the identical note
    # on the redirection-plane digest.
    return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()


_DIGEST_FIELD_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')


def _parse_digest_header(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _DIGEST_FIELD_RE.finditer(value):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = val
    return result


class _MockThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """A handful of test scenarios legitimately disconnect mid-request: a
    fingerprint-only TLS probe that never sends an HTTP request, or a client
    that gives up after one of our own timeout faults fires. Those are
    expected, not bugs, so silence the default traceback-to-stderr for them
    and let anything else through."""

    def handle_error(self, request: object, client_address: object) -> None:
        exc_type = sys.exc_info()[0]
        if exc_type is not None and issubclass(exc_type, (ConnectionError, TimeoutError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


class _WsmanHandler(http.server.BaseHTTPRequestHandler):
    server_version = "MockAMT-WSMAN/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass  # Silence: tests assert behaviour, not console noise.

    def do_POST(self) -> None:
        mock: WsmanMockServer = self.server.mock  # type: ignore[attr-defined]
        faults = mock.faults

        if faults.force_status is not None:
            status = faults.force_status
            faults.force_status = None
            self._send_plain(status, b"injected fault")
            return

        if faults.timeout_before_read:
            faults.timeout_before_read = False
            faults.last_timeout_body_was_read = False
            self._hang(mock)
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_body = self.rfile.read(length) if length else b""

        if faults.timeout_after_read:
            faults.timeout_after_read = False
            faults.last_timeout_body_was_read = True
            self._hang(mock)
            return

        if not mock.digest.verify(self.headers.get("Authorization"), "POST", self.path):
            self._send_401(mock)
            return

        try:
            root = ET.fromstring(raw_body)  # noqa: S314 -- fixed local test fixture input, not untrusted
        except ET.ParseError:
            self._send_plain(400, b"malformed SOAP request")
            return

        action, resource_uri, relates_to, body_elem = _parse_envelope(root)
        key = (resource_uri, action)

        if key in faults.malformed_xml_for:
            self._send_raw(200, b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><truncated')
            return
        if key in faults.soap_fault_for:
            body = _fault_body("InjectedFault", "Fault injected by test fixture")
            self._send_raw(500, _envelope(ACTION_FAULT, relates_to, body).encode("utf-8"))
            return
        if key in faults.http_status_for:
            self._send_plain(faults.http_status_for[key], b"injected fault")
            return

        return_override = faults.return_value_for.get(key)
        status, response_xml = mock.dispatch(action, resource_uri, relates_to, body_elem, return_override)
        self._send_raw(status, response_xml.encode("utf-8"))

    def _hang(self, mock: WsmanMockServer) -> None:
        # Block long enough for the client's own (short) timeout to fire, then
        # let this handler thread unwind naturally -- never write a response.
        threading.Event().wait(mock.timeout_hang_seconds)
        self.close_connection = True

    def _send_401(self, mock: WsmanMockServer) -> None:
        body = b"Unauthorized"
        self.send_response(401)
        self.send_header("WWW-Authenticate", mock.digest.challenge())
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_plain(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _parse_envelope(root: ET.Element) -> tuple[str, str, str, ET.Element | None]:
    header = root.find(f"{{{NS_S}}}Header")
    body = root.find(f"{{{NS_S}}}Body")
    action = (header.findtext(f"{{{NS_A}}}Action", default="") if header is not None else "").strip()
    resource_uri = (header.findtext(f"{{{NS_W}}}ResourceURI", default="") if header is not None else "").strip()
    message_id = (header.findtext(f"{{{NS_A}}}MessageID", default="") if header is not None else "").strip()
    body_elem = next(iter(body), None) if body is not None else None
    return action, resource_uri, message_id, body_elem


class WsmanMockServer:
    """Threaded mock WS-Man endpoint. Use as a context manager::

        with WsmanMockServer(password="test-password-not-real") as server:
            requests.post(server.base_url, auth=HTTPDigestAuth(...), data=..., verify=server.ca_bundle)

    Binds to an ephemeral port on 127.0.0.1 only. TLS mode generates a
    throw-away self-signed certificate per instance and exposes its SHA-256
    fingerprint via :attr:`cert_fingerprint` for fingerprint-pinning tests.
    """

    def __init__(
        self,
        *,
        username: str = "admin",
        password: str = "test-password-not-real",  # noqa: S107 -- obviously-fake fixture default, not a real credential
        realm: str = "Digest:mock-amt-fixture",
        use_tls: bool = False,
        host: str = "127.0.0.1",
        page_size: int = 2,
        timeout_hang_seconds: float = 1.0,
    ) -> None:
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.host = host
        self.page_size = page_size
        self.timeout_hang_seconds = timeout_hang_seconds

        self.state = AmtState()
        self.faults = FaultConfig()
        self.digest = DigestAuth(realm, {username: password})

        self._contexts: dict[str, list[str]] = {}
        self._lock = threading.Lock()
        self._httpd: _MockThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._tls_tmpdir: tempfile.TemporaryDirectory | None = None

        self.cert_fingerprint: str | None = None
        self.port: int | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> WsmanMockServer:
        httpd = _MockThreadingHTTPServer((self.host, 0), _WsmanHandler)
        httpd.daemon_threads = True
        httpd.mock = self  # type: ignore[attr-defined]

        if self.use_tls:
            ctx, fingerprint, tmpdir = generate_self_signed_tls_context(self.host)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            self.cert_fingerprint = fingerprint
            self._tls_tmpdir = tmpdir

        self._httpd = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(target=httpd.serve_forever, name="wsman-mock", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout_hang_seconds + 5)
        if self._tls_tmpdir is not None:
            self._tls_tmpdir.cleanup()
            self._tls_tmpdir = None
        self._httpd = None
        self._thread = None

    def __enter__(self) -> WsmanMockServer:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}/wsman"

    # -- dispatch ------------------------------------------------------------

    def dispatch(
        self,
        action: str,
        resource_uri: str,
        relates_to: str,
        body_elem: ET.Element | None,
        return_override: int | None,
    ) -> tuple[int, str]:
        with self._lock:
            try:
                if action == ACTION_GET:
                    return self._handle_get(resource_uri, relates_to)
                if action == ACTION_PUT:
                    return self._handle_put(resource_uri, relates_to, body_elem)
                if action == ACTION_ENUMERATE:
                    return self._handle_enumerate(resource_uri, relates_to)
                if action == ACTION_PULL:
                    return self._handle_pull(resource_uri, relates_to, body_elem)
                if resource_uri and action.startswith(resource_uri + "/"):
                    method_name = action[len(resource_uri) + 1 :]
                    return self._handle_method(resource_uri, method_name, relates_to, body_elem, return_override)
            except _UnknownResource:
                pass
            body = _fault_body("UnsupportedCapability", f"No handler for action={action!r} resourceURI={resource_uri!r}")
            return 500, _envelope(ACTION_FAULT, relates_to, body)

    def _handle_get(self, resource_uri: str, relates_to: str) -> tuple[int, str]:
        handler = GET_HANDLERS.get(resource_uri)
        if handler is None:
            raise _UnknownResource
        fields = handler(self.state)
        body = _fields_to_instance_xml(resource_uri, fields)
        return 200, _envelope(ACTION_GET_RESPONSE, relates_to, body, resource_uri=resource_uri)

    def _handle_put(self, resource_uri: str, relates_to: str, body_elem: ET.Element | None) -> tuple[int, str]:
        if resource_uri != AMT_BOOT_SETTING_DATA:
            raise _UnknownResource
        incoming = {child.tag.rsplit("}", 1)[-1]: (child.text or "") for child in (body_elem or [])}
        if self.faults.reject_boot_readonly_fields:
            offending = sorted(READONLY_BOOT_FIELDS & incoming.keys())
            if offending:
                body = _fault_body(
                    "InvalidParameter",
                    "Put rejected: read-only field(s) present: " + ", ".join(offending),
                )
                return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        self.state.boot_setting_data.update(incoming)
        body = _fields_to_instance_xml(resource_uri, self.state.boot_setting_data)
        return 200, _envelope(ACTION_PUT_RESPONSE, relates_to, body, resource_uri=resource_uri)

    def _handle_enumerate(self, resource_uri: str, relates_to: str) -> tuple[int, str]:
        handler = ENUMERATE_HANDLERS.get(resource_uri)
        if handler is None:
            raise _UnknownResource
        items = handler(self.state)
        ctx = uuid.uuid4().hex
        self._contexts[ctx] = list(items)
        body = f'<wsen:EnumerateResponse xmlns:wsen="{NS_WSEN}"><wsen:EnumerationContext>{ctx}</wsen:EnumerationContext></wsen:EnumerateResponse>'
        return 200, _envelope(ACTION_ENUMERATE_RESPONSE, relates_to, body)

    def _handle_pull(self, _resource_uri: str, relates_to: str, body_elem: ET.Element | None) -> tuple[int, str]:
        ctx = _child_text(body_elem, "EnumerationContext")
        if ctx is None or ctx not in self._contexts:
            body = _fault_body("InvalidEnumerationContext", "Unknown or expired enumeration context")
            return 500, _envelope(ACTION_FAULT, relates_to, body)
        remaining = self._contexts[ctx]
        page, remaining[:] = remaining[: self.page_size], remaining[self.page_size :]
        items_xml = "".join(page)
        if remaining:
            body = (
                f'<wsen:PullResponse xmlns:wsen="{NS_WSEN}">'
                f"<wsen:Items>{items_xml}</wsen:Items>"
                f"<wsen:EnumerationContext>{ctx}</wsen:EnumerationContext>"
                "</wsen:PullResponse>"
            )
        else:
            del self._contexts[ctx]
            body = f'<wsen:PullResponse xmlns:wsen="{NS_WSEN}"><wsen:Items>{items_xml}</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse>'
        return 200, _envelope(ACTION_PULL_RESPONSE, relates_to, body)

    def _handle_method(
        self,
        resource_uri: str,
        method_name: str,
        relates_to: str,
        body_elem: ET.Element | None,
        return_override: int | None,
    ) -> tuple[int, str]:
        handler = METHOD_HANDLERS.get((resource_uri, method_name))
        if handler is None:
            raise _UnknownResource
        if return_override is not None:
            return_value, extra = return_override, ""
        else:
            return_value, extra = handler(self.state, body_elem)
        out = f'<r:{method_name}_OUTPUT xmlns:r="{resource_uri}"><r:ReturnValue>{return_value}</r:ReturnValue>{extra}</r:{method_name}_OUTPUT>'
        return 200, _envelope(f"{resource_uri}/{method_name}Response", relates_to, out, resource_uri=resource_uri)

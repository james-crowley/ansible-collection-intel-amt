# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Self-tests for the mock WS-Man server.

These exercise ``WsmanMockServer`` from the outside with a plain HTTP client
(``requests``) plus a raw TLS socket for fingerprint checks, exactly as a
real integration test would, rather than calling internals directly -- the
whole point of these tests is to prove the mock behaves like a WS-Man
endpoint on the wire, not just that its Python happens to be self-consistent.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import threading
import uuid
import warnings
from xml.etree import ElementTree as ET

import pytest
import requests
from requests.auth import HTTPDigestAuth
from wsman_server import (
    AMT_BOOT_CAPABILITIES,
    AMT_BOOT_SETTING_DATA,
    AMT_GENERAL_SETTINGS,
    AMT_REDIRECTION_SERVICE,
    AMT_SETUP_AND_CONFIGURATION_SERVICE,
    CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE,
    CIM_BOOT_CONFIG_SETTING,
    CIM_BOOT_SERVICE,
    CIM_BOOT_SOURCE_SETTING,
    CIM_COMPUTER_SYSTEM,
    CIM_POWER_MANAGEMENT_SERVICE,
    WsmanMockServer,
)

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

FAKE_USERNAME = "admin"
FAKE_PASSWORD = "test-password-not-real"


def _find_text(root: ET.Element, local_name: str) -> str | None:
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] == local_name:
            return elem.text
    return None


def _find_all_text(root: ET.Element, local_name: str) -> list[str]:
    return [elem.text or "" for elem in root.iter() if elem.tag.rsplit("}", 1)[-1] == local_name]


def _has_element(root: ET.Element, local_name: str) -> bool:
    """True if an element with this local name exists anywhere in the tree.

    Deliberately distinct from :func:`_find_text`: ``EndOfSequence`` is
    self-closing, so its ``.text`` is ``None`` and cannot be used to detect
    presence.
    """
    return any(elem.tag.rsplit("}", 1)[-1] == local_name for elem in root.iter())


def _envelope(action: str, resource_uri: str, body_xml: str = "") -> str:
    message_id = f"uuid:{uuid.uuid4()}"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
        "<s:Header>"
        f'<a:Action s:mustUnderstand="true">{action}</a:Action>'
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        f"<w:ResourceURI>{resource_uri}</w:ResourceURI>"
        f"<a:MessageID>{message_id}</a:MessageID>"
        "</s:Header>"
        f"<s:Body>{body_xml}</s:Body>"
        "</s:Envelope>"
    )


def _get_xml(resource_uri: str) -> str:
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get", resource_uri)


def _put_xml(resource_uri: str, fields: dict[str, str]) -> str:
    inner = "".join(f"<r:{k}>{v}</r:{k}>" for k, v in fields.items())
    body = f'<r:AMT_BootSettingData xmlns:r="{resource_uri}">{inner}</r:AMT_BootSettingData>'
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/Put", resource_uri, body)


def _enumerate_xml(resource_uri: str) -> str:
    body = f'<Enumerate xmlns="{NS_WSEN}" />'
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", resource_uri, body)


def _pull_xml(resource_uri: str, context: str) -> str:
    body = f'<Pull xmlns="{NS_WSEN}"><EnumerationContext>{context}</EnumerationContext><MaxElements>999</MaxElements></Pull>'
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull", resource_uri, body)


def _method_xml(resource_uri: str, method: str, params: dict[str, str]) -> str:
    inner = "".join(f"<r:{k}>{v}</r:{k}>" for k, v in params.items())
    body = f'<r:{method}_INPUT xmlns:r="{resource_uri}">{inner}</r:{method}_INPUT>'
    return _envelope(f"{resource_uri}/{method}", resource_uri, body)


def _post(server: WsmanMockServer, xml: str, *, auth: HTTPDigestAuth | None = None, timeout: float = 5.0) -> requests.Response:
    if auth is None:
        auth = HTTPDigestAuth(server.username, server.password)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return requests.post(
            server.base_url,
            data=xml.encode("utf-8"),
            headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
            auth=auth,
            timeout=timeout,
            verify=False,  # noqa: S501 -- self-signed throw-away fixture cert, fingerprint checked separately
        )


BOOT_PUT_GOOD_FIELDS = {
    "ConfigurationDataReset": "false",
    "BIOSPause": "false",
    "EnforceSecureBoot": "false",
    "BIOSSetup": "false",
    "BootMediaIndex": "0",
    "FirmwareVerbosity": "0",
    "ForcedProgressEvents": "false",
    "IDERBootDevice": "0",
    "LockKeyboard": "false",
    "LockPowerButton": "false",
    "LockResetButton": "false",
    "LockSleepButton": "false",
    "ReflashBIOS": "false",
    "UseIDER": "true",
    "UseSOL": "true",
    "UseSafeMode": "false",
    "UserPasswordBypass": "false",
}


@pytest.fixture
def server():
    with WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, timeout_hang_seconds=1.0) as srv:
        yield srv


class TestDigestAuth:
    def test_unauthenticated_request_gets_401_challenge(self, server):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            resp = requests.post(
                server.base_url,
                data=_get_xml(CIM_COMPUTER_SYSTEM).encode(),
                timeout=5,
            )
        assert resp.status_code == 401
        challenge = resp.headers["WWW-Authenticate"]
        assert challenge.lower().startswith("digest ")
        assert 'qop="auth"' in challenge
        assert "nonce=" in challenge
        assert "realm=" in challenge

    def test_correct_password_is_accepted(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 200

    def test_wrong_password_is_rejected(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM), auth=HTTPDigestAuth(FAKE_USERNAME, "not-the-real-password"))
        assert resp.status_code == 401

    def test_unknown_username_is_rejected(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM), auth=HTTPDigestAuth("someone-else", FAKE_PASSWORD))
        assert resp.status_code == 401

    def test_replayed_authorization_header_with_stale_nonce_fails(self, server):
        # A nonce this server never issued must never verify, even if the
        # rest of the digest arithmetic is otherwise self-consistent.
        ok = server.digest.verify(
            'Digest username="admin", realm="x", nonce="00", uri="/wsman", response="deadbeef", qop=auth, nc=00000001, cnonce="abc"',
            "POST",
            "/wsman",
        )
        assert ok is False


class TestTls:
    def test_tls_serves_the_fingerprint_it_reports(self):
        with WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, use_tls=True) as srv:
            assert srv.cert_fingerprint is not None
            ctx = ssl._create_unverified_context()  # noqa: S323 -- deliberately unpinned: this test checks the fingerprint itself
            with socket.create_connection((srv.host, srv.port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=srv.host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
            observed = hashlib.sha256(der).hexdigest()
            assert observed == srv.cert_fingerprint

    def test_plain_http_mode_serves_no_certificate(self, server):
        assert server.cert_fingerprint is None
        assert server.base_url.startswith("http://")

    def test_tls_digest_auth_still_works(self):
        with WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, use_tls=True) as srv:
            resp = _post(srv, _get_xml(CIM_COMPUTER_SYSTEM))
            assert resp.status_code == 200


class TestCannedResponsesParseAsSoap:
    @pytest.mark.parametrize(
        "resource_uri",
        [
            CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE,
            AMT_BOOT_SETTING_DATA,
            AMT_BOOT_CAPABILITIES,
            AMT_REDIRECTION_SERVICE,
            AMT_GENERAL_SETTINGS,
            AMT_SETUP_AND_CONFIGURATION_SERVICE,
            CIM_COMPUTER_SYSTEM,
        ],
    )
    def test_get_response_is_well_formed_soap(self, server, resource_uri):
        resp = _post(server, _get_xml(resource_uri))
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("application/soap+xml")
        root = ET.fromstring(resp.content)  # noqa: S314 -- test fixture's own response
        assert root.tag == f"{{{NS_S}}}Envelope"
        # Every element in the body must be namespaced -- catches a common
        # canned-response bug where a field is emitted unqualified.
        body = root.find(f"{{{NS_S}}}Body")
        assert body is not None
        assert len(list(body)) == 1

    def test_power_state_field_present_and_correct_type(self, server):
        resp = _post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        power_state = _find_text(root, "PowerState")
        assert power_state is not None
        assert int(power_state) == 2  # freshly started mock reports "On"

    def test_boot_capabilities_reports_ider_support(self, server):
        resp = _post(server, _get_xml(AMT_BOOT_CAPABILITIES))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "IDER") == "true"

    def test_general_settings_has_no_real_hostname(self, server):
        resp = _post(server, _get_xml(AMT_GENERAL_SETTINGS))
        root = ET.fromstring(resp.content)  # noqa: S314
        host_name = _find_text(root, "HostName")
        assert host_name is not None
        assert "." not in host_name or host_name.endswith(".invalid") or "example" in host_name

    def test_computer_system_name_selector_matches_power_change_target(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "Name") == "ManagedSystem"


class TestEnumeratePullPaging:
    def test_paging_returns_every_item_exactly_once(self, server):
        server.state.boot_source_count = 5
        server.page_size = 2  # forces 3 pulls for 5 items -- paging is genuinely exercised

        resp = _post(server, _enumerate_xml(CIM_BOOT_SOURCE_SETTING))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        context = _find_text(root, "EnumerationContext")
        assert context

        seen_instance_ids: list[str] = []
        pulls = 0
        while True:
            pulls += 1
            resp = _post(server, _pull_xml(CIM_BOOT_SOURCE_SETTING, context))
            assert resp.status_code == 200
            root = ET.fromstring(resp.content)  # noqa: S314
            seen_instance_ids.extend(_find_all_text(root, "InstanceID"))
            if _has_element(root, "EndOfSequence"):
                break
            context = _find_text(root, "EnumerationContext")
            assert context, "server must keep returning a context until EndOfSequence"
            if pulls > 20:
                pytest.fail("paging did not terminate")

        assert pulls == 3
        assert len(seen_instance_ids) == 5
        assert len(set(seen_instance_ids)) == 5  # no duplicates, nothing dropped

    def test_pull_with_unknown_context_faults(self, server):
        resp = _post(server, _pull_xml(CIM_BOOT_SOURCE_SETTING, "not-a-real-context"))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None


class TestStatefulness:
    def test_boot_setting_data_put_is_observed_by_later_get(self, server):
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, {**BOOT_PUT_GOOD_FIELDS, "UseIDER": "true"}))
        assert resp.status_code == 200

        resp = _post(server, _get_xml(AMT_BOOT_SETTING_DATA))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "UseIDER") == "true"

    def test_boot_put_rejects_readonly_fields_by_default(self, server):
        bad_fields = {**BOOT_PUT_GOOD_FIELDS, "WinREBootEnabled": "false"}
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, bad_fields))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None
        reason = _find_text(root, "Text")
        assert reason is not None
        assert "WinREBootEnabled" in reason

    def test_boot_put_accepts_clean_instance(self, server):
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, BOOT_PUT_GOOD_FIELDS))
        assert resp.status_code == 200

    def test_boot_put_readonly_rejection_is_toggleable(self, server):
        server.faults.reject_boot_readonly_fields = False
        bad_fields = {**BOOT_PUT_GOOD_FIELDS, "BootguardStatus": "0"}
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, bad_fields))
        assert resp.status_code == 200

    def test_power_state_change_is_observed_by_later_get(self, server):
        # 8 = power off (soft) per protocol-notes.md action-code table.
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "8"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"

        resp = _post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "PowerState") == "8"

    def test_change_boot_order_and_set_boot_config_role(self, server):
        resp = _post(server, _method_xml(CIM_BOOT_SERVICE, "SetBootConfigRole", {"Role": "1"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_config_role == 1

        resp = _post(server, _method_xml(CIM_BOOT_CONFIG_SETTING, "ChangeBootOrder", {}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_order_source is None  # empty Source clears it

    def test_change_boot_order_with_a_source_records_the_instance_id(self, server):
        source_body = (
            "<r:Source>"
            '<a:Address xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/anonymous</a:Address>"
            '<a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            f'<w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">{CIM_BOOT_SOURCE_SETTING}</w:ResourceURI>'
            '<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
            '<w:Selector Name="InstanceID">Intel(r) AMT: Force PXE Boot</w:Selector>'
            "</w:SelectorSet></a:ReferenceParameters></r:Source>"
        )
        body = f'<r:ChangeBootOrder_INPUT xmlns:r="{CIM_BOOT_CONFIG_SETTING}">{source_body}</r:ChangeBootOrder_INPUT>'
        xml = _envelope(f"{CIM_BOOT_CONFIG_SETTING}/ChangeBootOrder", CIM_BOOT_CONFIG_SETTING, body)
        resp = _post(server, xml)
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_order_source == "Intel(r) AMT: Force PXE Boot"

    def test_redirection_state_change_is_observed_by_later_get(self, server):
        resp = _post(server, _method_xml(AMT_REDIRECTION_SERVICE, "RequestStateChange", {"RequestedState": "32771"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"

        resp = _post(server, _get_xml(AMT_REDIRECTION_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "EnabledState") == "32771"
        assert _find_text(root, "ListenerEnabled") == "true"


class TestFaultInjection:
    def test_forced_return_value_on_method_call(self, server):
        key = (CIM_POWER_MANAGEMENT_SERVICE, f"{CIM_POWER_MANAGEMENT_SERVICE}/RequestPowerStateChange")
        server.faults.return_value_for[key] = 2
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "8"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "2"
        # And the side effect must NOT have happened -- a real non-zero
        # ReturnValue means the mutation was refused.
        assert server.state.power_state == 2

    def test_soap_fault_injection(self, server):
        key = (CIM_COMPUTER_SYSTEM, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        server.faults.soap_fault_for.add(key)
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None

    def test_malformed_xml_injection(self, server):
        key = (CIM_COMPUTER_SYSTEM, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        server.faults.malformed_xml_for.add(key)
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 200
        with pytest.raises(ET.ParseError):
            ET.fromstring(resp.content)  # noqa: S314

    def test_http_status_injection_for_specific_resource(self, server):
        key = (CIM_COMPUTER_SYSTEM, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        server.faults.http_status_for[key] = 500
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 500
        # Unrelated resources are unaffected.
        resp = _post(server, _get_xml(AMT_GENERAL_SETTINGS))
        assert resp.status_code == 200

    def test_force_status_short_circuits_next_request_only(self, server):
        server.faults.force_status = 401
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 401
        # One-shot: the next request is unaffected.
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 200

    def test_timeout_before_read_does_not_read_the_body(self, server):
        server.faults.timeout_before_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is False

    def test_timeout_after_read_does_read_the_body(self, server):
        server.faults.timeout_after_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is True

    def test_the_two_timeout_faults_are_independently_triggerable(self, server):
        server.faults.timeout_before_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is False
        # Normal request works again in between.
        assert _post(server, _get_xml(CIM_COMPUTER_SYSTEM)).status_code == 200

        server.faults.timeout_after_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is True


class TestCleanShutdown:
    def test_no_leaked_threads_or_sockets_after_exit(self):
        before = set(threading.enumerate())
        srv = WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD).start()
        port = srv.port
        assert _post(srv, _get_xml(CIM_COMPUTER_SYSTEM)).status_code == 200
        srv.stop()

        after = set(threading.enumerate())
        leaked = after - before
        assert not leaked, f"threads leaked after shutdown: {leaked}"

        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

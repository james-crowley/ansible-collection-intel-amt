# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from unittest.mock import Mock

import pytest
import requests

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AuthenticationError,
    ConnectionError_,
    ProtocolError,
    RemoteOperationError,
    TimeoutError_,
    TlsValidationError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    ACTION_GET,
    NS_ADDRESSING,
    NS_SOAP,
    NS_WSMAN,
    EndpointReference,
    WsmanClient,
    build_envelope,
    build_selector_set,
    resource_uri,
)

PASSWORD = "Sup3rSecret!"


def _soap_response(body_xml: str, status_code: int = 200) -> Mock:
    """A fake ``requests.Response`` wrapping a hand-built SOAP envelope."""
    content = f'<s:Envelope xmlns:s="{NS_SOAP}"><s:Body>{body_xml}</s:Body></s:Envelope>'.encode()
    response = Mock()
    response.status_code = status_code
    response.ok = 200 <= status_code < 300
    response.content = content
    response.text = content.decode()
    # No `_connection` attribute -- exercises the "no TLS evidence available"
    # path in tls.peer_certificate_evidence without a real socket.
    response.raw = Mock(spec=[])
    return response


def _make_client(*, max_retries: int = 2) -> WsmanClient:
    session = requests.Session()
    session.post = Mock()
    return WsmanClient(
        host="10.0.0.5",
        port=16992,
        username="admin",
        password=PASSWORD,
        use_tls=False,
        max_retries=max_retries,
        session=session,
    )


class TestResourceUri:
    @pytest.mark.parametrize(
        "class_name,expected",
        [
            ("CIM_ComputerSystem", "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem"),
            ("AMT_BootSettingData", "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_BootSettingData"),
            ("IPS_OptInService", "http://intel.com/wbem/wscim/1/ips-schema/1/IPS_OptInService"),
        ],
    )
    def test_known_prefixes(self, class_name, expected):
        assert resource_uri(class_name) == expected

    def test_unrecognised_prefix_is_rejected(self):
        with pytest.raises(ValueError, match="CIM_, AMT_, or IPS_"):
            resource_uri("FOO_Widget")


class TestSelectorSet:
    def test_selectors_become_named_selector_elements(self):
        selector_set = build_selector_set({"InstanceID": "abc", "Name": "ManagedSystem"})
        selectors = list(selector_set)
        assert [el.get("Name") for el in selectors] == ["InstanceID", "Name"]
        assert [el.text for el in selectors] == ["abc", "ManagedSystem"]
        assert all(el.tag == f"{{{NS_WSMAN}}}Selector" for el in selectors)


class TestEndpointReference:
    def test_matches_the_exact_shape_amt_boot_needs(self):
        # docs/protocol-notes.md s2.5: this exact Address/ReferenceParameters/
        # ResourceURI/SelectorSet shape is what ChangeBootOrder requires to
        # name a CIM_BootSourceSetting instance.
        epr = EndpointReference("CIM_BootSourceSetting", {"InstanceID": "Intel(r) AMT: Force PXE Boot"})
        address, reference_parameters = epr.build_elements()

        assert address.tag == f"{{{NS_ADDRESSING}}}Address"
        assert address.text == NS_ADDRESSING

        assert reference_parameters.tag == f"{{{NS_ADDRESSING}}}ReferenceParameters"
        resource_uri_el = reference_parameters.find(f"{{{NS_WSMAN}}}ResourceURI")
        assert resource_uri_el is not None
        assert resource_uri_el.text == resource_uri("CIM_BootSourceSetting")

        selector_set_el = reference_parameters.find(f"{{{NS_WSMAN}}}SelectorSet")
        selector_el = selector_set_el.find(f"{{{NS_WSMAN}}}Selector")
        assert selector_el.get("Name") == "InstanceID"
        assert selector_el.text == "Intel(r) AMT: Force PXE Boot"


class TestBuildEnvelope:
    def test_header_shape_matches_protocol_notes(self):
        envelope = build_envelope(action=ACTION_GET, to="https://10.0.0.5:16993/wsman", resource_uri_value=resource_uri("AMT_BootSettingData"))
        header = envelope.find(f"{{{NS_SOAP}}}Header")

        action_el = header.find(f"{{{NS_ADDRESSING}}}Action")
        assert action_el.text == ACTION_GET
        assert action_el.get(f"{{{NS_SOAP}}}mustUnderstand") == "true"

        to_el = header.find(f"{{{NS_ADDRESSING}}}To")
        assert to_el.text == "https://10.0.0.5:16993/wsman"

        resource_uri_el = header.find(f"{{{NS_WSMAN}}}ResourceURI")
        assert resource_uri_el.text == resource_uri("AMT_BootSettingData")

        message_id_el = header.find(f"{{{NS_ADDRESSING}}}MessageID")
        assert message_id_el.text.startswith("uuid:")

        reply_to_address = header.find(f"{{{NS_ADDRESSING}}}ReplyTo/{{{NS_ADDRESSING}}}Address")
        assert reply_to_address.text == f"{NS_ADDRESSING}/role/anonymous"

        assert header.find(f"{{{NS_WSMAN}}}OperationTimeout").text == "PT60S"

    def test_message_id_is_fresh_per_call(self):
        # MeshCentral/parmstro reuse a constant MessageID; protocol-notes
        # calls that "sloppy" and requires a fresh uuid: per request.
        first = build_envelope(action=ACTION_GET, to="https://x/wsman", resource_uri_value="urn:x")
        second = build_envelope(action=ACTION_GET, to="https://x/wsman", resource_uri_value="urn:x")
        first_id = first.find(f"{{{NS_SOAP}}}Header/{{{NS_ADDRESSING}}}MessageID").text
        second_id = second.find(f"{{{NS_SOAP}}}Header/{{{NS_ADDRESSING}}}MessageID").text
        assert first_id != second_id

    def test_selectors_are_included_when_given(self):
        envelope = build_envelope(
            action=ACTION_GET,
            to="https://x/wsman",
            resource_uri_value="urn:x",
            selectors={"InstanceID": "abc"},
        )
        header = envelope.find(f"{{{NS_SOAP}}}Header")
        assert header.find(f"{{{NS_WSMAN}}}SelectorSet") is not None

    def test_no_selector_set_when_not_given(self):
        envelope = build_envelope(action=ACTION_GET, to="https://x/wsman", resource_uri_value="urn:x")
        header = envelope.find(f"{{{NS_SOAP}}}Header")
        assert header.find(f"{{{NS_WSMAN}}}SelectorSet") is None


class TestGet:
    def test_returns_flattened_instance_properties(self):
        client = _make_client()
        client._session.post.return_value = _soap_response(
            '<g:AMT_BootSettingData xmlns:g="urn:x"><g:UseIDER>true</g:UseIDER><g:BootMediaIndex>0</g:BootMediaIndex></g:AMT_BootSettingData>'
        )
        result = client.get("AMT_BootSettingData")
        assert result == {"UseIDER": "true", "BootMediaIndex": "0"}

    def test_repeated_child_elements_become_a_list(self):
        client = _make_client()
        client._session.post.return_value = _soap_response('<g:X xmlns:g="urn:x"><g:Assoc>a</g:Assoc><g:Assoc>b</g:Assoc></g:X>')
        result = client.get("AMT_Whatever".replace("Whatever", "BootSettingData"))
        assert result == {"Assoc": ["a", "b"]}


class TestEnumeratePull:
    def test_pages_until_end_of_sequence(self):
        client = _make_client()
        enumerate_response = _soap_response(
            '<wsen:EnumerateResponse xmlns:wsen="urn:enum"><wsen:EnumerationContext>ctx-1</wsen:EnumerationContext></wsen:EnumerateResponse>'
        )
        first_pull = _soap_response(
            '<wsen:PullResponse xmlns:wsen="urn:enum" xmlns:g="urn:x">'
            "<wsen:Items><g:Item><g:Name>one</g:Name></g:Item></wsen:Items>"
            "<wsen:EnumerationContext>ctx-2</wsen:EnumerationContext>"
            "</wsen:PullResponse>"
        )
        second_pull = _soap_response(
            '<wsen:PullResponse xmlns:wsen="urn:enum" xmlns:g="urn:x">'
            "<wsen:Items><g:Item><g:Name>two</g:Name></g:Item></wsen:Items>"
            "<wsen:EndOfSequence/>"
            "</wsen:PullResponse>"
        )
        client._session.post.side_effect = [enumerate_response, first_pull, second_pull]

        items = client.enumerate("CIM_BootSourceSetting")

        assert items == [{"Name": "one"}, {"Name": "two"}]
        assert client._session.post.call_count == 3  # Enumerate + two Pulls

    def test_no_items_element_yields_empty_page_without_error(self):
        client = _make_client()
        enumerate_response = _soap_response(
            '<wsen:EnumerateResponse xmlns:wsen="urn:enum"><wsen:EnumerationContext>ctx-1</wsen:EnumerationContext></wsen:EnumerateResponse>'
        )
        pull_response = _soap_response('<wsen:PullResponse xmlns:wsen="urn:enum"><wsen:EndOfSequence/></wsen:PullResponse>')
        client._session.post.side_effect = [enumerate_response, pull_response]

        assert client.enumerate("CIM_BootSourceSetting") == []


class TestSoapFault:
    def test_fault_is_raised_as_protocol_error_with_redacted_diagnostic(self):
        client = _make_client()
        client._session.post.return_value = _soap_response(
            f'<s:Fault xmlns:s="{NS_SOAP}"><s:Code><s:Value>s:Sender</s:Value></s:Code>'
            f'<s:Reason><s:Text>Authorization: Digest response="deadbeef"</s:Text></s:Reason></s:Fault>'
        )
        with pytest.raises(ProtocolError) as excinfo:
            client.get("AMT_BootSettingData")
        assert "s:Sender" in str(excinfo.value)
        # The fault's own diagnostic text can itself echo credential-shaped
        # content; that must be redacted like anything else.
        assert "deadbeef" not in (excinfo.value.diagnostic or "")


class TestHttpAuthentication:
    def test_401_maps_to_authentication_error(self):
        client = _make_client()
        client._session.post.return_value = _soap_response("<g:X xmlns:g='urn:x'/>", status_code=401)
        with pytest.raises(AuthenticationError):
            client.get("AMT_BootSettingData")

    def test_other_bad_status_maps_to_protocol_error(self):
        client = _make_client()
        client._session.post.return_value = _soap_response("<g:X xmlns:g='urn:x'/>", status_code=500)
        with pytest.raises(ProtocolError):
            client.get("AMT_BootSettingData")


class TestMalformedResponses:
    def test_non_xml_body_is_a_protocol_error(self):
        client = _make_client()
        response = Mock()
        response.status_code = 200
        response.ok = True
        response.content = b"not xml at all <<<"
        response.text = "not xml at all <<<"
        response.raw = Mock(spec=[])
        client._session.post.return_value = response
        with pytest.raises(ProtocolError):
            client.get("AMT_BootSettingData")

    def test_root_that_is_not_a_soap_envelope_is_a_protocol_error(self):
        client = _make_client()
        response = Mock()
        response.status_code = 200
        response.ok = True
        response.content = b"<NotAnEnvelope/>"
        response.text = "<NotAnEnvelope/>"
        response.raw = Mock(spec=[])
        client._session.post.return_value = response
        with pytest.raises(ProtocolError):
            client.get("AMT_BootSettingData")


class TestInvoke:
    def test_zero_return_value_succeeds(self):
        client = _make_client()
        client._session.post.return_value = _soap_response(
            '<g:SetBootConfigRole_OUTPUT xmlns:g="urn:x"><g:ReturnValue>0</g:ReturnValue></g:SetBootConfigRole_OUTPUT>'
        )
        output, return_value = client.invoke("CIM_BootService", "SetBootConfigRole", {"Role": 1})
        assert return_value == 0
        assert output["ReturnValue"] == "0"

    def test_nonzero_return_value_is_remote_operation_error(self):
        client = _make_client()
        client._session.post.return_value = _soap_response(
            '<g:ChangeBootOrder_OUTPUT xmlns:g="urn:x"><g:ReturnValue>2</g:ReturnValue></g:ChangeBootOrder_OUTPUT>'
        )
        with pytest.raises(RemoteOperationError) as excinfo:
            client.invoke("CIM_BootConfigSetting", "ChangeBootOrder", {"Source": None})
        assert excinfo.value.return_value == 2

    def test_invoke_is_never_retried_on_connection_error(self):
        client = _make_client(max_retries=5)
        client._session.post.side_effect = [requests.exceptions.ConnectionError("refused"), _soap_response("<g:X_OUTPUT xmlns:g='urn:x'/>")]
        with pytest.raises(ConnectionError_):
            client.invoke("CIM_BootService", "SetBootConfigRole", {"Role": 1})
        assert client._session.post.call_count == 1


class TestPutNeverRetried:
    def test_put_does_not_retry_on_connection_error(self):
        client = _make_client(max_retries=5)
        client._session.post.side_effect = [requests.exceptions.ConnectionError("refused"), _soap_response("<g:X xmlns:g='urn:x'/>")]
        with pytest.raises(ConnectionError_):
            client.put("AMT_BootSettingData", {"UseIDER": True})
        assert client._session.post.call_count == 1


class TestReadRetryPolicy:
    def test_get_retries_transient_connection_errors(self):
        client = _make_client(max_retries=2)
        client._session.post.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            _soap_response('<g:AMT_BootSettingData xmlns:g="urn:x"><g:UseIDER>true</g:UseIDER></g:AMT_BootSettingData>'),
        ]
        result = client.get("AMT_BootSettingData")
        assert result == {"UseIDER": "true"}
        assert client._session.post.call_count == 2

    def test_get_exhausts_retries_and_raises(self):
        client = _make_client(max_retries=1)
        client._session.post.side_effect = requests.exceptions.ConnectionError("refused")
        with pytest.raises(ConnectionError_):
            client.get("AMT_BootSettingData")
        assert client._session.post.call_count == 2  # initial attempt + 1 retry

    def test_enumerate_retries_transient_connection_errors_per_request(self):
        client = _make_client(max_retries=1)
        enumerate_response = _soap_response(
            '<wsen:EnumerateResponse xmlns:wsen="urn:enum"><wsen:EnumerationContext>ctx-1</wsen:EnumerationContext></wsen:EnumerateResponse>'
        )
        client._session.post.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            enumerate_response,
            requests.exceptions.ConnectionError("refused"),
            _soap_response('<wsen:PullResponse xmlns:wsen="urn:enum"><wsen:EndOfSequence/></wsen:PullResponse>'),
        ]
        assert client.enumerate("CIM_BootSourceSetting") == []


class TestTimeoutClassification:
    def test_connect_timeout_before_send_is_a_plain_timeout(self):
        # A ConnectTimeout means nothing was ever transmitted -- safe.
        client = _make_client(max_retries=0)
        client._session.post.side_effect = requests.exceptions.ConnectTimeout("connect timed out")
        with pytest.raises(TimeoutError_) as excinfo:
            client.get("AMT_BootSettingData")
        assert excinfo.value.indeterminate is False

    def test_read_timeout_after_send_is_indeterminate(self):
        # A ReadTimeout means the request body was already transmitted --
        # the mutation may have applied, so the caller must re-probe.
        client = _make_client(max_retries=5)
        client._session.post.side_effect = requests.exceptions.ReadTimeout("read timed out")
        with pytest.raises(TimeoutError_) as excinfo:
            client.put("AMT_BootSettingData", {"UseIDER": True})
        assert excinfo.value.indeterminate is True

    def test_read_timeout_is_never_retried_even_on_a_retryable_operation(self):
        client = _make_client(max_retries=5)
        client._session.post.side_effect = requests.exceptions.ReadTimeout("read timed out")
        with pytest.raises(TimeoutError_):
            client.get("AMT_BootSettingData")
        assert client._session.post.call_count == 1

    def test_ssl_error_maps_to_tls_validation_error(self):
        client = _make_client()
        client._session.post.side_effect = requests.exceptions.SSLError("certificate verify failed")
        with pytest.raises(TlsValidationError):
            client.get("AMT_BootSettingData")


class TestSecretsNeverLeak:
    def test_password_absent_from_every_raised_error(self):
        client = _make_client()
        client._session.post.return_value = _soap_response("<g:X xmlns:g='urn:x'/>", status_code=401)
        with pytest.raises(AuthenticationError) as excinfo:
            client.get("AMT_BootSettingData")
        assert PASSWORD not in str(excinfo.value)
        assert PASSWORD not in repr(excinfo.value)
        assert PASSWORD not in repr(excinfo.value.to_result())

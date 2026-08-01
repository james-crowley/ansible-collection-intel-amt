# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from unittest.mock import Mock
from xml.etree import ElementTree as ET

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
    NS_CIM_COMMON,
    NS_SOAP,
    NS_WSMAN,
    EmbeddedInstance,
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
        # Required now that the insecure-transport gate is enforced in
        # __init__ rather than only in from_connection_options().
        allow_insecure_transport=True,
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

    def test_end_of_sequence_wins_even_when_a_context_is_also_present(self):
        """``EndOfSequence`` must stop the loop even if firmware also echoes a context.

        A client that keys "keep pulling" off *presence of a context* rather than
        *absence of* ``EndOfSequence`` would issue a further ``Pull`` here and either
        loop forever or double-count the page. Only two responses are queued, so a
        client that asks for a third raises ``StopIteration`` from the mock and fails
        loudly rather than passing by accident.
        """
        client = _make_client()
        enumerate_response = _soap_response(
            '<wsen:EnumerateResponse xmlns:wsen="urn:enum"><wsen:EnumerationContext>ctx-1</wsen:EnumerationContext></wsen:EnumerateResponse>'
        )
        pull_response = _soap_response(
            '<wsen:PullResponse xmlns:wsen="urn:enum" xmlns:g="urn:x">'
            "<wsen:Items><g:Item><g:Name>one</g:Name></g:Item></wsen:Items>"
            "<wsen:EnumerationContext>ctx-1</wsen:EnumerationContext>"
            "<wsen:EndOfSequence/>"
            "</wsen:PullResponse>"
        )
        client._session.post.side_effect = [enumerate_response, pull_response]

        items = client.enumerate("CIM_BootSourceSetting")

        assert items == [{"Name": "one"}]
        assert client._session.post.call_count == 2  # Enumerate + exactly one Pull


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


class TestInsecureTransportGateIsUnbypassable:
    """The gate must hold on the direct constructor, not only the convenience
    classmethod. A gate guarding one of two entry points does not enforce the
    policy that plaintext is never selected implicitly."""

    def test_direct_constructor_refuses_plaintext_without_acknowledgement(self):
        with pytest.raises(TlsValidationError):
            WsmanClient(host="10.0.0.5", port=16992, username="admin", password="test-password-not-real", use_tls=False)

    def test_direct_constructor_allows_plaintext_when_acknowledged(self):
        client = WsmanClient(
            host="10.0.0.5",
            port=16992,
            username="admin",
            password="test-password-not-real",
            use_tls=False,
            allow_insecure_transport=True,
        )
        assert client._url.startswith("http://")
        client.close()

    def test_tls_needs_no_acknowledgement(self):
        client = WsmanClient(host="10.0.0.5", port=16993, username="admin", password="test-password-not-real")
        assert client._url.startswith("https://")
        client.close()


class TestNullMethodParametersAreOmitted:
    """A ``None`` method parameter must produce no element at all.

    Real AMT 16.1.30 rejected ChangeBootOrder with an empty ``<Source/>``:

        HTTP 400 -- "The supplied SOAP violates the corresponding XML schema
        definition."

    ``Source`` is typed as an endpoint reference, so it requires ``Address`` and
    ``ReferenceParameters`` children; an empty element is schema-invalid while an
    absent one is fine, because these parameters are optional. This is the exact
    bug that blocked IDE-R boot against real firmware, and no mock could have
    caught it -- the mock's XML parser accepted the empty element happily.
    """

    @staticmethod
    def _body_xml(params):
        client = _make_client()
        response = _soap_response("<g:ChangeBootOrder_OUTPUT xmlns:g='x'><g:ReturnValue>0</g:ReturnValue></g:ChangeBootOrder_OUTPUT>")
        client._session.post.return_value = response
        client.invoke("CIM_BootConfigSetting", "ChangeBootOrder", params)
        sent = client._session.post.call_args.kwargs.get("data") or client._session.post.call_args.args[1]
        return sent.decode() if isinstance(sent, bytes) else sent

    def test_none_parameter_emits_no_element(self):
        xml = self._body_xml({"Source": None})
        assert "ChangeBootOrder_INPUT" in xml
        assert "Source" not in xml, "an empty <Source/> is schema-invalid and real firmware rejects it"

    def test_non_none_parameter_is_still_emitted(self):
        xml = self._body_xml({"Role": 1})
        assert "Role" in xml
        assert ">1<" in xml

    def test_mixed_params_keep_the_non_null_ones(self):
        xml = self._body_xml({"Source": None, "Role": 1})
        assert "Source" not in xml
        assert "Role" in xml


def _local_name_of(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class TestDelete:
    """WS-Transfer ``Delete``, added for ``amt_alarm`` (issue #112).

    ``IPS_AlarmClockOccurrence`` is the only class this collection deletes, and it is
    addressed entirely by its ``InstanceID`` selector -- see docs/protocol-notes.md s2.10.
    """

    @staticmethod
    def _sent(client):
        call = client._session.post.call_args
        sent = call.kwargs.get("data") or call.args[1]
        return sent.decode() if isinstance(sent, bytes) else sent

    def test_sends_the_transfer_delete_action_with_the_selector_and_an_empty_body(self):
        client = _make_client()
        client._session.post.return_value = _soap_response("")
        client.delete("IPS_AlarmClockOccurrence", selectors={"InstanceID": "nightly"})
        xml = self._sent(client)
        assert "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete" in xml
        assert 'Name="InstanceID"' in xml
        assert ">nightly<" in xml
        # WS-Transfer Delete names the instance in the header and carries no body. An
        # element here would be a body firmware has no schema for.
        assert "<s:Body />" in xml or "<s:Body></s:Body>" in xml

    def test_returns_nothing_because_the_response_body_is_empty(self):
        """The vendor's captured DeleteResponse has ``<a:Body></a:Body>``.

        There is nothing to parse, so a caller wanting proof the instance is gone must
        re-read -- the same rule every other mutation here follows.
        """
        client = _make_client()
        client._session.post.return_value = _soap_response("")
        assert client.delete("IPS_AlarmClockOccurrence", selectors={"InstanceID": "nightly"}) is None

    def test_delete_is_never_retried_on_connection_error(self):
        """A mutation, so not retryable -- and the retry has a specific hazard here.

        A retry after a lost response would delete an instance a *different* caller had
        since recreated under the same key, which is possible precisely because the key
        is caller-supplied.
        """
        client = _make_client(max_retries=5)
        client._session.post.side_effect = [requests.exceptions.ConnectionError("refused"), _soap_response("")]
        with pytest.raises(ConnectionError_):
            client.delete("IPS_AlarmClockOccurrence", selectors={"InstanceID": "nightly"})
        assert client._session.post.call_count == 1

    def test_a_fault_surfaces_as_a_protocol_error(self):
        # Firmware faults a Delete for a key that does not exist; WS-Transfer has no
        # "delete if present". That is why amt_alarm reads before deciding.
        client = _make_client()
        client._session.post.return_value = _soap_response(
            '<s:Fault xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            "<s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:InvalidSelectors</s:Value></s:Subcode></s:Code>"
            '<s:Reason><s:Text xml:lang="en-US">No such instance</s:Text></s:Reason>'
            "</s:Fault>"
        )
        with pytest.raises(ProtocolError, match="Delete IPS_AlarmClockOccurrence"):
            client.delete("IPS_AlarmClockOccurrence", selectors={"InstanceID": "nope"})


class TestEmbeddedInstanceParameters:
    """A method parameter that is a nested property bag. Added for ``AddAlarm`` (#112).

    ``AddAlarm``'s body spans three namespaces (docs/protocol-notes.md s2.10.3), which no
    other method in this collection needs and which the flat parameter path structurally
    cannot express. These tests assert on the emitted XML rather than on a parsed result,
    because the namespaces *are* the thing that can be wrong.
    """

    NS_METHOD = "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AlarmClockService"
    NS_OCCURRENCE = "http://intel.com/wbem/wscim/1/ips-schema/1/IPS_AlarmClockOccurrence"

    @staticmethod
    def _sent_root(params):
        client = _make_client()
        client._session.post.return_value = _soap_response("<g:AddAlarm_OUTPUT xmlns:g='x'><g:ReturnValue>0</g:ReturnValue></g:AddAlarm_OUTPUT>")
        client.invoke("AMT_AlarmClockService", "AddAlarm", params)
        call = client._session.post.call_args
        sent = call.kwargs.get("data") or call.args[1]
        return ET.fromstring(sent)  # noqa: S314 -- the client's own envelope, built in-process

    def test_the_wrapper_is_named_in_the_enclosing_namespace_and_its_children_in_its_own(self):
        root = self._sent_root(
            {
                "AlarmTemplate": EmbeddedInstance(
                    namespace=self.NS_OCCURRENCE,
                    properties={"InstanceID": "nightly", "DeleteOnCompletion": True},
                )
            }
        )
        template = root.find(f".//{{{self.NS_METHOD}}}AlarmTemplate")
        assert template is not None, "the wrapper must be named in the method's namespace, not the instance's"
        assert [child.tag for child in template] == [
            f"{{{self.NS_OCCURRENCE}}}InstanceID",
            f"{{{self.NS_OCCURRENCE}}}DeleteOnCompletion",
        ]

    def test_nesting_reaches_a_third_namespace(self):
        root = self._sent_root(
            {
                "AlarmTemplate": EmbeddedInstance(
                    namespace=self.NS_OCCURRENCE,
                    properties={"StartTime": EmbeddedInstance(namespace=NS_CIM_COMMON, properties={"Datetime": "2030-01-02T03:04:00Z"})},
                )
            }
        )
        start_time = root.find(f".//{{{self.NS_OCCURRENCE}}}StartTime")
        assert [child.tag for child in start_time] == [f"{{{NS_CIM_COMMON}}}Datetime"]
        assert start_time[0].text == "2030-01-02T03:04:00Z"

    def test_booleans_render_lowercase_inside_an_embedded_instance_too(self):
        root = self._sent_root({"AlarmTemplate": EmbeddedInstance(namespace=self.NS_OCCURRENCE, properties={"DeleteOnCompletion": False})})
        assert root.find(f".//{{{self.NS_OCCURRENCE}}}DeleteOnCompletion").text == "false"

    def test_a_none_property_is_omitted_rather_than_emitted_empty(self):
        """The same rule as a flat ``None`` parameter, and for the same firmware reason.

        Real AMT 16.1.30 answers HTTP 400 to an empty element where an absent one is
        accepted; an embedded instance that emitted ``<Interval/>`` would reintroduce
        exactly the bug that blocked IDE-R boot.
        """
        root = self._sent_root({"AlarmTemplate": EmbeddedInstance(namespace=self.NS_OCCURRENCE, properties={"InstanceID": "nightly", "Interval": None})})
        template = root.find(f".//{{{self.NS_METHOD}}}AlarmTemplate")
        assert [child.tag for child in template] == [f"{{{self.NS_OCCURRENCE}}}InstanceID"]

    def test_property_insertion_order_survives_to_the_wire(self):
        # Both vendor implementations emit InstanceID, ElementName, StartTime, Interval,
        # DeleteOnCompletion in that order, and dict order is what carries it.
        names = ["InstanceID", "ElementName", "StartTime", "Interval", "DeleteOnCompletion"]
        root = self._sent_root({"AlarmTemplate": EmbeddedInstance(namespace=self.NS_OCCURRENCE, properties=dict.fromkeys(names, "x"))})
        template = root.find(f".//{{{self.NS_METHOD}}}AlarmTemplate")
        assert [_local_name_of(child.tag) for child in template] == names

# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""The collection's one security promise, tested against what Ansible actually emits.

Every other module test file stubs ``AnsibleModule.exit_json``/``fail_json`` with a bare
raiser and then asserts the password is absent from the kwargs the module passed in. That
assertion cannot fail. The password never reaches a module's ``exit_json(**kwargs)`` call in
the first place: it enters the result document via ``invocation.module_args``, which the
*real* ``_return_formatted`` injects from ``self.params``, and it is censored there by
``remove_values`` using the ``no_log_values`` set that the argument spec populates. Stub out
``exit_json`` and you have removed both the injection and the censoring, leaving an assertion
about a dict that structurally cannot contain a credential.

Measured: flipping ``"no_log": True`` -> ``False`` on ``amt_boot``'s password made the module
emit ``"password": "<the real password>"`` inside ``invocation.module_args`` and every one of
the seven per-module credential tests still passed, as did
``ansible-test sanity --test validate-modules`` (an explicit ``no_log: False`` reads to
validate-modules as a deliberate choice) and the integration targets (their tasks set
task-level ``no_log: true``, which censors regardless of the spec).

So this file deliberately does **not** patch ``exit_json``/``fail_json``. It lets the real
ones run, captures the JSON document they print to stdout, and asserts on the parsed result --
the same bytes the controller would receive. Two guards keep it honest:

* a positive control on every case -- ``invocation.module_args.username`` must be present and
  verbatim, proving the document really does echo the caller's arguments, so the password's
  absence from that same document means something;
* the argument-spec contract below, which is total over modules discovered by import rather
  than a hardcoded list, and which catches the ``no_log`` mutation directly rather than
  through its effect.

Capturing stdout is preferred over calling ``_return_formatted`` directly because
``_return_formatted``'s tail is private and has moved between cores (2.19 routes through
``_record_module_result``, earlier cores print inline), whereas "prints one JSON document to
stdout, then exits" is the module protocol itself and stable across every supported core.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import pkgutil
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import Mock

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins import modules as modules_package
from ansible_collections.james_crowley.intel_amt.plugins.module_utils import media_session, message_log, redirection_service
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import AmtFacts, PowerState

#: Obviously-fake credentials. The host is RFC 5737 TEST-NET-1, which is reserved for
#: documentation and is guaranteed not to route anywhere.
HOST = "192.0.2.10"
USERNAME = "amt-contract-test-user"
PASSWORD = "contract-test-password-not-real"

CONNECTION_ARGS = {
    "host": HOST,
    "username": USERNAME,
    "password": PASSWORD,
    "use_tls": False,
    "allow_insecure_transport": True,
}

#: The modules that existed when this contract was written. Discovery below must find at
#: least these; a discovery bug that returned nothing would otherwise make every
#: parametrized test in this file silently vacuous.
KNOWN_MODULES = frozenset(
    {
        "amt_boot",
        "amt_event_log",
        "amt_info",
        "amt_log_clear",
        "amt_media",
        "amt_power",
        "amt_redirection",
    }
)

#: An option name matching this is credential-shaped and must be ``no_log: True`` unless it
#: appears in :data:`DELIBERATELY_NOT_SECRET` below.
CREDENTIAL_SHAPED_NAME = re.compile(r"(?i)(?:^|_)(?:password|passwd|pwd|passphrase|secret|token|key|apikey|credential|credentials)(?:$|_)")

#: Options whose name is credential-shaped but whose value is deliberately not a secret.
#: Each must carry an *explicit* ``no_log: False`` -- the point is that the decision was
#: made and written down, not defaulted into.
#:
#: ``amt_boot.action_token`` is a caller-supplied one-time acknowledgement gate for arming a
#: boot selection. Its whole job is to appear in the audit trail of the run that armed the
#: boot, so censoring it would defeat the reason it exists.
DELIBERATELY_NOT_SECRET = frozenset({("amt_boot", "action_token")})

#: The names an Ansible module may use for its argument-spec accessor, most complete first.
#: ``argument_spec`` returns connection options plus module-specific ones; a module that has
#: only connection options exposes ``_connection_argument_spec`` alone.
SPEC_ACCESSOR_NAMES = ("argument_spec", "_argument_spec", "_connection_argument_spec")


def discover_modules() -> dict[str, Any]:
    """Every module in the collection, by import rather than by a list maintained here.

    Module eight is covered by every test in this file the moment it is added.
    """
    discovered = {}
    for info in pkgutil.iter_modules(modules_package.__path__):
        discovered[info.name] = importlib.import_module(f"{modules_package.__name__}.{info.name}")
    return dict(sorted(discovered.items()))


DISCOVERED_MODULES = discover_modules()
MODULE_NAMES = sorted(DISCOVERED_MODULES)


def argument_spec_of(module_name: str) -> dict[str, dict]:
    module = DISCOVERED_MODULES[module_name]
    for accessor_name in SPEC_ACCESSOR_NAMES:
        accessor = getattr(module, accessor_name, None)
        if callable(accessor):
            return accessor()
    raise AssertionError(
        f"{module_name} exposes none of {SPEC_ACCESSOR_NAMES} as a callable, so its argument "
        "spec cannot be inspected. Every module in this collection must expose its spec through "
        "one of those names -- otherwise this file's contract silently stops covering it."
    )


class TestDiscovery:
    """Discovery itself has to be trustworthy, or everything parametrized over it is vacuous."""

    def test_every_known_module_is_discovered(self):
        assert KNOWN_MODULES <= set(MODULE_NAMES)

    def test_every_discovered_module_exposes_an_inspectable_argument_spec(self):
        for module_name in MODULE_NAMES:
            spec = argument_spec_of(module_name)
            assert isinstance(spec, dict) and spec, f"{module_name} returned an empty argument spec"


class TestArgumentSpecCredentialContract:
    """The cheap, total check: the mutation that went undetected is caught here directly."""

    @pytest.mark.parametrize("module_name", MODULE_NAMES)
    def test_password_is_no_log(self, module_name):
        spec = argument_spec_of(module_name)
        assert "password" in spec, f"{module_name} has no password option; connection options are shared and must stay so"
        assert spec["password"].get("no_log") is True, (
            f"{module_name}'s password option is not no_log: True. Without it the credential is "
            "emitted verbatim inside invocation.module_args of every result the module returns."
        )

    @pytest.mark.parametrize("module_name", MODULE_NAMES)
    def test_password_is_required_and_a_string(self, module_name):
        # A password with a default would put a credential in the argument spec itself, which
        # ansible-doc publishes.
        spec = argument_spec_of(module_name)["password"]
        assert spec["type"] == "str"
        assert spec.get("required") is True
        assert "default" not in spec

    @pytest.mark.parametrize("module_name", MODULE_NAMES)
    def test_every_credential_shaped_option_is_no_log(self, module_name):
        spec = argument_spec_of(module_name)
        offenders = {
            option_name
            for option_name in spec
            if CREDENTIAL_SHAPED_NAME.search(option_name)
            and (module_name, option_name) not in DELIBERATELY_NOT_SECRET
            and spec[option_name].get("no_log") is not True
        }
        assert not offenders, (
            f"{module_name} has credential-shaped options that are not no_log: True: {sorted(offenders)}. "
            "Either mark them no_log: True, or add them to DELIBERATELY_NOT_SECRET in this file with "
            "an explicit no_log: False in the spec and a note saying why the value is not a secret."
        )

    def test_each_deliberate_exception_still_exists_and_is_still_explicit(self):
        # If one of these options is renamed or removed, this fails rather than leaving a stale
        # exemption behind that would excuse a genuinely secret option of the same name later.
        for module_name, option_name in sorted(DELIBERATELY_NOT_SECRET):
            spec = argument_spec_of(module_name)
            assert option_name in spec, f"{module_name} no longer has a {option_name!r} option; remove the stale exemption"
            assert spec[option_name].get("no_log") is False, (
                f"{module_name}.{option_name} is exempted from the no_log requirement, so it must say "
                'so with an explicit "no_log": False rather than omitting the key.'
            )

    def test_the_exception_list_is_not_a_blanket_pass(self):
        # A guard on the guard: if DELIBERATELY_NOT_SECRET ever grew to cover `password`, the
        # test above would pass while the invariant was gone.
        exempted_options = {option_name for _module_name, option_name in DELIBERATELY_NOT_SECRET}
        assert "password" not in exempted_options


def set_module_args(args: dict) -> None:
    basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    # ansible-core >= 2.18 requires an explicit args-decoding profile alongside _ANSIBLE_ARGS;
    # "legacy" is the plain-JSON profile, which is what this hand-built buffer actually is.
    basic._ANSIBLE_PROFILE = "legacy"


@dataclass(frozen=True)
class EmittedResult:
    """What a module really wrote to stdout, plus the exit status it used."""

    exit_code: int
    raw: str
    document: dict


def emit(module_name: str, args: dict) -> EmittedResult:
    """Run a module's ``main()`` with the real ``exit_json``/``fail_json`` and capture the result.

    ``exit_json``/``fail_json`` print one JSON document to stdout and then ``sys.exit``. Both
    halves matter here: the document is where ``invocation.module_args`` is injected and where
    ``no_log`` censoring is applied, and the non-local exit is the only proof the module
    terminated through one of them rather than falling off the end of ``main()``.
    """
    set_module_args(args)
    buffer = io.StringIO()
    exit_code: int | None = None
    with contextlib.redirect_stdout(buffer):
        try:
            DISCOVERED_MODULES[module_name].main()
        except SystemExit as exc:
            exit_code = 0 if exc.code is None else int(exc.code)
    raw = buffer.getvalue()
    assert exit_code is not None, f"{module_name}.main() returned without calling exit_json or fail_json; nothing was serialized"
    assert raw.strip(), f"{module_name} exited with {exit_code} but printed no result document"
    return EmittedResult(exit_code=exit_code, raw=raw, document=json.loads(raw))


def assert_credential_absent_from(result: EmittedResult, module_name: str) -> None:
    """The actual invariant, plus the positive control that keeps it from being vacuous."""
    module_args = result.document["invocation"]["module_args"]

    # Positive control. If this fails, the document is not echoing the caller's arguments and
    # the credential assertions below prove nothing -- which is exactly how the original
    # per-module tests came to pass against a leaking module.
    assert module_args["username"] == USERNAME, (
        f"{module_name}'s result does not echo module_args verbatim, so this test cannot show that the password was censored rather than merely absent"
    )
    assert module_args["password"] != PASSWORD, f"{module_name} emitted the caller's password verbatim in invocation.module_args"
    assert PASSWORD not in result.raw, f"{module_name} emitted the caller's password somewhere in its result document"


@dataclass
class ModuleScenario:
    """One module plus enough wiring to reach a real ``exit_json``."""

    module_name: str
    extra_args: dict = field(default_factory=dict)
    wire: Callable[[pytest.MonkeyPatch, Any], dict] | None = None

    def build_args(self, monkeypatch, tmp_path) -> dict:
        args = dict(CONNECTION_ARGS, **self.extra_args)
        if self.wire is not None:
            args.update(self.wire(monkeypatch, tmp_path) or {})
        return args


def _fake_wsman(**attributes) -> Mock:
    wsman = Mock(endpoint=f"{HOST}:16992", last_peer_certificate=None, **attributes)
    return wsman


def _wire_boot(monkeypatch, _tmp_path) -> dict:
    client = _fake_wsman()
    capabilities = {"ForcePXEBoot": "true", "ForceHardDriveBoot": "true", "ForceCDorDVDBoot": "true", "BIOSSetup": "true", "IDER": "true", "SOL": "true"}
    sources = [{"InstanceID": "Intel(r) AMT: Force PXE Boot"}]
    client.enumerate.side_effect = lambda resource_class, **kwargs: [capabilities] if resource_class == "AMT_BootCapabilities" else sources
    client.get.return_value = {"InstanceID": "Intel(r) AMT: Boot Configuration Data", "UseIDER": "false"}
    client.invoke.return_value = ({"ReturnValue": "0"}, 0)
    client.put.return_value = {}
    monkeypatch.setattr(DISCOVERED_MODULES["amt_boot"].WsmanClient, "from_connection_options", classmethod(lambda cls, **kwargs: client))
    return {}


def _wire_redirection(monkeypatch, _tmp_path) -> dict:
    client = _fake_wsman()
    client.enumerate.return_value = [{"IDER": "true", "SOL": "true"}]
    client.get.return_value = {"EnabledState": "32768", "ListenerEnabled": "false"}
    client.invoke.return_value = ({"ReturnValue": "0"}, 0)
    monkeypatch.setattr(DISCOVERED_MODULES["amt_redirection"].WsmanClient, "from_connection_options", classmethod(lambda cls, **kwargs: client))
    # The reachability probe's socket factory is a *default argument*, bound at import time, so
    # patching socket.create_connection would not reach it. See test_amt_redirection.py.
    refuse = Mock(side_effect=OSError("no real sockets in unit tests"))
    monkeypatch.setitem(redirection_service.get_status.__kwdefaults__, "connect", refuse)
    monkeypatch.setitem(redirection_service.probe_transport_reachable.__kwdefaults__, "connect", refuse)
    return {}


def _wire_info(monkeypatch, _tmp_path) -> dict:
    amt_info = DISCOVERED_MODULES["amt_info"]
    client = Mock()
    client.get_facts.return_value = AmtFacts()
    monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman())
    monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: client)
    return {}


def _wire_power(monkeypatch, _tmp_path) -> dict:
    amt_power = DISCOVERED_MODULES["amt_power"]
    client = Mock()
    client.get_power_state.return_value = PowerState.from_cim_value(2)
    monkeypatch.setattr(amt_power, "build_wsman_client", lambda params: _fake_wsman())
    monkeypatch.setattr(amt_power, "AmtClient", lambda wsman: client)
    return {"state": "query"}


def _log_properties(record_count: int) -> message_log.MessageLogProperties:
    return message_log.MessageLogProperties(
        current_number_of_records=record_count,
        max_number_of_records=390,
        max_record_size=21,
        element_name="Intel(r) AMT:MessageLog 1",
        is_frozen=False,
        log_state=4,
        overwrite_policy=2,
        capabilities=[5, 6, 8, 7],
    )


def _wire_event_log(monkeypatch, _tmp_path) -> dict:
    amt_event_log = DISCOVERED_MODULES["amt_event_log"]
    read = message_log.MessageLogRead(
        properties=_log_properties(0),
        records=[],
        total_records=0,
        truncated=False,
        complete=True,
        stop_reason="no_record_exists",
        batches=0,
    )
    monkeypatch.setattr(amt_event_log, "build_wsman_client", lambda params: _fake_wsman())
    monkeypatch.setattr(amt_event_log.message_log, "read_records", lambda _wsman, **kwargs: read)
    return {}


def _wire_log_clear(monkeypatch, _tmp_path) -> dict:
    amt_log_clear = DISCOVERED_MODULES["amt_log_clear"]
    monkeypatch.setattr(amt_log_clear, "build_wsman_client", lambda params: _fake_wsman())
    # An already-empty log: a confirmed run that has nothing to clear still returns a full
    # result document, which is all this file needs.
    monkeypatch.setattr(amt_log_clear.message_log, "get_log_properties", lambda _wsman: _log_properties(0))
    return {"confirm_destructive": True}


def _wire_media(monkeypatch, tmp_path) -> dict:
    floppy = tmp_path / "floppy.img"
    floppy.write_bytes(b"\x00" * 512)
    attached = {
        "session_id": "contract-session",
        "pid": 4242,
        "state": media_session.STATE_ATTACHED,
        "error": None,
        "tls_peer_fingerprint": None,
        "devices": {},
    }
    monkeypatch.setattr(media_session, "spawn_session", lambda *args, **kwargs: 4242)
    monkeypatch.setattr(media_session, "wait_for_state", lambda *args, **kwargs: attached)
    monkeypatch.setattr(media_session, "is_pid_alive", lambda pid: True)
    return {"state": "attached", "floppy": str(floppy), "runtime_dir": str(tmp_path / "runtime")}


SUCCESS_SCENARIOS = (
    ModuleScenario("amt_boot", extra_args={"device": "pxe", "action_token": "contract-test-token"}, wire=_wire_boot),
    ModuleScenario("amt_event_log", wire=_wire_event_log),
    ModuleScenario("amt_info", wire=_wire_info),
    ModuleScenario("amt_log_clear", wire=_wire_log_clear),
    ModuleScenario("amt_media", wire=_wire_media),
    ModuleScenario("amt_power", wire=_wire_power),
    ModuleScenario("amt_redirection", wire=_wire_redirection),
)

SCENARIOS_BY_NAME = {scenario.module_name: scenario for scenario in SUCCESS_SCENARIOS}

#: Minimal module-specific arguments that satisfy `required=True` without any transport at all.
#: Used for the failure path, which fails inside ``AnsibleModule.__init__``.
REQUIRED_ARGS = {
    "amt_boot": {"device": "pxe", "action_token": "contract-test-token"},
    "amt_media": {"state": "attached"},
}


class TestEveryModuleIsWiredIntoThisFile:
    def test_no_discovered_module_is_missing_a_success_scenario(self):
        # A new module with no scenario here would simply not be exercised against the real
        # serializer, which is the whole point of this file.
        assert set(MODULE_NAMES) == set(SCENARIOS_BY_NAME), (
            "every module must have a success scenario in SUCCESS_SCENARIOS: missing "
            f"{sorted(set(MODULE_NAMES) - set(SCENARIOS_BY_NAME))}, stale {sorted(set(SCENARIOS_BY_NAME) - set(MODULE_NAMES))}"
        )


class TestCredentialNeverReachesTheEmittedDocument:
    """Against the real ``exit_json``/``fail_json``, not a stub."""

    @pytest.mark.parametrize("scenario", SUCCESS_SCENARIOS, ids=lambda scenario: scenario.module_name)
    def test_a_successful_run_censors_the_password(self, monkeypatch, tmp_path, scenario):
        args = scenario.build_args(monkeypatch, tmp_path)
        result = emit(scenario.module_name, args)
        assert result.exit_code == 0, f"expected a successful exit, got {result.exit_code}: {result.document.get('msg')}"
        assert_credential_absent_from(result, scenario.module_name)

    @pytest.mark.parametrize("module_name", MODULE_NAMES)
    def test_an_argument_validation_failure_censors_the_password(self, module_name):
        # The failure path needs no transport: an un-coercible `port` fails inside
        # AnsibleModule.__init__, which is the earliest point a module can emit a result. It is
        # worth pinning precisely because it is early -- no_log_values is populated from the
        # spec just *before* this fail_json, and a core that reordered those two steps would
        # leak the credential out of every module at once.
        args = dict(CONNECTION_ARGS, port="not-an-int", **REQUIRED_ARGS.get(module_name, {}))
        result = emit(module_name, args)
        assert result.exit_code != 0
        assert result.document["failed"] is True
        assert_credential_absent_from(result, module_name)

    def test_a_credential_the_endpoint_echoes_back_is_censored_too(self, monkeypatch, tmp_path):
        """Defence in depth: a credential arriving from *outside* the module is censored as well.

        ``amt_media``'s attach failure surfaces whatever text the session daemon recorded, and a
        daemon killed during the digest handshake can record a message quoting what it sent. The
        module does not redact that string itself; it relies on ansible-core substituting every
        occurrence of a ``no_log`` value across the whole result document. That coupling is
        precisely what the missing flag would break, and only the real serializer can show it
        holding -- with ``exit_json`` stubbed, the password sails straight through.
        """
        floppy = tmp_path / "floppy.img"
        floppy.write_bytes(b"\x00" * 512)
        error_state = {
            "session_id": "contract-session",
            "state": media_session.STATE_ERROR,
            "pid": 4242,
            "error": f"IDE-R digest handshake rejected (password={PASSWORD})",
            "error_class": "authentication",
            "devices": {},
        }
        monkeypatch.setattr(media_session, "spawn_session", lambda *args, **kwargs: 4242)
        monkeypatch.setattr(media_session, "wait_for_state", lambda *args, **kwargs: error_state)
        args = dict(
            CONNECTION_ARGS,
            state="attached",
            floppy=str(floppy),
            runtime_dir=str(tmp_path / "runtime"),
        )
        result = emit("amt_media", args)
        assert result.exit_code != 0
        assert result.document["error_class"] == "authentication"
        # The diagnosis survives, only the credential does not.
        assert "IDE-R digest handshake rejected" in result.document["msg"]
        assert_credential_absent_from(result, "amt_media")

    @pytest.mark.parametrize("module_name", MODULE_NAMES)
    def test_the_password_is_censored_rather_than_dropped(self, module_name):
        # Distinguishes "no_log removed the value" from "the key happened to be absent". A
        # module that stopped emitting invocation.module_args at all would still satisfy a bare
        # `password not in output` assertion while telling us nothing.
        args = dict(CONNECTION_ARGS, port="not-an-int", **REQUIRED_ARGS.get(module_name, {}))
        module_args = emit(module_name, args).document["invocation"]["module_args"]
        assert "password" in module_args
        assert module_args["password"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"

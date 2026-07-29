# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import message_log
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    ProtocolError,
    RemoteOperationError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_log_clear

PASSWORD = "Sup3rSecret!"

BASE_ARGS = {
    "host": "192.0.2.10",
    "username": "admin",
    "password": PASSWORD,
    "tls_fingerprint": "aa" * 32,
}

CONFIRMED_ARGS = {**BASE_ARGS, "confirm_destructive": True}


def _set_module_args(args: dict) -> None:
    basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    basic._ANSIBLE_PROFILE = "legacy"


class AnsibleExitJson(Exception):
    pass


class AnsibleFailJson(Exception):
    pass


def _exit_json(*_args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _fail_json(*_args, **kwargs):
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def _patch_module_exit(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


def _properties(count: int | None) -> message_log.MessageLogProperties:
    return message_log.MessageLogProperties(
        current_number_of_records=count,
        max_number_of_records=390,
        max_record_size=21,
        element_name="Intel(r) AMT:MessageLog 1",
        is_frozen=False,
        log_state=4,
        overwrite_policy=2,
        capabilities=[5, 6, 8, 7],
    )


class Recorder:
    """Records exactly which transport operations the module performed.

    ``get_log_properties`` serves a queue so the before/after reads can differ,
    which is the whole point of the receipt: the "after" count is *observed*, not
    assumed from ``ReturnValue``.
    """

    def __init__(self, counts, *, clear_error=None, properties_error=None):
        self.queue = list(counts)
        self.clear_error = clear_error
        self.properties_error = properties_error
        self.calls: list[str] = []

    def get_log_properties(self, _wsman):
        self.calls.append("get_log_properties")
        if self.properties_error is not None:
            raise self.properties_error
        count = self.queue.pop(0) if self.queue else None
        return _properties(count)

    def clear_log(self, _wsman):
        self.calls.append("clear_log")
        if self.clear_error is not None:
            raise self.clear_error
        return 0


def _wire(monkeypatch, recorder: Recorder) -> Recorder:
    monkeypatch.setattr(amt_log_clear, "build_wsman_client", lambda params: Mock(endpoint="192.0.2.10:16993", last_peer_certificate=None))
    monkeypatch.setattr(amt_log_clear.message_log, "get_log_properties", recorder.get_log_properties)
    monkeypatch.setattr(amt_log_clear.message_log, "clear_log", recorder.clear_log)
    return recorder


def _payload(args: dict, *, check_mode: bool) -> dict:
    payload = dict(args)
    if check_mode:
        payload["_ansible_check_mode"] = True
    return payload


def _run_ok(args: dict, *, check_mode: bool = False) -> dict:
    """Run the module and require that it *succeeded*.

    Split out from a single helper that accepted either outcome. For a destructive module that
    distinction is the whole contract: "refused" and "cleared the log" are the two outcomes, and
    a helper that treats them as interchangeable cannot assert either.

    Measured, on the mutation that matters most: making ``main()``'s ``except AmtError`` handler
    call ``exit_json(changed=False, **err.to_result())`` instead of ``fail_json`` -- so both the
    confirmation gate and every firmware refusal become non-fatal, exactly the prior-art defect
    this module exists to avoid -- left origin/main's whole file green at 26 passed. With the two
    helpers, eight tests fail.
    """
    _set_module_args(_payload(args, check_mode=check_mode))
    with pytest.raises(AnsibleExitJson) as excinfo:
        amt_log_clear.main()
    return excinfo.value.args[0]


def _run_fail(args: dict, *, check_mode: bool = False) -> dict:
    """Run the module and require that it *failed* via fail_json."""
    _set_module_args(_payload(args, check_mode=check_mode))
    with pytest.raises(AnsibleFailJson) as excinfo:
        amt_log_clear.main()
    return excinfo.value.args[0]


class TestArgumentSpec:
    def test_password_is_no_log(self):
        assert amt_log_clear.argument_spec()["password"]["no_log"] is True

    def test_confirm_destructive_defaults_to_false(self):
        spec = amt_log_clear.argument_spec()["confirm_destructive"]
        assert spec["type"] == "bool"
        assert spec["default"] is False

    def test_the_option_surface_stays_small(self):
        spec = amt_log_clear.argument_spec()
        connection = set(amt_log_clear._connection_argument_spec())
        assert set(spec) - connection == {"confirm_destructive"}


class TestConfirmationGate:
    def test_a_bare_invocation_refuses_and_clears_nothing(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([6, 0]))
        result = _run_fail(BASE_ARGS)
        assert result["error_class"] == "invalid_state"
        assert "confirm_destructive" in result["msg"]
        # Nothing at all was done -- not even a read. An unconfirmed invocation
        # does not touch the endpoint.
        assert recorder.calls == []

    def test_the_refusal_message_is_the_shared_constant(self, monkeypatch):
        _wire(monkeypatch, Recorder([6, 0]))
        assert _run_fail(BASE_ARGS)["msg"] == amt_log_clear.CONFIRMATION_REQUIRED_MSG

    def test_explicit_false_refuses_just_as_a_bare_invocation_does(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([6, 0]))
        result = _run_fail({**BASE_ARGS, "confirm_destructive": False})
        assert result["error_class"] == "invalid_state"
        assert recorder.calls == []

    def test_the_gate_refuses_in_check_mode_too(self, monkeypatch):
        """``--check`` previews a correctly-configured play; it does not bypass the gate."""
        recorder = _wire(monkeypatch, Recorder([6, 0]))
        result = _run_fail(BASE_ARGS, check_mode=True)
        assert result["error_class"] == "invalid_state"
        assert recorder.calls == []

    def test_confirmation_true_proceeds(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([6, 0]))
        result = _run_ok(CONFIRMED_ARGS)
        assert result["changed"] is True
        assert "clear_log" in recorder.calls


class TestCheckMode:
    def test_check_mode_really_reads_the_record_count(self, monkeypatch):
        """The prior art exits changed=false without reading anything at all."""
        recorder = _wire(monkeypatch, Recorder([6]))
        result = _run_ok(CONFIRMED_ARGS, check_mode=True)
        assert recorder.calls == ["get_log_properties"]
        assert result["records_before"] == 6

    def test_check_mode_reports_the_intended_change_without_clearing(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([6]))
        result = _run_ok(CONFIRMED_ARGS, check_mode=True)
        assert result["changed"] is True
        assert result["cleared"] is False
        assert result["records_after"] is None
        assert result["return_value"] is None
        assert "clear_log" not in recorder.calls

    def test_check_mode_on_an_already_empty_log_reports_no_change(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([0]))
        result = _run_ok(CONFIRMED_ARGS, check_mode=True)
        assert result["changed"] is False
        assert result["records_before"] == 0
        assert "clear_log" not in recorder.calls

    def test_check_mode_receipt_records_what_would_be_destroyed(self, monkeypatch):
        _wire(monkeypatch, Recorder([42]))
        operation = _run_ok(CONFIRMED_ARGS, check_mode=True)["operation"]
        assert operation["previous"] == {"current_number_of_records": 42}
        assert operation["desired"] == {"current_number_of_records": 0}
        assert operation["observed"] is None
        assert operation["changed"] is True


class TestClear:
    def test_a_successful_clear_records_before_and_after(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([6, 0]))
        result = _run_ok(CONFIRMED_ARGS)
        assert result["changed"] is True
        assert result["cleared"] is True
        assert result["records_before"] == 6
        assert result["records_after"] == 0
        assert result["return_value"] == 0
        # Read, clear, read again -- the after count is observed, not assumed.
        assert recorder.calls == ["get_log_properties", "clear_log", "get_log_properties"]

    def test_the_after_count_is_observed_rather_than_assumed_to_be_zero(self, monkeypatch):
        """``ReturnValue == 0`` means AMT accepted the request, not that the log is empty."""
        _wire(monkeypatch, Recorder([6, 3]))
        result = _run_ok(CONFIRMED_ARGS)
        assert result["records_after"] == 3
        assert result["operation"]["observed"] == {"current_number_of_records": 3}

    def test_the_receipt_is_the_documented_schema(self, monkeypatch):
        _wire(monkeypatch, Recorder([6, 0]))
        operation = _run_ok(CONFIRMED_ARGS)["operation"]
        assert operation["schema"] == "intel-amt-operation/v1"
        assert operation["action"] == "amt_log_clear.clear"
        assert operation["endpoint"] == "192.0.2.10:16993"
        assert operation["previous"] == {"current_number_of_records": 6}
        assert operation["desired"] == {"current_number_of_records": 0}
        assert operation["observed"] == {"current_number_of_records": 0}
        assert operation["error_class"] is None

    def test_the_log_container_properties_are_surfaced(self, monkeypatch):
        _wire(monkeypatch, Recorder([6, 0]))
        log = _run_ok(CONFIRMED_ARGS)["log"]
        # Capability 6 is ClearLogSupported -- firmware saying the method exists.
        assert 6 in log["capabilities"]
        assert log["max_record_size"] == 21

    # The password assertion that used to close this class was deleted rather than repaired: with
    # exit_json replaced by the bare raiser in the autouse fixture above, the credential could not
    # be in those kwargs, because the real exit_json is what injects invocation.module_args and
    # applies no_log censoring. That invariant now runs against the real serializer in
    # tests/unit/plugins/modules/test_credential_contract.py. The failure-path redaction test at
    # the bottom of this file stays: there the credential really is in the text being handled,
    # and it is this collection's own errors.redact that has to remove it.


class TestAlreadyEmptyLog:
    def test_an_empty_log_is_a_no_op_reporting_changed_false(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([0]))
        result = _run_ok(CONFIRMED_ARGS)
        assert result["changed"] is False
        assert result["cleared"] is False
        assert result["records_before"] == 0
        assert result["records_after"] is None
        assert recorder.calls == ["get_log_properties"]

    def test_an_unknown_record_count_attempts_the_clear_rather_than_assuming_clean(self, monkeypatch):
        """``None`` is "firmware did not say", which is not "already empty"."""
        recorder = _wire(monkeypatch, Recorder([None, None]))
        result = _run_ok(CONFIRMED_ARGS)
        assert result["changed"] is True
        assert result["cleared"] is True
        assert result["records_before"] is None
        assert "clear_log" in recorder.calls


class TestPlan:
    def test_zero_records_means_nothing_to_do(self):
        assert amt_log_clear.plan(0) is False

    def test_records_present_means_clear(self):
        assert amt_log_clear.plan(1) is True
        assert amt_log_clear.plan(390) is True

    def test_an_unknown_count_is_not_treated_as_already_clean(self):
        assert amt_log_clear.plan(None) is True


class TestFailureClassification:
    """A firmware refusal must be a task failure, and a classified one.

    Two weak assertions were replaced here.

    ``assert "changed" not in result or result["changed"] is not True`` claimed to prove the run
    was "emphatically not a success". It does not: ``AmtError.to_result()`` has never produced a
    ``changed`` key, so the first disjunct holds on every failure, and the realistic demotion --
    ``exit_json(changed=False, **err.to_result())`` -- satisfies the second. Both were measured.
    What actually separates "failed the task" from "demoted it to a warning" is which of
    ``exit_json`` and ``fail_json`` ran, so ``_run_fail`` requires it.

    ``assert "Traceback" not in json.dumps(result)`` is narrower than it looks rather than dead:
    it does catch a traceback string being added to ``to_result()`` (measured -- that mutation
    fails all four of these tests on origin/main). What it misses is everything else about the
    message. Changing ``to_result``'s msg to ``repr(self)``, which is how a traceback-ish blob
    would realistically arrive, failed exactly one test in origin/main's file and seven here. So
    the message is now pinned exactly, and the key that would actually carry a traceback --
    ``exception``, which ``fail_json`` accepts and no module passes -- is asserted absent.
    """

    def test_a_non_zero_return_value_fails_with_remote_operation(self, monkeypatch):
        """The specific defect in the prior art: it demotes this to a warning and succeeds."""
        error = RemoteOperationError(
            "AMT_MessageLog.ClearLog returned ReturnValue=5",
            endpoint="192.0.2.10:16993",
            operation="AMT_MessageLog.ClearLog",
            return_value=5,
        )
        recorder = _wire(monkeypatch, Recorder([6, 6], clear_error=error))
        result = _run_fail(CONFIRMED_ARGS)
        assert result["error_class"] == "remote_operation"
        assert result["return_value"] == 5
        # The clear really was attempted -- this is a firmware refusal, not a pre-flight veto --
        # and the failure was raised instead of being smoothed over into a second read.
        assert recorder.calls == ["get_log_properties", "clear_log"]

    def test_absent_class_reports_unsupported_capability(self, monkeypatch):
        error = UnsupportedCapabilityError("AMT_MessageLog is not available", endpoint="192.0.2.10:16993")
        _wire(monkeypatch, Recorder([], properties_error=error))
        result = _run_fail(CONFIRMED_ARGS)
        assert result["error_class"] == "unsupported_capability"
        assert result["msg"] == "AMT_MessageLog is not available"
        assert "exception" not in result

    def test_a_faulting_read_reports_protocol(self, monkeypatch):
        recorder = _wire(monkeypatch, Recorder([], properties_error=ProtocolError("SOAP Fault", endpoint="192.0.2.10:16993")))
        result = _run_fail(CONFIRMED_ARGS)
        assert result["error_class"] == "protocol"
        assert result["msg"] == "SOAP Fault"
        assert "exception" not in result
        # A read that faulted must not be followed by the destructive call.
        assert "clear_log" not in recorder.calls

    def test_a_failure_message_is_redacted(self, monkeypatch):
        error = ProtocolError(f"failed with password={PASSWORD}", endpoint="192.0.2.10:16993", secrets=PASSWORD)
        _wire(monkeypatch, Recorder([], properties_error=error))
        result = _run_fail(CONFIRMED_ARGS)
        assert PASSWORD not in json.dumps(result)
        # Redacted, not truncated: the caller still learns which field was involved.
        assert result["msg"] == "failed with password=[REDACTED]"

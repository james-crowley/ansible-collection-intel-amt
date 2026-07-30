# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for the ``amt_media`` module's decision logic.

``media_session.spawn_session`` (the real fork -> connect -> IDE-R pump path) is
mocked throughout: it is exercised for real by the integration test target against
the mock IDE-R server, which is the only place a real fork and a real (loopback)
network connection belong. These tests are about the module's own logic --
idempotency against an existing session, stale-session recovery, option validation,
check-mode, and error surfacing -- all of which is fully exercisable without ever
forking or opening a socket.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from unittest.mock import patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import media_session
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import TlsValidationError
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_media

BASE_ARGS = {
    "host": "10.0.0.5",
    "username": "admin",
    "password": "test-password-not-real",
    "use_tls": False,
    "allow_insecure_transport": True,
}


class AnsibleExitJson(Exception):
    def __init__(self, kwargs):
        super().__init__("exit_json")
        self.kwargs = kwargs


class AnsibleFailJson(Exception):
    def __init__(self, kwargs):
        super().__init__("fail_json")
        self.kwargs = kwargs


def _set_module_args(args: dict) -> None:
    basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    basic._ANSIBLE_PROFILE = "legacy"


def _exit_json(*_args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _fail_json(*_args, **kwargs):
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def _patch_exit_and_fail(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


@pytest.fixture
def floppy_image(tmp_path):
    path = tmp_path / "floppy.img"
    path.write_bytes(b"\x00" * 512)
    return str(path)


@pytest.fixture
def runtime_dir(tmp_path):
    path = tmp_path / "runtime"
    return str(path)


def _attach_args(*, runtime_dir, floppy_image, **overrides) -> dict:
    args = dict(BASE_ARGS, floppy=floppy_image, state="attached", runtime_dir=runtime_dir)
    args.update(overrides)
    return args


class TestAttachFreshSession:
    def test_spawns_and_reports_changed_true(self, runtime_dir, floppy_image):
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image))
        attached_state = {
            "session_id": "will-be-overwritten",
            "pid": 4242,
            "state": "attached",
            "error": None,
            "tls_peer_fingerprint": None,
            "devices": {"floppy": {"path": floppy_image, "writable": False, "size": 512, "bytes_read": 0, "bytes_written": 0}},
        }
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session", return_value=4242) as spawn,
            patch(
                "ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_state",
                return_value=attached_state,
            ),
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        result = excinfo.value.kwargs
        assert result["changed"] is True
        assert result["session_state"] == "attached"
        assert result["pid"] == 4242
        assert result["bytes_read"] == 0
        assert result["bytes_written"] == 0
        assert result.get("session_id")
        spawn.assert_called_once()
        # The config handed to spawn_session must carry the resolved plaintext redirection
        # port (16994, since use_tls=False here), never the WS-Man port.
        config = spawn.call_args.args[0]
        assert config.port == 16994
        assert config.devices[0].device_code == media_session.ider.DEVICE_FLOPPY

    def test_receipt_is_nested_under_operation_not_spread_at_top_level(self, runtime_dir, floppy_image):
        # issue #22: the receipt lives under `operation`, never spread at the top level
        # alongside module-specific keys like `session_id`/`session_state`/`devices`.
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image))
        attached_state = {
            "session_id": "will-be-overwritten",
            "pid": 4242,
            "state": "attached",
            "error": None,
            "tls_peer_fingerprint": "aa" * 32,
            "devices": {"floppy": {"path": floppy_image, "writable": False, "size": 512, "bytes_read": 0, "bytes_written": 0}},
        }
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session", return_value=4242),
            patch(
                "ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_state",
                return_value=attached_state,
            ),
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        result = excinfo.value.kwargs
        for moved_field in ("schema", "action", "endpoint", "previous", "desired", "observed"):
            assert moved_field not in result, f"{moved_field!r} must not be spread at the top level; it belongs under operation"
        # tls_peer_fingerprint in particular used to be spread at the top level (from the
        # receipt) *and* duplicated via _status_fields -- it now lives only under operation.
        assert "tls_peer_fingerprint" not in result
        assert result["operation"]["schema"] == "intel-amt-operation/v1"
        assert result["operation"]["action"] == "amt_media.attach"
        assert result["operation"]["tls_peer_fingerprint"] == "aa" * 32
        assert result["operation"]["error_class"] is None

    def test_generated_session_id_is_returned_for_a_later_detach(self, runtime_dir, floppy_image):
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image))
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session", return_value=1),
            patch(
                "ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_state",
                return_value={"state": "attached", "pid": 1, "devices": {}},
            ),
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        session_id = excinfo.value.kwargs["session_id"]
        assert isinstance(session_id, str) and len(session_id) == 32

    def test_daemon_reporting_error_fails_the_module(self, runtime_dir, floppy_image):
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image))
        error_state = {"state": "error", "error": "connection refused", "error_class": "connection", "pid": 99, "devices": {}}
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session", return_value=99),
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_state", return_value=error_state),
        ):
            with pytest.raises(AnsibleFailJson) as excinfo:
                amt_media.main()
        # The daemon's own error_class (e.g. "connection", "authentication", ...) is
        # preserved rather than collapsed into a generic "protocol" bucket -- see
        # media_session._run_daemon's _fail() helper.
        assert excinfo.value.kwargs["error_class"] == "connection"
        assert "connection refused" in excinfo.value.kwargs["msg"]

    def test_daemon_reporting_an_unclassified_error_falls_back_to_protocol(self, runtime_dir, floppy_image):
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image))
        error_state = {"state": "error", "error": "something odd", "pid": 99, "devices": {}}  # no error_class key at all
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session", return_value=99),
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_state", return_value=error_state),
        ):
            with pytest.raises(AnsibleFailJson) as excinfo:
                amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "protocol"


class TestAttachIdempotency:
    def test_existing_live_session_is_not_respawned(self, runtime_dir, floppy_image):
        session_id = "existing-session"
        media_session._write_state_atomic(
            runtime_dir,
            session_id,
            {"session_id": session_id, "pid": os.getpid(), "state": "attached", "devices": {}, "error": None, "tls_peer_fingerprint": None},
        )
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image, session_id=session_id))
        with patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session") as spawn:
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        result = excinfo.value.kwargs
        assert result["changed"] is False
        assert result["session_id"] == session_id
        spawn.assert_not_called()

    def test_stale_session_file_is_recovered_and_a_fresh_one_spawned(self, runtime_dir, floppy_image):
        session_id = "stale-session"
        dead_pid = _dead_pid()
        media_session._write_state_atomic(
            runtime_dir,
            session_id,
            {"session_id": session_id, "pid": dead_pid, "state": "attached", "devices": {}, "error": None, "tls_peer_fingerprint": None},
        )
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image, session_id=session_id))
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session", return_value=4242) as spawn,
            patch(
                "ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_state",
                return_value={"state": "attached", "pid": 4242, "devices": {}},
            ),
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        result = excinfo.value.kwargs
        assert result["changed"] is True
        assert result["recovered_stale_session"] is True
        spawn.assert_called_once()


class TestAttachCheckMode:
    def test_never_spawns_but_still_validates_media(self, runtime_dir, floppy_image):
        args = dict(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image), _ansible_check_mode=True)
        _set_module_args(args)
        with patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session") as spawn:
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        assert excinfo.value.kwargs["changed"] is True
        spawn.assert_not_called()

    def test_bad_media_path_still_fails_in_check_mode(self, runtime_dir, tmp_path):
        args = dict(
            _attach_args(runtime_dir=runtime_dir, floppy_image=str(tmp_path / "does-not-exist.img")),
            _ansible_check_mode=True,
        )
        _set_module_args(args)
        with patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.spawn_session") as spawn:
            with pytest.raises(AnsibleFailJson) as excinfo:
                amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "protocol"
        spawn.assert_not_called()


class TestOptionValidation:
    def test_floppy_writable_without_floppy_is_a_usage_error(self, runtime_dir, tmp_path):
        cdrom = tmp_path / "boot.iso"
        cdrom.write_bytes(b"\x00" * 2048)
        args = dict(BASE_ARGS, cdrom=str(cdrom), floppy_writable=True, state="attached", runtime_dir=runtime_dir)
        _set_module_args(args)
        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "invalid_state"

    def test_neither_cdrom_nor_floppy_is_a_usage_error(self, runtime_dir):
        args = dict(BASE_ARGS, state="attached", runtime_dir=runtime_dir)
        _set_module_args(args)
        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "invalid_state"

    def test_detach_without_session_id_is_rejected_by_argument_spec(self, runtime_dir):
        args = dict(BASE_ARGS, state="detached", runtime_dir=runtime_dir)
        _set_module_args(args)
        with pytest.raises((AnsibleFailJson, SystemExit)):
            amt_media.main()

    def test_insecure_transport_without_acknowledgement_is_refused(self, runtime_dir, floppy_image):
        args = dict(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image))
        args["allow_insecure_transport"] = False
        _set_module_args(args)
        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "tls_validation"

    def test_cdrom_is_never_opened_writable_even_if_only_cdrom_is_set(self, tmp_path):
        cdrom = tmp_path / "boot.iso"
        cdrom.write_bytes(b"\x00" * 2048)
        specs = amt_media.build_media_specs({"cdrom": str(cdrom), "floppy": None, "floppy_writable": False})
        assert len(specs) == 1
        assert specs[0].writable is False


class TestDetach:
    def test_no_existing_session_is_a_no_op(self, runtime_dir):
        args = dict(BASE_ARGS, state="detached", session_id="never-existed", runtime_dir=runtime_dir)
        _set_module_args(args)
        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_media.main()
        result = excinfo.value.kwargs
        assert result["changed"] is False
        assert result["session_state"] == "unknown"

    def test_live_session_is_stopped_and_state_file_removed(self, runtime_dir):
        session_id = "live-session"
        media_session._write_state_atomic(
            runtime_dir,
            session_id,
            {"session_id": session_id, "pid": 4242, "state": "attached", "devices": {}, "error": None, "tls_peer_fingerprint": None},
        )
        args = dict(BASE_ARGS, state="detached", session_id=session_id, runtime_dir=runtime_dir)
        _set_module_args(args)
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.is_pid_alive", return_value=True),
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.request_stop") as request_stop,
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.wait_for_exit", return_value=True),
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        result = excinfo.value.kwargs
        assert result["changed"] is True
        request_stop.assert_called_once_with(4242)
        assert media_session.read_state(runtime_dir, session_id) is None

    def test_stale_session_reports_no_change_but_cleans_up(self, runtime_dir):
        session_id = "stale-session"
        dead_pid = _dead_pid()
        media_session._write_state_atomic(
            runtime_dir,
            session_id,
            {"session_id": session_id, "pid": dead_pid, "state": "attached", "devices": {}, "error": None, "tls_peer_fingerprint": None},
        )
        args = dict(BASE_ARGS, state="detached", session_id=session_id, runtime_dir=runtime_dir)
        _set_module_args(args)
        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_media.main()
        result = excinfo.value.kwargs
        assert result["changed"] is False
        assert result["recovered_stale_session"] is True
        assert media_session.read_state(runtime_dir, session_id) is None

    def test_check_mode_never_signals_a_live_session(self, runtime_dir):
        session_id = "live-session"
        media_session._write_state_atomic(
            runtime_dir,
            session_id,
            {"session_id": session_id, "pid": 4242, "state": "attached", "devices": {}, "error": None, "tls_peer_fingerprint": None},
        )
        args = dict(BASE_ARGS, state="detached", session_id=session_id, runtime_dir=runtime_dir, _ansible_check_mode=True)
        _set_module_args(args)
        with (
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.is_pid_alive", return_value=True),
            patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.request_stop") as request_stop,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_media.main()
        assert excinfo.value.kwargs["changed"] is True
        request_stop.assert_not_called()
        # The state file must still exist -- check mode must not have removed it either.
        assert media_session.read_state(runtime_dir, session_id) is not None


# The TestCredentialSafety class that used to sit here was deleted rather than repaired: with
# exit_json replaced by the bare raiser in the autouse fixture above, `password not in
# json.dumps(kwargs)` asserted against a dict that structurally cannot contain the credential,
# since the real exit_json is what injects invocation.module_args and what applies no_log
# censoring. That invariant is now tested against the real serializer -- including the case of a
# credential echoed back inside the daemon's own error text -- in
# tests/unit/plugins/modules/test_credential_contract.py.


def _dead_pid() -> int:
    """A pid guaranteed not to be alive, for stale-session tests."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])  # fixed argv, no shell
    proc.wait()
    return proc.pid


class TestRedirectionTrustPolicy:
    """The redirection plane must make the same fail-closed trust promise as the
    WS-Man plane.

    Two holes were closed here. ca_path was accepted and ignored, so an operator
    setting it would believe the media session was chain-validated when nothing
    checked it. And use_tls with no pin gave encrypted-but-unauthenticated TLS,
    which an on-path attacker can terminate to serve its own boot media -- worse
    than the plaintext path, which at least announces itself.
    """

    def test_ca_path_is_rejected_not_ignored(self):
        params = {"host": "10.0.0.5", "port": 16995, "use_tls": True, "tls_fingerprint": "ab" * 32, "ca_path": "/etc/ssl/certs/ca.pem"}
        with pytest.raises(TlsValidationError, match="ca_path is not supported"):
            amt_media.enforce_redirection_trust_policy(params)

    def test_tls_without_a_pin_is_refused(self):
        params = {"host": "10.0.0.5", "port": 16995, "use_tls": True, "tls_fingerprint": None, "ca_path": None}
        with pytest.raises(TlsValidationError, match="requires tls_fingerprint"):
            amt_media.enforce_redirection_trust_policy(params)

    def test_tls_with_a_pin_is_accepted(self):
        params = {"host": "10.0.0.5", "port": 16995, "use_tls": True, "tls_fingerprint": "ab" * 32, "ca_path": None}
        amt_media.enforce_redirection_trust_policy(params)  # must not raise

    def test_acknowledged_plaintext_needs_no_pin(self):
        # An endpoint that cannot do TLS at all is still reachable, but only via
        # the explicit acknowledgement, which enforce_transport_policy checks.
        params = {"host": "10.0.0.5", "port": 16994, "use_tls": False, "tls_fingerprint": None, "ca_path": None}
        amt_media.enforce_redirection_trust_policy(params)  # must not raise

    def test_error_is_classified_as_tls_validation(self):
        params = {"host": "10.0.0.5", "port": 16995, "use_tls": True, "tls_fingerprint": None, "ca_path": None}
        try:
            amt_media.enforce_redirection_trust_policy(params)
        except TlsValidationError as exc:
            assert exc.to_result()["error_class"] == "tls_validation"
        else:
            raise AssertionError("expected TlsValidationError")


class TestTrustPolicyIsScopedToAttach:
    """Detach must never be blocked by transport or trust configuration.

    Detach opens no connection: it reads the state file and signals the recorded
    pid. An earlier revision of this gate ran for both states, which meant a
    tightened trust policy could make a running session unstoppable, leaving an
    orphaned daemon holding media open on a live machine. The integration target
    caught that, not the unit tests -- hence these.
    """

    def _detach_args(self, runtime_dir, session_id, **overrides):
        args = {
            "host": "10.0.0.5",
            "username": "admin",
            "password": "test-password-not-real",
            "state": "detached",
            "session_id": session_id,
            "runtime_dir": runtime_dir,
            "use_tls": True,
        }
        args.update(overrides)
        return args

    def test_detach_succeeds_under_tls_without_a_fingerprint(self, runtime_dir):
        session_id = "sess-detach-no-pin"
        media_session._write_state_atomic(runtime_dir, session_id, {"session_id": session_id, "state": "stopped", "pid": None})
        _set_module_args(self._detach_args(runtime_dir, session_id))
        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_media.main()
        assert excinfo.value.kwargs["session_id"] == session_id

    def test_detach_succeeds_even_with_ca_path_set(self, runtime_dir):
        session_id = "sess-detach-ca"
        media_session._write_state_atomic(runtime_dir, session_id, {"session_id": session_id, "state": "stopped", "pid": None})
        _set_module_args(self._detach_args(runtime_dir, session_id, ca_path="/etc/ssl/certs/ca.pem"))
        with pytest.raises(AnsibleExitJson):
            amt_media.main()

    def test_attach_still_refuses_tls_without_a_pin(self, runtime_dir, floppy_image):
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image, use_tls=True, allow_insecure_transport=False))
        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "tls_validation"
        assert "tls_fingerprint" in excinfo.value.kwargs["msg"]

    def test_attach_refuses_ca_path(self, runtime_dir, floppy_image):
        _set_module_args(
            _attach_args(
                runtime_dir=runtime_dir,
                floppy_image=floppy_image,
                use_tls=True,
                tls_fingerprint="ab" * 32,
                ca_path="/etc/ssl/certs/ca.pem",
            )
        )
        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_media.main()
        assert excinfo.value.kwargs["error_class"] == "tls_validation"
        assert "ca_path" in excinfo.value.kwargs["msg"]


class _DrivesAnAttach:
    """Shared harness for the two classes below, both of which drive one attach and
    inspect what the post-wait decision made of it.

    Extracted rather than duplicated because the two classes test the two axes of
    the *same* decision -- issue #44's "is the daemon still alive" and this
    change's "did it ever actually confirm" -- and a harness that drifted between
    them would let one axis be tested against a setup the other never reaches,
    which is precisely how the original #44 tests went vacuous (see PR #72).
    """

    SESSION_ID = "sess-liveness"

    def _attach(self, monkeypatch, runtime_dir, floppy_image, *, polled_state, pid_alive, written_after_poll=None):
        """Drive one attach, supplying each of the three inputs to the decision separately.

        The decision reads three things: the snapshot ``wait_for_state`` returned when it gave
        up, whether the daemon pid is still alive, and what the state file says when the module
        re-reads it afterwards. Those have to be independently controllable or the test cannot
        show which one decided the outcome.

        ``read_state`` is therefore left **real**, against the real ``runtime_dir``. An earlier
        version of these tests stubbed it to return the same literal as ``wait_for_state``, which
        collapsed two of the three inputs into one and made the module's "re-read once, the daemon
        may have written its error since the last poll" step untestable -- it could not have
        failed if that re-read were deleted. ``written_after_poll`` models exactly that race: the
        stubbed ``wait_for_state`` writes it to the real state file just before returning the
        older ``polled_state``.
        """
        monkeypatch.setattr(media_session, "spawn_session", lambda *a, **k: 4242)

        def _wait_for_state(*_args, **_kwargs):
            if written_after_poll is not None:
                media_session._write_state_atomic(runtime_dir, self.SESSION_ID, written_after_poll)
            return polled_state

        monkeypatch.setattr(media_session, "wait_for_state", _wait_for_state)
        monkeypatch.setattr(media_session, "is_pid_alive", lambda pid: pid_alive)
        _set_module_args(_attach_args(runtime_dir=runtime_dir, floppy_image=floppy_image, session_id=self.SESSION_ID))
        return amt_media.main

    def _fail(self, monkeypatch, runtime_dir, floppy_image, **kwargs) -> dict:
        main = self._attach(monkeypatch, runtime_dir, floppy_image, **kwargs)
        with pytest.raises(AnsibleFailJson) as excinfo:
            main()
        return excinfo.value.kwargs

    def _succeed(self, monkeypatch, runtime_dir, floppy_image, **kwargs) -> dict:
        main = self._attach(monkeypatch, runtime_dir, floppy_image, **kwargs)
        with pytest.raises(AnsibleExitJson) as excinfo:
            main()
        return excinfo.value.kwargs


class TestAttachFailureIsDecidedByDaemonLiveness(_DrivesAnAttach):
    """A dead daemon that never reported 'attached' must fail the module.

    Regression test for issue #44. Only an explicit ERROR state used to fail the
    attach, so a daemon that died without writing one -- or had not written it yet
    when attach_timeout expired -- fell through to a success receipt. Bad
    credentials kill the daemon during the digest handshake, so whether the module
    noticed was a race, and the wrong-password integration assertion flaked green
    roughly one run in three.

    Liveness is the unambiguous signal, so these tests pin it rather than the
    timing. What liveness alone does *not* settle is the live-daemon-never-confirmed
    case; that is TestUnconfirmedAttachIsNotReportedAsSuccess below.
    """

    def test_dead_daemon_with_no_error_state_fails(self, monkeypatch, runtime_dir, floppy_image):
        # The exact shape that used to slip through: an intermediate state, no
        # error recorded, and a daemon that is already gone.
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242},
            pid_alive=False,
        )
        assert "exited without reporting" in result["msg"]
        # The last state actually seen is named in the message, so an operator can tell how far
        # the attach got; and with no classification recorded anywhere the fallback is the
        # generic class, not something more specific that would be a guess. Asserting the value
        # rather than its truthiness is the point: `assert result["error_class"]` passed for any
        # of the nine classes, including ones that would be actively misleading here.
        assert "'connecting'" in result["msg"]
        assert result["error_class"] == "protocol"
        assert result["session_id"] == self.SESSION_ID

    def test_dead_daemon_with_a_late_error_reports_that_error(self, monkeypatch, runtime_dir, floppy_image):
        # The poll timed out on an intermediate state carrying no error at all; the daemon then
        # wrote its real failure and exited. The module must report the *later* state, which it
        # can only do by re-reading -- nothing in `polled_state` mentions credentials.
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242},
            written_after_poll={
                "session_id": self.SESSION_ID,
                "state": media_session.STATE_ERROR,
                "pid": 4242,
                "error": "AMT rejected the credentials",
                "error_class": "authentication",
                "devices": {},
            },
            pid_alive=False,
        )
        assert "AMT rejected the credentials" in result["msg"]
        assert result["error_class"] == "authentication"
        # The re-read state is what gets reported back, not the stale poll snapshot.
        assert result["session_state"] == media_session.STATE_ERROR

    def test_absent_state_with_dead_daemon_fails(self, monkeypatch, runtime_dir, floppy_image):
        result = self._fail(monkeypatch, runtime_dir, floppy_image, polled_state=None, pid_alive=False)
        assert "exited without reporting" in result["msg"]
        assert result["session_state"] == "unknown"
        assert result["error_class"] == "protocol"

    def test_live_daemon_that_never_confirmed_is_classified_by_liveness_not_by_error(self, monkeypatch, runtime_dir, floppy_image):
        # The liveness axis, held against the *same* intermediate state as
        # test_dead_daemon_with_no_error_state_fails above. Both fail -- what liveness decides
        # is *which* failure. A daemon that is gone can never confirm, so that is a settled
        # V(protocol) failure; a daemon still running may yet confirm, so this one is V(timeout)
        # and indeterminate. Collapsing the two would lose the distinction a caller branches on.
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242, "devices": {}},
            pid_alive=True,
        )
        assert result["error_class"] == "timeout"
        assert result["indeterminate"] is True
        assert result["session_state"] == media_session.STATE_CONNECTING

    def test_live_daemon_that_reported_attached_succeeds(self, monkeypatch, runtime_dir, floppy_image):
        result = self._succeed(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={
                "session_id": self.SESSION_ID,
                "state": media_session.STATE_ATTACHED,
                "pid": 4242,
                "devices": {},
                "error": None,
                "tls_peer_fingerprint": None,
            },
            pid_alive=True,
        )
        assert result["session_state"] == media_session.STATE_ATTACHED
        assert result["operation"]["error_class"] is None


class TestUnconfirmedAttachIsNotReportedAsSuccess(_DrivesAnAttach):
    """An attach that never confirmed V(attached) must not return a success receipt,
    even when the daemon is still alive.

    The second hole on the path issue #44 half-closed. #44's fix decides failure by
    daemon *liveness*, which only fires when the recorded pid is B(dead). A daemon
    that is still alive when ``attach_timeout`` expires without ever having reported
    V(attached) skipped both the ERROR branch and the liveness branch and fell
    through to ``OperationReceipt(changed=True, ...)`` -- ``changed: true``, a
    ``session_id``, ``operation.error_class: null``, and ``session_state:
    'connecting'`` sitting there unread.

    That receipt is acted on, not inspected. ``roles/amt_baremetal_install`` goes
    straight from this task to ``arm_boot.yml`` and then ``reset.yml``, so a machine
    gets power-cycled into media that was never confirmed to be served. It is the
    same family as the defect fixed in #69, where the daemon reported V(attached) for
    a session whose IDE-R feature toggle firmware had refused: in both cases the
    module asserted a fact it had not established, and the cost is a machine rather
    than a retry.

    The classification follows #69's own rule, one level up. #69 taught the daemon to
    distinguish a definite refusal (V(unsupported_capability)) from a verdict that
    never arrived (V(timeout)); a module-level wait that expires with no verdict is
    the same "no verdict" case and is V(timeout) too. It is additionally
    ``indeterminate``, which in this collection means precisely "the operation may
    have taken effect, so re-probe rather than retry" -- and re-probing is exactly
    what a repeated ``state=attached`` call for the same ``session_id`` does. Blind
    retry is the one thing a caller must not do here, because IDE-R is
    single-session: a second attach collides with a daemon that may still hold the
    one connection firmware has to give.
    """

    def test_live_daemon_still_connecting_at_timeout_fails_as_an_indeterminate_timeout(self, monkeypatch, runtime_dir, floppy_image):
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242, "devices": {}},
            pid_alive=True,
        )
        # Asserting the class and the indeterminate flag, not merely that it failed: the whole
        # value of this failure to a caller is that it says "re-probe, do not retry", and a
        # generic failure would say neither.
        assert result["error_class"] == "timeout"
        assert result["indeterminate"] is True
        # ...and emphatically not the success receipt this used to return. `changed` must not be
        # claimed, and no `operation` key at all rather than a degraded one: RETURN documents
        # `operation` as the nested receipt dict, so emitting anything else under that name would
        # be a second false claim on the way out. Both sibling failure paths agree.
        assert result.get("changed") is not True
        assert "operation" not in result

    def test_live_daemon_still_starting_at_timeout_fails_the_same_way(self, monkeypatch, runtime_dir, floppy_image):
        # STATE_STARTING reaches the same gate as STATE_CONNECTING. Both mean "no verdict yet",
        # and the module has no basis for treating one as more attached than the other; the
        # documented "session_state may still show starting" case is this one.
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_STARTING, "pid": 4242, "devices": {}},
            pid_alive=True,
        )
        assert result["error_class"] == "timeout"
        assert result["indeterminate"] is True
        assert result["session_state"] == media_session.STATE_STARTING

    def test_the_failure_still_carries_the_session_id_and_pid_so_the_session_can_be_cleaned_up(self, monkeypatch, runtime_dir, floppy_image):
        # The load-bearing property of this failure. The daemon is still alive and still holds
        # the single IDE-R session, so a failure that did not name the session would strand it:
        # the caller could neither detach it nor re-probe it, and every later attach against
        # that endpoint would collide with it. Worse than the success receipt it replaces.
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242, "devices": {}},
            pid_alive=True,
        )
        assert result["session_id"] == self.SESSION_ID
        assert result["pid"] == 4242

    def test_the_unconfirmed_session_is_left_running_not_torn_down(self, monkeypatch, runtime_dir, floppy_image):
        # Deliberately *not* auto-detached, and this pins that choice so it cannot be quietly
        # reversed. Three reasons. (1) An indeterminate result promises the caller something to
        # re-probe; detaching destroys it and makes the promise false. (2) media_session's own
        # teardown path (`remove_state`) deletes the session log file alongside the state file,
        # and that log is the only record of how far the attach got -- the diagnosis would be
        # deleted by the code reporting the problem. (3) attach_timeout defaults to 10s and
        # connect_timeout also defaults to 10s, so the ordinary way to reach this gate is an
        # attach that is merely slow and about to succeed; killing it would convert that into a
        # guaranteed failure. Cleanup belongs to the caller, which can do it on its own terms
        # (roles/amt_baremetal_install already detaches from an `always:` block).
        with patch("ansible_collections.james_crowley.intel_amt.plugins.module_utils.media_session.request_stop") as request_stop:
            self._fail(
                monkeypatch,
                runtime_dir,
                floppy_image,
                polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242, "devices": {}},
                pid_alive=True,
                written_after_poll={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242, "devices": {}},
            )
        request_stop.assert_not_called()
        # The state file survives, so the session id the failure reported is still resolvable by
        # a later state=detached or a re-probing state=attached call.
        assert media_session.read_state(runtime_dir, self.SESSION_ID) is not None

    def test_the_message_names_the_session_and_says_re_probe_rather_than_retry(self, monkeypatch, runtime_dir, floppy_image):
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={"session_id": self.SESSION_ID, "state": media_session.STATE_CONNECTING, "pid": 4242, "devices": {}},
            pid_alive=True,
        )
        msg = result["msg"]
        # An operator reading only the failure line has to learn three things from it: what was
        # not established, that the session is still running and still theirs to deal with, and
        # which of re-probe/retry to reach for. Pinning the substance, not the phrasing -- hence
        # case-insensitive matching on the phrases and an exact match only on the session id,
        # which is the one token a caller has to copy verbatim into a follow-up task.
        lowered = msg.lower()
        assert "attach_timeout" in lowered
        assert self.SESSION_ID in msg
        assert "still running" in lowered
        assert "re-probe" in lowered
        assert "was not detached" in lowered

    def test_absent_state_with_a_live_daemon_fails_as_an_indeterminate_timeout(self, monkeypatch, runtime_dir, floppy_image):
        # No readable state record at all (never written, or a torn/corrupt read degraded to
        # None by read_state) while the daemon is still alive. Nothing was confirmed, so this
        # cannot be a success either -- and the corresponding dead-daemon case
        # (test_absent_state_with_dead_daemon_fails) has failed since #44.
        result = self._fail(monkeypatch, runtime_dir, floppy_image, polled_state=None, pid_alive=True)
        assert result["error_class"] == "timeout"
        assert result["indeterminate"] is True
        assert result["session_state"] == "unknown"

    def test_a_daemon_that_reported_detached_is_a_settled_failure_not_an_indeterminate_one(self, monkeypatch, runtime_dir, floppy_image):
        # A live daemon whose last report is a *terminal* state is a different case, and must
        # not be swept into the timeout bucket. STATE_DETACHED means the daemon has published
        # its verdict -- the session ended without ever attaching, typically because the peer
        # closed the connection -- and is merely still winding down (closing images, and a TLS
        # `session.close()` does a shutdown round trip, so the window where the state file says
        # `detached` while the pid is still alive is real, not theoretical). wait_for_state's
        # `until` matches STATE_DETACHED, so it returns on sight rather than timing out.
        #
        # Nothing about that is indeterminate: there is no attach still in flight to re-probe.
        # Marking it indeterminate would tell the caller to poll a session that is already
        # over, which is the same species of false claim as the success receipt this change
        # removes.
        result = self._fail(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={
                "session_id": self.SESSION_ID,
                "state": media_session.STATE_DETACHED,
                "pid": 4242,
                "error": "connection closed by peer",
                "devices": {},
            },
            pid_alive=True,
        )
        assert result["error_class"] == "protocol"
        assert result.get("indeterminate") is not True
        assert "connection closed by peer" in result["msg"]

    def test_an_attached_session_is_still_a_success(self, monkeypatch, runtime_dir, floppy_image):
        # Positive control. The gate above rejects everything that is not V(attached), so
        # without this a fix that failed *every* attach would satisfy the whole class.
        result = self._succeed(
            monkeypatch,
            runtime_dir,
            floppy_image,
            polled_state={
                "session_id": self.SESSION_ID,
                "state": media_session.STATE_ATTACHED,
                "pid": 4242,
                "devices": {},
                "error": None,
                "tls_peer_fingerprint": None,
            },
            pid_alive=True,
        )
        assert result["changed"] is True
        assert result["session_state"] == media_session.STATE_ATTACHED
        assert result["operation"]["error_class"] is None
        assert "indeterminate" not in result

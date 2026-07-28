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


class TestCredentialSafety:
    def test_credential_never_appears_in_the_result(self, runtime_dir, floppy_image):
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
        assert BASE_ARGS["password"] not in json.dumps(excinfo.value.kwargs)


def _dead_pid() -> int:
    """A pid guaranteed not to be alive, for stale-session tests."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])  # fixed argv, no shell
    proc.wait()
    return proc.pid

# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for the state-file/process-lifecycle primitives in ``media_session.py``.

Deliberately scoped to logic that does not require a real fork or a real network
connection -- state file read/write/atomicity, pid liveness, bounded waits, and
media-spec validation. The actual fork -> connect -> IDE-R pump path
(:func:`media_session.spawn_session` / :func:`media_session._run_daemon`) is exercised
end-to-end by the ``amt_media`` integration test target against the real mock IDE-R
server instead: forking a real detached daemon and having it complete a real (loopback)
redirection handshake is exactly the kind of thing that is invisible to a mocked unit
test and easy to get subtly wrong, so it is proven for real there rather than faked here.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import ider, media_session
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ProtocolError


class TestStateFileRoundTrip:
    def test_missing_file_reads_as_none(self, tmp_path):
        assert media_session.read_state(tmp_path, "no-such-session") is None

    def test_write_then_read_round_trips(self, tmp_path):
        data = {"session_id": "abc", "pid": 123, "state": "attached", "devices": {}}
        media_session._write_state_atomic(tmp_path, "abc", data)
        assert media_session.read_state(tmp_path, "abc") == data

    def test_corrupt_file_reads_as_none_not_an_exception(self, tmp_path):
        media_session.state_file_path(tmp_path, "abc").write_text("{not json", encoding="utf-8")
        assert media_session.read_state(tmp_path, "abc") is None

    def test_non_dict_json_reads_as_none(self, tmp_path):
        media_session.state_file_path(tmp_path, "abc").write_text("[1, 2, 3]", encoding="utf-8")
        assert media_session.read_state(tmp_path, "abc") is None

    def test_write_is_atomic_no_temp_file_left_behind(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "abc", {"state": "attached"})
        leftover = list(tmp_path.glob("*.tmp"))
        assert leftover == []

    def test_remove_state_deletes_state_and_log_files(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "abc", {"state": "attached"})
        media_session.log_file_path(tmp_path, "abc").write_text("log line\n", encoding="utf-8")
        media_session.remove_state(tmp_path, "abc")
        assert not media_session.state_file_path(tmp_path, "abc").exists()
        assert not media_session.log_file_path(tmp_path, "abc").exists()

    def test_remove_state_is_silent_when_nothing_exists(self, tmp_path):
        media_session.remove_state(tmp_path, "never-existed")  # must not raise


class TestIsPidAlive:
    def test_self_pid_is_alive(self):
        assert media_session.is_pid_alive(os.getpid()) is True

    def test_none_is_not_alive(self):
        assert media_session.is_pid_alive(None) is False

    @pytest.mark.parametrize("bad_pid", [0, -1, -999])
    def test_non_positive_pid_is_not_alive_and_never_reaches_os_kill(self, bad_pid, monkeypatch):
        # pid <= 0 has special meaning to kill(2) (a process group, or "every process
        # this caller may signal") -- must be rejected before ever calling os.kill,
        # not merely happen to return False because the kernel refused it.
        def _boom(*_args, **_kwargs):
            raise AssertionError("os.kill must not be called for a non-positive pid")

        monkeypatch.setattr(media_session.os, "kill", _boom)
        assert media_session.is_pid_alive(bad_pid) is False

    def test_dead_pid_is_not_alive(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"])  # fixed argv, no shell
        proc.wait()
        assert media_session.is_pid_alive(proc.pid) is False


class TestRequestStopAndWaitForExit:
    @pytest.fixture
    def sleeper(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])  # fixed argv, no shell
        yield proc
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        proc.wait()

    def test_request_stop_terminates_a_live_process(self, sleeper):
        assert media_session.is_pid_alive(sleeper.pid) is True
        media_session.request_stop(sleeper.pid)
        # sleeper is a direct child of *this* process, unlike the orphaned/reparented
        # daemon spawn_session() actually produces, so it must be reaped (wait()) before
        # is_pid_alive() can observe it as gone -- until reaped it is a zombie, which
        # still occupies its pid and answers a signal-0 probe. wait_for_exit() alone
        # would spin until its timeout here for exactly that reason.
        sleeper.wait(timeout=5.0)
        assert media_session.is_pid_alive(sleeper.pid) is False

    def test_request_stop_on_dead_pid_is_a_no_op(self, sleeper):
        sleeper.kill()
        sleeper.wait()
        media_session.request_stop(sleeper.pid)  # must not raise

    @pytest.mark.parametrize("bad_pid", [None, 0, -1])
    def test_request_stop_rejects_non_positive_pid_before_os_kill(self, bad_pid, monkeypatch):
        def _boom(*_args, **_kwargs):
            raise AssertionError("os.kill must not be called for a non-positive/None pid")

        monkeypatch.setattr(media_session.os, "kill", _boom)
        media_session.request_stop(bad_pid)

    def test_wait_for_exit_times_out_on_a_still_live_process(self, sleeper):
        exited = media_session.wait_for_exit(sleeper.pid, timeout=0.2, poll_interval=0.05)
        assert exited is False


class TestWaitForState:
    def test_returns_immediately_when_predicate_already_satisfied(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "abc", {"state": "attached"})
        start = time.monotonic()
        result = media_session.wait_for_state(tmp_path, "abc", until=lambda s: s["state"] == "attached", timeout=5.0, poll_interval=0.05)
        assert result == {"state": "attached"}
        assert time.monotonic() - start < 1.0

    def test_times_out_returning_the_last_observed_state(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "abc", {"state": "connecting"})
        result = media_session.wait_for_state(tmp_path, "abc", until=lambda s: s["state"] == "attached", timeout=0.2, poll_interval=0.05)
        assert result == {"state": "connecting"}

    def test_observes_a_transition_that_happens_mid_wait(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "abc", {"state": "connecting"})

        def _flip_soon():
            time.sleep(0.1)
            media_session._write_state_atomic(tmp_path, "abc", {"state": "attached"})

        thread = threading.Thread(target=_flip_soon)
        thread.start()
        result = media_session.wait_for_state(tmp_path, "abc", until=lambda s: s["state"] == "attached", timeout=5.0, poll_interval=0.02)
        thread.join()
        assert result == {"state": "attached"}

    def test_missing_state_file_never_satisfies_and_times_out_with_none(self, tmp_path):
        result = media_session.wait_for_state(tmp_path, "no-such-session", until=lambda s: True, timeout=0.2, poll_interval=0.05)
        assert result is None


class TestAggregateBytes:
    def test_none_state_is_zero_zero(self):
        assert media_session.aggregate_bytes(None) == (0, 0)

    def test_sums_across_devices(self):
        state = {
            "devices": {
                "cdrom": {"bytes_read": 100, "bytes_written": 0},
                "floppy": {"bytes_read": 20, "bytes_written": 512},
            }
        }
        assert media_session.aggregate_bytes(state) == (120, 512)

    def test_missing_devices_key_is_zero_zero(self):
        assert media_session.aggregate_bytes({"state": "attached"}) == (0, 0)


class TestValidateMediaSpecs:
    def test_valid_image_passes(self, tmp_path):
        path = tmp_path / "f.img"
        path.write_bytes(b"\x00" * 512)
        spec = media_session.MediaSpec(path=str(path), device_code=ider.DEVICE_FLOPPY, writable=False)
        media_session.validate_media_specs((spec,), allowed_directory=None)  # must not raise

    def test_wrong_size_image_raises_protocol_error(self, tmp_path):
        path = tmp_path / "f.img"
        path.write_bytes(b"\x00" * 511)  # not a multiple of 512
        spec = media_session.MediaSpec(path=str(path), device_code=ider.DEVICE_FLOPPY, writable=False)
        with pytest.raises(ProtocolError):
            media_session.validate_media_specs((spec,), allowed_directory=None)

    def test_missing_image_raises_protocol_error(self, tmp_path):
        spec = media_session.MediaSpec(path=str(tmp_path / "missing.img"), device_code=ider.DEVICE_FLOPPY, writable=False)
        with pytest.raises(ProtocolError):
            media_session.validate_media_specs((spec,), allowed_directory=None)

    def test_symlink_is_refused(self, tmp_path):
        real = tmp_path / "real.img"
        real.write_bytes(b"\x00" * 512)
        link = tmp_path / "link.img"
        link.symlink_to(real)
        spec = media_session.MediaSpec(path=str(link), device_code=ider.DEVICE_FLOPPY, writable=False)
        with pytest.raises(ProtocolError):
            media_session.validate_media_specs((spec,), allowed_directory=None)

    def test_outside_allowed_directory_is_refused(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.img"
        outside.write_bytes(b"\x00" * 512)
        spec = media_session.MediaSpec(path=str(outside), device_code=ider.DEVICE_FLOPPY, writable=False)
        with pytest.raises(ProtocolError):
            media_session.validate_media_specs((spec,), allowed_directory=str(allowed))


class TestGenerateSessionId:
    def test_generates_a_plausible_unique_hex_id(self):
        first = media_session.generate_session_id()
        second = media_session.generate_session_id()
        assert first != second
        assert len(first) == 32
        int(first, 16)  # must be valid hex


class TestSpawnSessionPlatformGuard:
    def test_raises_unsupported_capability_when_os_fork_is_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.delattr(media_session.os, "fork", raising=False)
        config = media_session.SessionConfig(
            session_id="abc",
            host="127.0.0.1",
            port=16994,
            use_tls=False,
            tls_pin_sha256=None,
            connect_timeout=1.0,
            start_mode=ider.START_MODE_ON_REBOOT,
            allowed_directory=None,
            runtime_dir=str(tmp_path),
            devices=(),
        )
        from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import UnsupportedCapabilityError

        with pytest.raises(UnsupportedCapabilityError):
            media_session.spawn_session(config, username="admin", password="test-password-not-real")


class TestJsonSerializability:
    def test_state_written_by_the_daemon_shape_is_json_safe_and_credential_free(self, tmp_path):
        # Guards the "no credential-shaped field" contract from the module docstring: build a
        # state dict the same way _run_daemon does and confirm it round-trips through JSON with
        # no password-looking value anywhere.
        state = {
            "session_id": "abc",
            "pid": 123,
            "endpoint": "127.0.0.1:16994",
            "state": "attached",
            "error": None,
            "tls_peer_fingerprint": "ab" * 32,
            "devices": {"floppy": {"path": "/srv/images/f.img", "device": "floppy", "writable": True, "size": 512, "bytes_read": 0, "bytes_written": 0}},
            "started_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
        media_session._write_state_atomic(tmp_path, "abc", state)
        raw = media_session.state_file_path(tmp_path, "abc").read_text(encoding="utf-8")
        assert "password" not in raw.lower()
        assert "test-password-not-real" not in raw
        assert json.loads(raw) == state

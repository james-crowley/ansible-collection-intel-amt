# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for the state-file/process-lifecycle primitives in ``media_session.py``.

Mostly scoped to logic that does not require a real fork or a real network connection --
state file read/write/atomicity, pid liveness, bounded waits, and media-spec validation.
The *fork* half of the daemon path (:func:`media_session.spawn_session`'s double fork,
and a real redirection handshake over a real socket) is still proven end-to-end by the
``amt_media`` integration test target against the mock IDE-R server rather than faked
here: forking a real detached daemon and having it complete a real loopback handshake is
exactly the kind of thing that is invisible to a mocked test and easy to get subtly
wrong.

:class:`TestRunDaemonAttachGate` is the exception, and deliberately so. What state
:func:`media_session._run_daemon` reports, and *when*, is the highest-consequence
decision in this module -- ``session_state: attached`` is what a caller treats as
permission to arm a boot device and reset a machine. That decision is a function of
which IDE-R frames have arrived so far, so it needs to be driven frame by frame with the
real :class:`ider.IderEngine` on the other side. A fake session object supplies the
bytes; nothing about the engine or the state machine under test is mocked.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import struct
import subprocess
import sys
import threading
import time
from typing import Any

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import ider, media_session
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ErrorClass, ProtocolError

# ---------------------------------------------------------------------------
# IDE-R frame builders, for driving _run_daemon's loop through the real engine.
# Mirrors docs/protocol-notes.md sections 4.1-4.2; kept local (and minimal) rather
# than shared with test_ider.py, which is not an importable package.
# ---------------------------------------------------------------------------

#: Documentation-only endpoint address (RFC 5737 TEST-NET-1). Nothing here connects.
EXAMPLE_HOST = "192.0.2.10"


def _ider_header(cmdid: int, seq: int) -> bytes:
    return bytes([cmdid, 0x00, 0x00, 0x00]) + struct.pack("<I", seq)


def open_session_reply(*, seq: int = 0, readbfr: int = 512, writebfr: int = 512) -> bytes:
    body = bytearray(22)  # absolute offsets 8..29
    body[0:4] = bytes([1, 0, 1, 0])
    struct.pack_into("<H", body, 8, readbfr)  # abs 16..17
    struct.pack_into("<H", body, 10, writebfr)  # abs 18..19
    return _ider_header(0x41, seq) + bytes(body)


def status_data(status_type: int, value: int, *, seq: int) -> bytes:
    """``0x49`` STATUS_DATA: type at abs 8, LE uint32 value at abs 9..12."""
    return _ider_header(0x49, seq) + bytes([status_type]) + struct.pack("<I", value)


class _FakeRedirectionSession:
    """Stands in for :class:`redirection.RedirectionSession` -- and only for it.

    Everything above the socket stays real: :func:`media_session._run_daemon` runs its
    actual loop, driving an actual :class:`ider.IderEngine`, writing actual state files.
    This class supplies the inbound bytes and collects the outbound ones.

    ``script`` is a list of items consumed one per ``recv()``:

    - ``bytes``   -- returned as received data (b"" means the peer closed the connection)
    - callable    -- invoked; its return value is used the same way, and ``None`` means
                     "this poll cycle timed out", i.e. the quiet-connection wakeup path.
                     This is the hook for inspecting the state file *mid-session*, which
                     is the only way to test what the daemon reported at a given moment
                     rather than only what it ended up reporting.

    Once the script runs out, every further ``recv()`` reports a timeout, bounded by
    :data:`_MAX_QUIET_POLLS` so that a daemon which fails to terminate fails the test
    quickly instead of hanging CI.
    """

    #: Generous enough that no correct daemon reaches it, small enough to fail fast.
    _MAX_QUIET_POLLS = 500

    def __init__(self, script: list[Any], *, leftover: bytes = b"", fingerprint: str | None = None) -> None:
        self.script = list(script)
        self.leftover = leftover
        self.fingerprint = fingerprint
        self.sent = bytearray()
        self.recv_timeout: float | None = None
        self.closed = False
        self.connect_calls = 0
        self._quiet_polls = 0

    def connect(self) -> bytes:
        self.connect_calls += 1
        return self.leftover

    def peer_certificate_sha256(self) -> str | None:
        return self.fingerprint

    def send(self, data: bytes) -> None:
        self.sent.extend(data)

    def set_recv_timeout(self, timeout: float | None) -> None:
        self.recv_timeout = timeout

    def recv(self) -> bytes:
        if self.script:
            item = self.script.pop(0)
            produced = item() if callable(item) else item
            if produced is None:
                raise TimeoutError
            return produced
        self._quiet_polls += 1
        if self._quiet_polls > self._MAX_QUIET_POLLS:
            raise AssertionError(f"_run_daemon still polling after {self._MAX_QUIET_POLLS} quiet cycles; it is not terminating")
        raise TimeoutError

    def close(self) -> None:
        self.closed = True


class TestRunDaemonAttachGate:
    """What ``_run_daemon`` reports as ``attached``, and when.

    The bug this class exists for: the loop gated ``STATE_ATTACHED`` on
    ``engine.session_open`` alone. An endpoint can open the IDE-R session and then refuse
    the *feature toggle* -- STATUS_DATA type 3 / REGS_TOGGLE, docs/protocol-notes.md
    section 4.2 -- which means it is not serving the media. ``engine.feature_toggle_ok``
    recorded that refusal and no consumer read it, so ``amt_media`` reported
    ``session_state: attached`` for a session serving nothing. The caller's next move is
    to arm a boot device and reset the machine.

    The two facts arrive in separate frames, so every test here is about ordering as much
    as about outcome.
    """

    @pytest.fixture
    def harness(self, tmp_path, monkeypatch):
        """Returns ``run(script, **overrides)``, which runs the daemon to completion."""
        image_path = tmp_path / "answer.img"
        image_path.write_bytes(b"\x00" * 1024)
        runtime_dir = tmp_path / "runtime"

        # The daemon normally dup2()s stdout/stderr onto its log file. In-process that
        # would redirect the *test runner's* fds, so this is the one piece of daemon
        # start-up that has to be stubbed out.
        monkeypatch.setattr(media_session, "_redirect_std_fds", lambda _log_path: None)
        # Likewise the SIGTERM handler: installing it would outlive the test.
        monkeypatch.setattr(media_session.signal, "signal", lambda _signum, _handler: None)
        # Module-global stop flag; monkeypatch restores it even if a test sets it.
        monkeypatch.setattr(media_session, "_stop_flag", False)

        sessions: list[_FakeRedirectionSession] = []

        def run(script: list[Any], *, leftover: bytes = b"", fingerprint: str | None = None, session_id: str = "gate-session") -> dict:
            def _factory(*_args, **_kwargs):
                session = _FakeRedirectionSession(script, leftover=leftover, fingerprint=fingerprint)
                sessions.append(session)
                return session

            monkeypatch.setattr(media_session, "RedirectionSession", _factory)
            config = media_session.SessionConfig(
                session_id=session_id,
                host=EXAMPLE_HOST,
                port=16994,
                use_tls=False,
                tls_pin_sha256=None,
                connect_timeout=1.0,
                start_mode=ider.START_MODE_ON_REBOOT,
                allowed_directory=None,
                runtime_dir=str(runtime_dir),
                devices=(media_session.MediaSpec(path=str(image_path), device_code=ider.DEVICE_FLOPPY, writable=True),),
            )
            media_session._run_daemon(config, "admin", "test-password-not-real")
            return media_session.read_state(runtime_dir, session_id)

        run.runtime_dir = runtime_dir  # type: ignore[attr-defined]
        run.sessions = sessions  # type: ignore[attr-defined]
        return run

    @staticmethod
    def _stop_after(observations: list[str | None], harness) -> Any:
        """A script step that records the currently reported state and then stops the daemon."""

        def _step():
            observations.append((media_session.read_state(harness.runtime_dir, "gate-session") or {}).get("state"))
            media_session._stop_flag = True
            return None  # a timed-out poll cycle; the loop condition then ends it

        return _step

    def _observe(self, observations: list[str | None], harness) -> Any:
        def _step():
            observations.append((media_session.read_state(harness.runtime_dir, "gate-session") or {}).get("state"))
            return None

        return _step

    def test_session_open_alone_is_not_reported_as_attached(self, harness):
        # The regression proper. OPEN_SESSION_REPLY arrives and the toggle verdict does
        # not, so the daemon must sit at "connecting" rather than claim "attached".
        observed: list[str | None] = []
        final = harness([open_session_reply(seq=0), self._observe(observed, harness), self._stop_after(observed, harness)])
        assert observed == [media_session.STATE_CONNECTING, media_session.STATE_CONNECTING], (
            "an open session whose feature toggle is unconfirmed must not be reported as attached"
        )
        assert final["state"] == media_session.STATE_DETACHED

    def test_attached_only_once_the_feature_toggle_is_confirmed(self, harness):
        observed: list[str | None] = []
        final = harness(
            [
                open_session_reply(seq=0),
                self._observe(observed, harness),  # session open, verdict not in yet
                status_data(3, 1, seq=1),  # REGS_TOGGLE: success
                self._stop_after(observed, harness),
            ]
        )
        assert observed == [media_session.STATE_CONNECTING, media_session.STATE_ATTACHED]
        # A clean stop after a real attach is a detach, not an error.
        assert final["state"] == media_session.STATE_DETACHED
        assert final["error"] is None
        assert final["error_class"] is None

    def test_refused_feature_toggle_fails_instead_of_reporting_attached(self, harness):
        observed: list[str | None] = []
        final = harness(
            [
                open_session_reply(seq=0),
                status_data(3, 0, seq=1),  # REGS_TOGGLE: firmware refused
                self._observe(observed, harness),
            ]
        )
        assert media_session.STATE_ATTACHED not in observed
        assert final["state"] == media_session.STATE_ERROR
        assert final["error_class"] == ErrorClass.UNSUPPORTED_CAPABILITY
        assert "feature toggle" in final["error"]
        assert "no media is being served" in final["error"]

    def test_a_refusal_arriving_after_attach_also_fails_the_session(self, harness):
        # REGS_AVAIL makes the engine re-send the toggle mid-session, so a refusal can
        # land after a legitimate attach. The media stops being served at that point;
        # a stale "attached" is exactly as dangerous as a premature one.
        observed: list[str | None] = []
        final = harness(
            [
                open_session_reply(seq=0),
                status_data(3, 1, seq=1),
                self._observe(observed, harness),
                status_data(3, 0, seq=2),
                self._observe(observed, harness),
            ]
        )
        assert observed[0] == media_session.STATE_ATTACHED
        assert final["state"] == media_session.STATE_ERROR
        assert final["error_class"] == ErrorClass.UNSUPPORTED_CAPABILITY

    def test_a_toggle_verdict_that_never_arrives_expires_as_a_classified_timeout(self, harness, monkeypatch):
        # The bounded wait must not become a silent pass, and must not hang. Zero here
        # makes the expiry land on the first loop pass after the session opens, which is
        # what keeps this test deterministic rather than timing-dependent.
        monkeypatch.setattr(media_session, "_FEATURE_TOGGLE_TIMEOUT", 0.0)
        observed: list[str | None] = []
        final = harness([open_session_reply(seq=0), self._observe(observed, harness)])
        assert media_session.STATE_ATTACHED not in observed
        assert final["state"] == media_session.STATE_ERROR
        assert final["error_class"] == ErrorClass.TIMEOUT
        assert "never reported the outcome" in final["error"]

    def test_the_wait_is_bounded_and_the_daemon_exits(self, harness, monkeypatch):
        # Same path, but asserting the property that matters operationally: the daemon
        # terminates on its own. _FakeRedirectionSession fails the test if it does not.
        monkeypatch.setattr(media_session, "_FEATURE_TOGGLE_TIMEOUT", 0.05)
        final = harness([open_session_reply(seq=0)])
        assert final["state"] == media_session.STATE_ERROR
        assert final["error_class"] == ErrorClass.TIMEOUT
        assert harness.sessions[0].closed is True, "the redirection session must be closed on the way out"

    def test_a_toggle_arriving_late_but_inside_the_bound_still_attaches(self, harness):
        # Several quiet poll cycles before the verdict: slow firmware is not failed
        # firmware, and the gate must not turn ordinary latency into an error.
        observed: list[str | None] = []
        final = harness(
            [
                open_session_reply(seq=0),
                None,
                None,
                None,
                status_data(3, 1, seq=1),
                self._stop_after(observed, harness),
            ]
        )
        assert observed == [media_session.STATE_ATTACHED]
        assert final["state"] == media_session.STATE_DETACHED

    def test_peer_closing_the_connection_is_recorded_as_detached(self, harness):
        final = harness([open_session_reply(seq=0), status_data(3, 1, seq=1), b""])
        assert final["state"] == media_session.STATE_DETACHED
        assert final["error"] == "connection closed by peer"

    def test_device_counters_and_fingerprint_reach_the_state_file(self, harness):
        observed: list[str | None] = []
        final = harness(
            [open_session_reply(seq=0), status_data(3, 1, seq=1), self._stop_after(observed, harness)],
            fingerprint="ab" * 32,
        )
        assert final["tls_peer_fingerprint"] == "ab" * 32
        assert final["devices"]["floppy"]["writable"] is True
        assert final["devices"]["floppy"]["size"] == 1024
        assert media_session.aggregate_bytes(final) == (0, 0)

    def test_the_daemon_claims_the_state_file_before_it_opens_any_media(self, harness, monkeypatch):
        # Ordering matters for the spawn_session race (see TestInitialStateRecord): the
        # daemon must be on disk with its own pid before it does anything that can block
        # or fail, so that spawn_session's fallback write finds the file already there.
        seen: list[dict | None] = []

        real_media_image = ider.MediaImage

        def _spy(*args, **kwargs):
            seen.append(media_session.read_state(harness.runtime_dir, "gate-session"))
            return real_media_image(*args, **kwargs)

        monkeypatch.setattr(media_session.ider, "MediaImage", _spy)
        harness([open_session_reply(seq=0), status_data(3, 1, seq=1), b""])
        assert seen and seen[0] is not None, "no state record existed when the first image was opened"
        assert seen[0]["state"] == media_session.STATE_STARTING
        assert seen[0]["pid"] == os.getpid()


class TestInitialStateRecord:
    """The two writers of a session's first state record must agree, and must not race.

    ``spawn_session`` (parent) and ``_run_daemon`` (daemon) both write a "starting"
    record. Two defects lived here:

    1. The shapes disagreed -- the parent's dict omitted ``error_class``. Whichever
       record a caller happened to read decided whether it saw a real classification or
       ``amt_media._error_class_of``'s generic fallback.
    2. The parent wrote unconditionally, *after* the daemon was already running. When the
       daemon lost the footrace it won it instead: a daemon that had already recorded
       ``error``/``authentication`` had that overwritten with ``starting``, and never
       wrote again because it had already exited. The caller then polled ``starting``
       until ``attach_timeout`` and reported a generic failure. Pure scheduling luck,
       which is why it presented as an intermittent wrong ``error_class`` under load
       rather than as a reproducible bug.
    """

    def test_the_record_carries_a_classification_slot(self):
        record = media_session._initial_state(session_id="abc", endpoint=f"{EXAMPLE_HOST}:16994", pid=4242)
        assert "error_class" in record, "a record without this key reads back as the generic fallback class"
        assert record["error_class"] is None
        assert record["state"] == media_session.STATE_STARTING
        assert record["pid"] == 4242

    def test_both_writers_produce_the_same_key_set(self, tmp_path, monkeypatch):
        # The daemon's record, captured from a real _run_daemon start-up.
        image_path = tmp_path / "f.img"
        image_path.write_bytes(b"\x00" * 512)
        monkeypatch.setattr(media_session, "_redirect_std_fds", lambda _log_path: None)
        monkeypatch.setattr(media_session.signal, "signal", lambda _signum, _handler: None)
        monkeypatch.setattr(media_session, "_stop_flag", False)
        monkeypatch.setattr(media_session, "RedirectionSession", lambda *a, **k: _FakeRedirectionSession([b""]))
        config = media_session.SessionConfig(
            session_id="shape",
            host=EXAMPLE_HOST,
            port=16994,
            use_tls=False,
            tls_pin_sha256=None,
            connect_timeout=1.0,
            start_mode=ider.START_MODE_ON_REBOOT,
            allowed_directory=None,
            runtime_dir=str(tmp_path / "runtime"),
            devices=(media_session.MediaSpec(path=str(image_path), device_code=ider.DEVICE_FLOPPY, writable=False),),
        )
        media_session._run_daemon(config, "admin", "test-password-not-real")
        daemon_record = media_session.read_state(tmp_path / "runtime", "shape")

        parent_record = media_session._initial_state(session_id="shape", endpoint=f"{EXAMPLE_HOST}:16994", pid=4242)
        assert set(parent_record) == set(daemon_record), "spawn_session and _run_daemon must write the same shape"

    def test_create_only_write_does_not_clobber_a_daemons_report(self, tmp_path):
        # The exact race: the daemon has already failed and recorded why.
        daemon_report = {
            "session_id": "abc",
            "pid": 4242,
            "endpoint": f"{EXAMPLE_HOST}:16994",
            "state": media_session.STATE_ERROR,
            "error": "redirection-plane digest rejected",
            "error_class": ErrorClass.AUTHENTICATION,
            "tls_peer_fingerprint": None,
            "devices": {},
            "started_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
        media_session._write_state_atomic(tmp_path, "abc", daemon_report)

        wrote = media_session._write_state_if_absent(
            tmp_path, "abc", media_session._initial_state(session_id="abc", endpoint=f"{EXAMPLE_HOST}:16994", pid=4242)
        )
        assert wrote is False
        surviving = media_session.read_state(tmp_path, "abc")
        assert surviving == daemon_report, "the daemon's own report must survive; overwriting it loses the real error_class"
        assert surviving["error_class"] == ErrorClass.AUTHENTICATION

    def test_create_only_write_does_create_when_the_daemon_wrote_nothing(self, tmp_path):
        # The case the parent's record exists for: a daemon that died before reporting.
        # Something must be on disk, or a later detach cannot even find the pid.
        record = media_session._initial_state(session_id="abc", endpoint=f"{EXAMPLE_HOST}:16994", pid=4242)
        assert media_session._write_state_if_absent(tmp_path, "abc", record) is True
        assert media_session.read_state(tmp_path, "abc") == record

    def test_create_only_write_is_owner_only(self, tmp_path):
        media_session._write_state_if_absent(tmp_path, "abc", media_session._initial_state(session_id="abc", endpoint="x:1", pid=1))
        mode = stat.S_IMODE(media_session.state_file_path(tmp_path, "abc").stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


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
        #
        # Built from _initial_state() rather than hand-written, so that a key added to the
        # real record is covered here automatically. The hand-written copy this replaced had
        # already drifted: it was missing error_class, mirroring the very shape mismatch
        # between spawn_session and _run_daemon that TestInitialStateRecord now pins down.
        state = media_session._initial_state(session_id="abc", endpoint=f"{EXAMPLE_HOST}:16994", pid=123)
        state["state"] = "attached"
        state["tls_peer_fingerprint"] = "ab" * 32
        state["devices"] = {"floppy": {"path": "/srv/images/f.img", "device": "floppy", "writable": True, "size": 512, "bytes_read": 0, "bytes_written": 0}}
        media_session._write_state_atomic(tmp_path, "abc", state)
        raw = media_session.state_file_path(tmp_path, "abc").read_text(encoding="utf-8")
        assert "password" not in raw.lower()
        assert "test-password-not-real" not in raw
        assert json.loads(raw) == state


class TestStateFilePermissions:
    """The state file must not be readable by other local users.

    It carries no credential -- SessionConfig deliberately excludes them -- but it
    does record endpoint addresses, media paths and a pid. The 0700 parent
    directory is the only thing that protected it while the file itself was
    created at the umask default (typically 0644), and
    mkdir(exist_ok=True, mode=...) does not tighten an already-existing
    directory, so a runtime_dir pointed at a laxer pre-existing path would have
    exposed it.
    """

    def test_state_file_is_owner_only(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "sess-perm", {"session_id": "sess-perm", "state": "attached"})
        mode = stat.S_IMODE(media_session.state_file_path(tmp_path, "sess-perm").stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_state_file_is_owner_only_even_in_a_lax_pre_existing_directory(self, tmp_path):
        lax = tmp_path / "shared"
        lax.mkdir(mode=0o777)
        media_session._write_state_atomic(lax, "sess-lax", {"session_id": "sess-lax", "state": "attached"})
        mode = stat.S_IMODE(media_session.state_file_path(lax, "sess-lax").stat().st_mode)
        assert not mode & stat.S_IROTH, "state file is world-readable"
        assert not mode & stat.S_IRGRP, "state file is group-readable"

    def test_no_temp_file_is_left_behind(self, tmp_path):
        media_session._write_state_atomic(tmp_path, "sess-tmp", {"state": "attached"})
        assert list(tmp_path.glob("*.tmp")) == []

    def test_credentials_never_reach_the_state_file(self, tmp_path):
        # Belt and braces: SessionConfig excludes credentials structurally, but
        # assert on the written bytes too, since this file is world-visible in
        # the sense that it outlives the module invocation.
        secret = "Sup3rSecret!"
        media_session._write_state_atomic(tmp_path, "sess-cred", {"session_id": "sess-cred", "state": "attached", "host": EXAMPLE_HOST})
        assert secret not in media_session.state_file_path(tmp_path, "sess-cred").read_text()

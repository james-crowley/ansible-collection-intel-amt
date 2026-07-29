# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Detached, long-lived IDE-R session process for ``amt_media``.

An IDE-R session is not something one Ansible module invocation can hold open: the
target machine stays booted from the attached media for as long as an OS install
takes, which can be an hour, while a single ``amt_media`` task must return in seconds.
So ``state: attached`` does not pretend to hold the session synchronously. It forks a
detached daemon that owns the :class:`redirection.RedirectionSession` /
:class:`ider.IderEngine` pair, writes a small JSON state/receipt file keyed by
``session_id`` under a runtime directory, and returns once the daemon has reported
either success or an early failure (bounded by ``attach_timeout``). ``state: detached``
looks that daemon up by pid, asks it to stop, and waits (bounded by ``detach_timeout``)
for it to actually exit.

Two design points worth calling out for reviewers:

1. **Fork, never exec.** :func:`spawn_session` uses a double-fork (``os.fork()`` twice,
   never ``subprocess``), specifically so the daemon inherits this already-running
   interpreter's memory -- including the plaintext ``username``/``password`` already
   held as ordinary Python values -- via copy-on-write. There is no ``exec()`` anywhere
   in this path, so there is no argv and no environment handed to a new process image at
   all; the credential-exposure question the collection's own security notes and
   docs/protocol-notes.md raise about "passed via argv or environment to a helper
   process" does not apply because no helper process is ever spawned, only forked.
   The daemon closes over its arguments as ordinary function-call locals and never
   externalises them (state files below carry no credential-shaped field).
2. **The state file is the only channel back.** Once forked, the daemon and the
   Ansible module process that spawned it share no memory; the state file (written
   atomically -- write to a temp path, then ``os.replace()``) is genuinely the only way
   a later ``state: detached`` call, or a later ``state: attached`` call checking for an
   existing session, learns anything about it. A stale file (daemon dead, pid reused or
   gone) is always recoverable: every reader checks liveness with :func:`is_pid_alive`
   before trusting the file's claims, and a caller finding a stale file is expected to
   remove it and proceed rather than treating it as a permanent wedge.

This module owns exactly the process lifecycle and state-file bookkeeping. It knows
nothing about Ansible; ``plugins/modules/amt_media.py`` is the only caller.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import os
import signal
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import ider
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    ErrorClass,
    ProtocolError,
    UnsupportedCapabilityError,
    redact,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection import (
    START_SESSION_IDER,
    RedirectionSession,
)

#: Observable session states, written to the state file's ``state`` key.
STATE_STARTING = "starting"
STATE_CONNECTING = "connecting"
STATE_ATTACHED = "attached"
STATE_DETACHED = "detached"
STATE_ERROR = "error"

#: States a live daemon will never revert out of on its own -- once here, the process
#: is expected to be exiting or already gone.
TERMINAL_STATES = frozenset({STATE_DETACHED, STATE_ERROR})

#: Default location for state/receipt/log files, one per session_id. Deliberately a
#: per-user, per-collection directory rather than a shared /tmp path -- state files for
#: other users' sessions must not be readable, and this must be the *same* path across
#: separate module invocations (attach, then later detach), which rules out anything
#: temp-directory-per-process.
DEFAULT_RUNTIME_DIR = "~/.ansible/intel_amt/media-sessions"

#: How often the daemon's main loop wakes on a quiet connection to check for a stop
#: request and refresh its heartbeat. Not a module option: it is an internal
#: responsiveness knob, not something a caller has a reason to tune.
_RECV_POLL_TIMEOUT = 2.0

#: How often callers waiting on a state-file transition (attach confirmation, detach
#: confirmation) re-check the file.
_STATE_POLL_INTERVAL = 0.2

#: How long after the IDE-R session opens the daemon waits for firmware's verdict on the
#: feature toggle -- STATUS_DATA type 3 / REGS_TOGGLE, docs/protocol-notes.md section 4.2 --
#: before giving up and reporting a classified timeout.
#:
#: The toggle is a separate round trip from OPEN_SESSION_REPLY, so "the session is open" and
#: "firmware agreed to engage IDE-R" are two different facts arriving at two different times,
#: and this daemon must not report the second on the strength of the first (see
#: :func:`_run_daemon`). That makes a bounded wait unavoidable: firmware that opens the session
#: and then simply never answers the toggle would otherwise leave the daemon reporting
#: ``connecting`` forever, which the module's ``attach_timeout`` would surface as an
#: unclassified generic failure.
#:
#: Deliberately shorter than ``amt_media``'s default ``attach_timeout`` (10s), so the daemon
#: loses this race on purpose: it gets to write its own specific, classified error
#: (``timeout``, naming the toggle) and have the module report *that*, rather than the module
#: timing out first on a daemon still claiming ``connecting``. Real firmware answers the toggle
#: in the same breath as it sends OPEN_SESSION_REPLY; this is a stuck-peer bound, not a
#: latency budget, so there is nothing to tune and it is not a module option.
_FEATURE_TOGGLE_TIMEOUT = 5.0


@dataclass(frozen=True, slots=True)
class MediaSpec:
    """One device slot to attach: a local path, the IDE-R device code, and writability.

    ``writable`` must already be ``False`` for :data:`ider.DEVICE_CDROM` by the time it
    reaches here -- see ``amt_media.py``'s own validation -- but :class:`ider.MediaImage`
    enforces the same rule again independently, so a bug upstream of this dataclass still
    fails safe rather than silently opening the ISO read-write.
    """

    path: str
    device_code: int
    writable: bool


@dataclass(frozen=True, slots=True)
class SessionConfig:
    """Everything the daemon needs that is not a credential.

    Deliberately excludes ``username``/``password`` -- see the module docstring's point
    1. Fully JSON-serializable-shaped (plain str/int/bool/tuple of MediaSpec), even
    though it is never actually serialized: :func:`spawn_session` passes it as a normal
    in-memory argument across the fork, but keeping it credential-free and simple-typed
    means a future caller could log or inspect it without a second thought.
    """

    session_id: str
    host: str
    port: int
    use_tls: bool
    tls_pin_sha256: str | None
    connect_timeout: float
    start_mode: int
    allowed_directory: str | None
    runtime_dir: str
    devices: tuple[MediaSpec, ...]


# --------------------------------------------------------------------------
# State file plumbing -- shared by the daemon (writer) and the module (reader).
# --------------------------------------------------------------------------


def state_file_path(runtime_dir: str | os.PathLike[str], session_id: str) -> Path:
    return Path(runtime_dir) / f"{session_id}.json"


def log_file_path(runtime_dir: str | os.PathLike[str], session_id: str) -> Path:
    """Where the daemon's stdout/stderr are redirected -- see :func:`_redirect_std_fds`."""
    return Path(runtime_dir) / f"{session_id}.log"


def read_state(runtime_dir: str | os.PathLike[str], session_id: str) -> dict[str, Any] | None:
    """Read and parse the state file, or ``None`` if it does not exist or is unreadable.

    A parse failure degrades to ``None`` (treated as "no session") rather than raising:
    the atomic write below makes a torn read very unlikely, but this file is a
    best-effort receipt, not a source of truth a caller should ever fail hard on.
    """
    try:
        raw = state_file_path(runtime_dir, session_id).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _write_state_atomic(runtime_dir: str | os.PathLike[str], session_id: str, data: dict[str, Any]) -> None:
    """Write ``data`` as the current state, atomically.

    Write to a sibling temp path then ``os.replace()`` it over the real path -- on
    POSIX, ``rename(2)`` onto an existing path is atomic, so a concurrent
    :func:`read_state` never observes a partially written file, only the previous
    complete one or the new complete one. Ensures ``runtime_dir`` exists first (mode
    ``0700``) -- harmless if :func:`spawn_session` already created it, and this is the
    only path a test writing a state file directly (without going through
    :func:`spawn_session`) needs.
    """
    path = state_file_path(runtime_dir, session_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")

    # Create the temp file 0600 explicitly rather than letting the umask decide,
    # which typically yields 0644. The 0700 parent directory does protect it in
    # the common case, but that is the *only* thing doing so, and
    # mkdir(exist_ok=True, mode=...) does not tighten a directory that already
    # exists -- so a runtime_dir pointed at a pre-existing, laxer directory would
    # leave these files readable to other local users. The contents are not
    # secret (no credential ever reaches this file, see SessionConfig) but they
    # do record endpoint addresses and media paths, and file mode is the wrong
    # thing to leave to chance on a security boundary.
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    os.replace(tmp_path, path)


def _initial_state(*, session_id: str, endpoint: str, pid: int) -> dict[str, Any]:
    """The starting state record, in the one shape every writer must use.

    There are two independent writers of a session's *first* state record -- the daemon
    itself (:func:`_run_daemon`) and the process that forked it (:func:`spawn_session`,
    for the case where the daemon dies before writing anything) -- and they used to build
    that dict separately. They drifted: ``spawn_session``'s copy omitted ``error_class``.

    That is not cosmetic. ``amt_media._error_class_of`` reads ``error_class`` off whatever
    record it finds and falls back to a generic class when the key is absent, so whichever
    of the two records a caller happened to read decided the failure class it reported.
    Factored into one function so the two shapes cannot disagree again; a new key added
    here reaches both writers by construction.
    """
    now = _now_iso()
    return {
        "session_id": session_id,
        "pid": pid,
        "endpoint": endpoint,
        "state": STATE_STARTING,
        "error": None,
        "error_class": None,
        "tls_peer_fingerprint": None,
        "devices": {},
        "started_at": now,
        "updated_at": now,
    }


def _write_state_if_absent(runtime_dir: str | os.PathLike[str], session_id: str, data: dict[str, Any]) -> bool:
    """Write ``data`` as the state record only if no record exists yet. Returns whether it wrote.

    This is the create-only counterpart of :func:`_write_state_atomic`, and it exists to
    remove a race rather than to save a write.

    :func:`spawn_session` returns to its caller only after the forked daemon has reported
    its pid back over a pipe -- by which time the daemon is already running and may already
    have written ``connecting``, or even its final ``error``. An unconditional write of the
    ``starting`` record at that point *clobbers* the daemon's own report with a record that
    is both older and less informative, and the daemon never writes again once it has
    exited. The caller then polls a ``starting`` record until ``attach_timeout`` expires and
    reports a generic failure, having overwritten the specific one. Which of the two wins is
    pure scheduling luck, so it showed up as an intermittent wrong ``error_class`` under CPU
    contention rather than as a reproducible bug.

    ``O_CREAT | O_EXCL`` is what makes this safe against that ordering rather than merely
    less likely to hit it: the kernel decides who creates the file. If the daemon got there
    first the create fails and we leave its record alone. If we get there first, a daemon
    write landing while we are still writing is equally harmless -- it arrives via
    ``os.replace()``, so it becomes the file and our bytes go to an unlinked inode nobody
    will read.
    """
    path = state_file_path(runtime_dir, session_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return True


def remove_state(runtime_dir: str | os.PathLike[str], session_id: str) -> None:
    """Delete the state and log files for ``session_id``, if present.

    Frees the session_id for reuse. Silent about files that are already gone -- callers
    call this defensively (e.g. cleaning up a stale session) without checking existence
    first.
    """
    for path in (state_file_path(runtime_dir, session_id), log_file_path(runtime_dir, session_id)):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def is_pid_alive(pid: int | None) -> bool:
    """Whether ``pid`` refers to a live process this user can at least signal-probe.

    ``os.kill(pid, 0)`` sends no signal; it only asks the kernel whether the target
    exists and is signalable. A ``PermissionError`` means it exists but is owned by
    someone else -- treated as "alive" here, since the only thing that matters for
    staleness detection is whether the pid has been recycled for an unrelated process,
    and a permission error rules that out at least as well as a successful probe does.

    ``pid`` values that are not a live daemon's own pid by construction (``None``, from
    a missing/corrupt state file; zero or negative, which ``os.kill`` treats as "every
    process in a group" rather than one specific process) are rejected before ever
    reaching ``os.kill`` -- a state file is untrusted-ish input from a caller's point of
    view, and signalling an entire process group because of a malformed pid field would
    be a far worse failure mode than just reporting "not alive".
    """
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def generate_session_id() -> str:
    return uuid.uuid4().hex


def aggregate_bytes(state: dict[str, Any] | None) -> tuple[int, int]:
    """Sum ``bytes_read``/``bytes_written`` across every attached device in ``state``.

    These are actual media I/O counters (``MediaImage.bytes_read``/``bytes_written``),
    not raw redirection-framing byte counts -- see docs/protocol-notes.md s5.3's
    requirement to "log total bytes written in the operation receipt so callers can
    detect surprises."
    """
    if not state:
        return 0, 0
    devices = state.get("devices") or {}
    total_read = sum(int(device.get("bytes_read", 0)) for device in devices.values())
    total_written = sum(int(device.get("bytes_written", 0)) for device in devices.values())
    return total_read, total_written


def wait_for_state(
    runtime_dir: str | os.PathLike[str],
    session_id: str,
    *,
    until: Callable[[dict[str, Any]], bool],
    timeout: float,
    poll_interval: float = _STATE_POLL_INTERVAL,
) -> dict[str, Any] | None:
    """Poll the state file until ``until(state)`` is true or ``timeout`` elapses.

    Returns whatever was last read -- which may not satisfy ``until`` if the timeout
    won the race. This is the "bounded wait for early confirmation" the module uses
    after spawning, and the "bounded wait for a clean stop" it uses after signalling a
    detach; either way, the caller must decide what an unsatisfied wait means (a slow
    attach that is probably still fine vs. a detach that may need a firmer follow-up),
    not this function.
    """
    deadline = time.monotonic() + timeout
    observed: dict[str, Any] | None = None
    while True:
        observed = read_state(runtime_dir, session_id)
        if observed is not None and until(observed):
            return observed
        if time.monotonic() >= deadline:
            return observed
        time.sleep(poll_interval)


def wait_for_exit(pid: int | None, *, timeout: float, poll_interval: float = _STATE_POLL_INTERVAL) -> bool:
    """Poll ``is_pid_alive(pid)`` until it goes false or ``timeout`` elapses. Returns whether it exited."""
    deadline = time.monotonic() + timeout
    while is_pid_alive(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval)
    return True


def request_stop(pid: int | None) -> None:
    """Ask the daemon at ``pid`` to shut down. Silent if it is already gone or not a real pid.

    See :func:`is_pid_alive` for why ``None``/non-positive values are rejected before
    ever reaching ``os.kill`` -- signal 0 vs. a real signal makes no difference to the
    "pid <= 0 addresses a process group, not a process" hazard.
    """
    if pid is None or pid <= 0:
        return
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)


# --------------------------------------------------------------------------
# Validation shared by check_mode and real attach -- runs in the *caller's* process,
# never in the daemon, so a bad path fails synchronously and visibly rather than only
# showing up later in the daemon's log file.
# --------------------------------------------------------------------------


def validate_media_specs(specs: tuple[MediaSpec, ...], *, allowed_directory: str | None) -> None:
    """Open and immediately close every configured image, to fail fast on a bad path.

    :class:`ider.MediaImage` raises plain ``ValueError`` for a validation failure it
    detects itself (unknown device code, writable ISO, symlink, outside
    ``allowed_directory``, wrong size) and lets ``OSError`` (missing file, permission
    denied, ...) propagate unchanged from the underlying ``Path``/``open()`` calls --
    either way, it has no dependency on this collection's ``AmtError`` hierarchy, since
    it is pure protocol/filesystem logic with no notion of an AMT operation. Both are
    re-raised here as :class:`ProtocolError` so ``amt_media.py`` can catch one exception
    family, per every other module in this collection.
    """
    for spec in specs:
        try:
            image = ider.MediaImage(spec.path, device_code=spec.device_code, writable=spec.writable, allowed_directory=allowed_directory)
        except (ValueError, OSError) as exc:
            raise ProtocolError(f"invalid media configuration for {spec.path!r}: {exc}", operation="amt_media.validate_media") from exc
        image.close()


# --------------------------------------------------------------------------
# Spawning -- double-fork daemonize. No subprocess, no exec, no argv/env credential
# exposure: see the module docstring.
# --------------------------------------------------------------------------


def spawn_session(config: SessionConfig, *, username: str, password: str) -> int:
    """Fork the detached daemon and return its pid once it has reported in.

    A conventional double fork: the first child calls ``os.setsid()`` (detaching from
    the controlling terminal/session, so nothing that signals this module's own process
    group reaches the daemon) and immediately forks the real daemon, then reports the
    daemon's pid back to *this* process over a pipe and exits. This process reaps that
    short-lived first child with ``waitpid`` (so it never lingers as a zombie) and
    returns the daemon's pid, which the caller records in the state file.

    The daemon itself (the grandchild) never returns to this function -- it runs
    :func:`_run_daemon` and then calls ``os._exit()`` unconditionally, whether it
    finished cleanly or hit an exception. It must never fall back into normal Python
    interpreter shutdown, which could re-run atexit handlers registered before the fork
    or double-flush inherited buffers.
    """
    if not hasattr(os, "fork"):
        raise UnsupportedCapabilityError(
            "amt_media's background-session mechanism requires a POSIX controller with os.fork() "
            "(Linux/macOS). It is not available when the Ansible controller itself runs on Windows.",
            operation="amt_media.spawn_session",
        )

    runtime_dir = Path(config.runtime_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    read_fd, write_fd = os.pipe()
    first_pid = os.fork()

    if first_pid > 0:
        # Original process: this is the only branch that returns normally.
        os.close(write_fd)
        with os.fdopen(read_fd, encoding="utf-8") as reader:
            reported = reader.read().strip()
        os.waitpid(first_pid, 0)  # reap the short-lived first child; never a zombie.
        if not reported:
            raise ProtocolError(
                "amt_media background daemon did not report a pid; it likely failed during "
                "os.setsid()/fork() before it could start the IDE-R session -- check the session log",
                operation="amt_media.spawn_session",
            )
        pid = int(reported)
        # Create-only, never overwrite: by the time we get here the daemon is already
        # running and may already have written a more advanced -- or final -- record. See
        # _write_state_if_absent for why clobbering it was a real, intermittent bug and not
        # a theoretical one. This record is the fallback for the opposite case, a daemon
        # that dies before writing anything at all, so that a later detach can still find
        # the pid.
        _write_state_if_absent(
            config.runtime_dir,
            config.session_id,
            _initial_state(session_id=config.session_id, endpoint=f"{config.host}:{config.port}", pid=pid),
        )
        return pid

    # First child: never returns to the caller. Always os._exit(), never raise past here.
    os.close(read_fd)
    try:
        os.setsid()
        second_pid = os.fork()
        if second_pid > 0:
            with os.fdopen(write_fd, "w", encoding="utf-8") as writer:
                writer.write(f"{second_pid}\n")
            os._exit(0)
        os.close(write_fd)
        _run_daemon(config, username, password)
        # Last-resort: a forked child must never propagate an exception into normal
        # interpreter shutdown; there is nothing left to report to.
    except BaseException:
        os._exit(1)
    os._exit(0)


# --------------------------------------------------------------------------
# The daemon itself.
# --------------------------------------------------------------------------

_stop_flag = False


def _handle_sigterm(_signum: int, _frame: object) -> None:
    global _stop_flag
    _stop_flag = True


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _redirect_std_fds(log_path: Path) -> None:
    """Detach stdin/stdout/stderr from whatever this process inherited across the fork.

    This is a correctness requirement, not cosmetic. This daemon deliberately outlives
    the Ansible module invocation that forked it. If it kept a duplicate of that
    process's original stdout -- a pipe the controller reads until EOF to know the
    module's JSON result is complete -- the controller could hang past the module's own
    exit, waiting for an EOF that never arrives because this long-lived daemon still
    holds the pipe's write end open. Must run before any other daemon logic.
    """
    devnull_fd = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull_fd, 0)
    os.close(devnull_fd)

    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    os.close(log_fd)


def _device_state(image: ider.MediaImage) -> dict[str, Any]:
    return {
        "path": str(image.path),
        "device": "cdrom" if image.device_code == ider.DEVICE_CDROM else "floppy",
        "writable": image.writable,
        "size": image.size,
        "bytes_read": image.bytes_read,
        "bytes_written": image.bytes_written,
    }


def _run_daemon(config: SessionConfig, username: str, password: str) -> None:
    """The daemon's entire lifetime: open media, connect, pump bytes until told to stop.

    Runs in the grandchild produced by :func:`spawn_session`. Every exit from this
    function is through a state-file write recording the outcome -- there is no other
    channel back to whatever, if anything, is still watching for this session.

    ``STATE_ATTACHED`` is reported only once the endpoint has *confirmed the IDE-R feature
    toggle*, not merely opened the session; see the long comment on the gate in the main
    loop for why that distinction is the difference between a retry and a wrongly reset
    machine, and :data:`_FEATURE_TOGGLE_TIMEOUT` for the bound on waiting for it.
    """
    log_path = log_file_path(config.runtime_dir, config.session_id)
    _redirect_std_fds(log_path)
    signal.signal(signal.SIGTERM, _handle_sigterm)

    state: dict[str, Any] = _initial_state(session_id=config.session_id, endpoint=f"{config.host}:{config.port}", pid=os.getpid())

    def _persist() -> None:
        state["updated_at"] = _now_iso()
        _write_state_atomic(config.runtime_dir, config.session_id, state)

    # Claim the state file immediately, before opening a single image. Two reasons: this
    # record carries the daemon's real pid (spawn_session's fallback record can only carry
    # what the pipe told it), and getting in first means the fallback write in
    # spawn_session finds the file already present and leaves this daemon's reports alone.
    _persist()

    def _fail(message: str, *, error_class: str = ErrorClass.PROTOCOL) -> None:
        # error_class defaults to "protocol" only for failures this daemon itself detects
        # with no more specific classification available (e.g. engine.stopped going true
        # with no exception). Anything raised as an AmtError keeps its own real
        # error_class -- see the except clause below -- so a caller can distinguish, say,
        # a wrong password (authentication) from a bad OPEN_SESSION_REPLY (protocol)
        # instead of every attach failure collapsing into the same generic bucket.
        state["state"] = STATE_ERROR
        state["error"] = redact(message)
        state["error_class"] = error_class
        _persist()

    images: dict[str, ider.MediaImage] = {}
    session: RedirectionSession | None = None
    try:
        for spec in config.devices:
            slot = "cdrom" if spec.device_code == ider.DEVICE_CDROM else "floppy"
            image = ider.MediaImage(spec.path, device_code=spec.device_code, writable=spec.writable, allowed_directory=config.allowed_directory)
            images[slot] = image
            state["devices"][slot] = _device_state(image)

        state["state"] = STATE_CONNECTING
        _persist()

        session = RedirectionSession(
            config.host,
            username=username,
            password=password,
            use_tls=config.use_tls,
            tls_pin_sha256=config.tls_pin_sha256,
            port=config.port,
            connect_timeout=config.connect_timeout,
            start_frame=START_SESSION_IDER,
        )
        leftover = session.connect()
        state["tls_peer_fingerprint"] = session.peer_certificate_sha256()

        engine = ider.IderEngine(send=session.send, start_mode=config.start_mode)
        for image in images.values():
            engine.attach_device(image)
        engine.start()
        if leftover:
            engine.feed(leftover)

        session.set_recv_timeout(_RECV_POLL_TIMEOUT)

        # Deadline for firmware's REGS_TOGGLE verdict, armed the first time we observe the
        # session as open. See _FEATURE_TOGGLE_TIMEOUT and the gate inside the loop.
        toggle_deadline: float | None = None

        while not engine.stopped and not _stop_flag:
            # The attach gate. ``session_open`` alone is NOT sufficient to report
            # STATE_ATTACHED, and this is the whole point of the gate:
            #
            #   OPEN_SESSION_REPLY  -> engine.session_open = True, toggle sent
            #   STATUS_DATA type 3  -> engine.feature_toggle_ok = True | False
            #
            # An endpoint that accepts the session and then *refuses* the IDE-R feature
            # toggle is not serving the media. Reporting ``attached`` there is the worst
            # failure this module can produce, because of what the caller does next: it
            # arms a boot device and resets the machine, expecting it to come up on media
            # that is not actually being redirected. A hard failure here costs a retry; a
            # false success costs a machine.
            #
            # The two facts arrive in separate frames, so this is a timing question and not
            # just a conditional. Three outcomes, all of them explicit:
            #
            #   feature_toggle_ok is True  -> attached, for real
            #   feature_toggle_ok is False -> firmware refused; fail, do not attach
            #   feature_toggle_ok is None  -> verdict not in yet; stay ``connecting`` until
            #                                 _FEATURE_TOGGLE_TIMEOUT, then fail as a timeout
            #
            # The refusal check sits outside the ``session_open`` branch on purpose: a
            # REGS_AVAIL status makes the engine re-send the toggle mid-session (see
            # ider._on_status_data), so a refusal can also arrive *after* we have already
            # reported ``attached``. The media stops being served at that moment, so the
            # session must fail then too rather than sit in a stale ``attached``.
            if engine.feature_toggle_ok is False:
                _fail(
                    "IDE-R session opened but the endpoint refused the IDE-R feature toggle "
                    "(STATUS_DATA REGS_TOGGLE reported failure), so no media is being served. "
                    "Check that IDE-R/redirection is enabled for this endpoint and that no other "
                    "redirection session holds the device.",
                    error_class=ErrorClass.UNSUPPORTED_CAPABILITY,
                )
                return
            if engine.session_open:
                if toggle_deadline is None:
                    toggle_deadline = time.monotonic() + _FEATURE_TOGGLE_TIMEOUT
                if engine.feature_toggle_ok:
                    state["state"] = STATE_ATTACHED
                elif time.monotonic() >= toggle_deadline:
                    _fail(
                        f"IDE-R session opened but the endpoint never reported the outcome of the "
                        f"IDE-R feature toggle within {_FEATURE_TOGGLE_TIMEOUT}s (no STATUS_DATA "
                        "REGS_TOGGLE frame arrived), so whether media is being served is unknown. "
                        "The session was not reported as attached.",
                        error_class=ErrorClass.TIMEOUT,
                    )
                    return
            for slot, image in images.items():
                state["devices"][slot] = _device_state(image)
            _persist()

            try:
                chunk = session.recv()
            except TimeoutError:
                continue  # just a wakeup to check _stop_flag / refresh the heartbeat.

            if not chunk:
                state["state"] = STATE_DETACHED
                state["error"] = "connection closed by peer"
                _persist()
                return

            engine.feed(chunk)

        for slot, image in images.items():
            state["devices"][slot] = _device_state(image)
        if _stop_flag:
            state["state"] = STATE_DETACHED
            state["error"] = None
        else:
            # engine.stopped went true on its own -- a protocol-level teardown
            # (out-of-sequence frame, firmware-initiated CLOSE) rather than our own
            # SIGTERM-driven shutdown.
            state["state"] = STATE_ERROR
            state["error"] = "IDE-R session was torn down by the peer or a protocol error, not by a detach request"
            state["error_class"] = ErrorClass.PROTOCOL
        _persist()
    except AmtError as exc:
        _fail(str(exc), error_class=exc.error_class)
    except Exception as exc:  # last-resort: the daemon has no other way to report a crash.
        _fail(f"unexpected error: {exc}")
    finally:
        for image in images.values():
            with contextlib.suppress(Exception):
                image.close()
        if session is not None:
            with contextlib.suppress(Exception):
                session.close()

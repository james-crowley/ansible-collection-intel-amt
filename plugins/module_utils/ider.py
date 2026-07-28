# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Intel AMT IDE-R (IDE Redirect) engine: framing, SCSI emulation, virtual media.

This module is pure protocol logic. It never touches a socket: bytes come in
via :meth:`IderEngine.feed`, and outbound protocol bytes leave through the
``send`` callable supplied at construction. The transport and authentication
handshake that gets you to the point of calling this live in
:mod:`ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection`.

Wire layouts are normative and come from ``docs/protocol-notes.md`` sections 4
and 5. The canned SCSI reply arrays are copied verbatim (Apache-2.0) from
Intel/MeshCentral's ``amt-ider-module.js`` -- they encode drive geometry a real
BIOS expects and are deliberately not "cleaned up" here. See ``NOTICE``.

The one deliberate behavioural departure from that reference is writable
media (docs/protocol-notes.md section 5): the reference is read-only for both
device slots. Floppy/USB-R (:data:`DEVICE_FLOPPY`) can be opened writable
here; CD/DVD (:data:`DEVICE_CDROM`) cannot -- see :class:`MediaImage`.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ProtocolError

# --------------------------------------------------------------------------
# Command IDs (docs/protocol-notes.md section 4.2)
# --------------------------------------------------------------------------

CMD_OPEN_SESSION = 0x40
CMD_OPEN_SESSION_REPLY = 0x41
CMD_CLOSE = 0x43
CMD_KEEPALIVE_PING = 0x44
CMD_KEEPALIVE_PONG = 0x45
CMD_RESET_OCCURRED = 0x46
CMD_RESET_OCCURRED_RESPONSE = 0x47
CMD_DISABLE_ENABLE_FEATURES = 0x48
CMD_STATUS_DATA = 0x49
CMD_ERROR_OCCURRED = 0x4A
CMD_HEARTBEAT = 0x4B
CMD_COMMAND_WRITTEN = 0x50
CMD_COMMAND_END_RESPONSE = 0x51
CMD_GET_DATA_FROM_HOST = 0x52
CMD_DATA_FROM_HOST = 0x53
CMD_DATA_TO_HOST = 0x54

#: Fixed-length inbound commands: cmdid -> total frame length (header included).
_FIXED_LENGTH_COMMANDS: dict[int, int] = {
    CMD_CLOSE: 8,
    CMD_KEEPALIVE_PING: 8,
    CMD_KEEPALIVE_PONG: 8,
    CMD_HEARTBEAT: 8,
    CMD_RESET_OCCURRED: 9,
    CMD_STATUS_DATA: 13,
    CMD_ERROR_OCCURRED: 11,
    CMD_COMMAND_WRITTEN: 28,
}

# --------------------------------------------------------------------------
# Device model (docs/protocol-notes.md section 4.4)
# --------------------------------------------------------------------------

#: Floppy / USB-R. 512-byte sectors. The only device that may be writable.
DEVICE_FLOPPY = 0xA0

#: CD/DVD. 2048-byte sectors. Read-only by design -- see MediaImage.
DEVICE_CDROM = 0xB0

# --------------------------------------------------------------------------
# Feature-toggle start modes (docs/protocol-notes.md section 4.1)
# --------------------------------------------------------------------------

START_MODE_ON_REBOOT = 0x01 + 0x08  # 0x09
START_MODE_GRACEFUL = 0x01 + 0x10  # 0x11
START_MODE_IMMEDIATE = 0x01 + 0x18  # 0x19

_MAX_READ_WRITE_BUFFER = 8192

# --------------------------------------------------------------------------
# Canned SCSI reply arrays, copied verbatim from amt-ider-module.js
# (Apache-2.0, Intel Corporation / Ylian Saint-Hilaire). Do not "clean up" the
# byte layouts -- they are what real firmware/BIOS expects. See NOTICE.
#
# These are shared, immutable module-level constants. Any code path that
# needs a mutated copy (clearing the write-protect bit) MUST copy first --
# see _mode_sense_10_page() -- never index-assign into these directly.
# --------------------------------------------------------------------------

_MS_LS120_DISK_PAGE = bytes(
    [
        0x00, 0x26, 0x31, 0x80, 0x00, 0x00, 0x00, 0x00, 0x05, 0x1E, 0x10, 0xA9, 0x08, 0x20, 0x02, 0x00,
        0x03, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0xD0, 0x00, 0x00,
    ]
)  # fmt: skip

_MS_3F_LS120 = bytes(
    [
        0x00, 0x5C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x03, 0x16, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x05, 0x1E, 0x10, 0xA9, 0x08, 0x20,
        0x02, 0x00, 0x03, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xD0, 0x00, 0x00, 0x08, 0x0A, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x06, 0x00, 0x00, 0x00, 0x11, 0x24, 0x31,
    ]
)  # fmt: skip

_MS_FLOPPY_DISK_PAGE = bytes(
    [
        0x00, 0x26, 0x24, 0x80, 0x00, 0x00, 0x00, 0x00, 0x05, 0x1E, 0x04, 0xB0, 0x02, 0x12, 0x02, 0x00,
        0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0xD0, 0x00, 0x00,
    ]
)  # fmt: skip

_MS_3F_FLOPPY = bytes(
    [
        0x00, 0x5C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x03, 0x16, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x05, 0x1E, 0x04, 0xB0, 0x02, 0x12,
        0x02, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xD0, 0x00, 0x00, 0x08, 0x0A, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x06, 0x00, 0x00, 0x00, 0x11, 0x24, 0x31,
    ]
)  # fmt: skip

_MS_CD_1A = bytes([0x00, 0x12, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
_MS_CD_1D = bytes([0x00, 0x12, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
_MS_CD_2A = bytes(
    [
        0x00, 0x20, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x18, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]
)  # fmt: skip
_MS_3F_CD = bytes(
    [
        0x00, 0x28, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x2A, 0x18, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
)  # fmt: skip

_MS_FLOPPY_ERROR_RECOVERY = bytes([0x00, 0x12, 0x24, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
_MS_LS120_ERROR_RECOVERY = bytes([0x00, 0x12, 0x31, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
_MS_CD_ERROR_RECOVERY = bytes([0x00, 0x0E, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00])

_CD_CONFIG_PROFILE_LIST = bytes([0x00, 0x00, 0x03, 0x04, 0x00, 0x08, 0x01, 0x00])
_CD_CONFIG_CORE = bytes([0x00, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x02])
_CD_CONFIG_MORPHING = bytes([0x00, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00])
_CD_CONFIG_REMOVABLE = bytes([0x00, 0x03, 0x03, 0x04, 0x29, 0x00, 0x00, 0x02])
_CD_CONFIG_RANDOM = bytes([0x00, 0x10, 0x01, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00])
_CD_CONFIG_READ = bytes([0x00, 0x1E, 0x03, 0x00])
_CD_CONFIG_POWER = bytes([0x01, 0x00, 0x03, 0x00])
_CD_CONFIG_TIMEOUT = bytes([0x01, 0x05, 0x03, 0x00])

_GET_PERFORMANCE_REPLY = bytes([0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00])

#: Bit position of the write-protect flag in the Mode Parameter Header (10)
#: "device-specific parameter" byte, which every canned MODE_SENSE(10) array
#: above carries at index 3. 0x80 = write-protected, 0x00 = writable.
_WRITE_PROTECT_BIT = 0x80


def _mode_sense_10_page(data: bytes, *, writable: bool) -> bytes:
    """Return a private copy of a canned MODE_SENSE(10) page with the
    write-protect bit set or cleared per ``writable``.

    Always copies. The canned arrays above are module-level constants shared
    by every :class:`IderEngine` instance in this process; index-assigning
    into one directly would corrupt every other session (past, present, and
    future) that happens to share this interpreter.
    """
    page = bytearray(data)
    if writable:
        page[3] &= ~_WRITE_PROTECT_BIT
    else:
        page[3] |= _WRITE_PROTECT_BIT
    return bytes(page)


# --------------------------------------------------------------------------
# Virtual media
# --------------------------------------------------------------------------


class MediaImage:
    """One virtual-media backing file attached to an IDE-R device slot.

    Capability split (docs/protocol-notes.md section 5.1), enforced here on
    ``device_code`` rather than on filename or extension, precisely so a
    caller cannot smuggle a writable image onto the CD/DVD slot by naming it
    ``foo.img`` instead of ``foo.iso``:

    - Floppy/USB-R (:data:`DEVICE_FLOPPY`) -- may be opened writable.
    - CD/DVD (:data:`DEVICE_CDROM`) -- always read-only. Emulating an optical
      burner (track/session management, RESERVE_TRACK, CLOSE_TRACK_SESSION)
      is out of scope, and BIOSes generally will not boot such a device
      anyway. ``writable=True`` with this device code is a hard error.

    Safety, applied to every image regardless of device or writability: the
    leaf path must not be a symlink, and if ``allowed_directory`` is given the
    resolved real path must fall inside it. (docs/protocol-notes.md section
    5.3 scopes these checks to writable images; this implementation applies
    them unconditionally, since there is no good reason to allow a read-only
    "ISO" to be a symlink escape either, and the cost of the check is
    negligible. Flagged here for reviewer attention as a deliberate
    broadening of the letter of the spec.)
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        device_code: int,
        writable: bool = False,
        allowed_directory: str | os.PathLike[str] | None = None,
    ) -> None:
        if device_code not in (DEVICE_FLOPPY, DEVICE_CDROM):
            raise ValueError(f"unknown IDE-R device code {device_code:#x}")
        if device_code == DEVICE_CDROM and writable:
            raise ValueError("CD/DVD (0xB0) media is read-only by design; pass writable=False (or attach it as DEVICE_FLOPPY instead)")

        resolved = self._validate_path(Path(path), allowed_directory)

        size = resolved.stat().st_size
        if size % 512 != 0:
            raise ValueError(f"image {resolved} is {size} bytes, which is not a multiple of 512")

        self.path = resolved
        self.device_code = device_code
        self.sector_shift = 11 if device_code == DEVICE_CDROM else 9
        self.size = size
        self.blocks = size >> self.sector_shift
        self.writable = writable
        self.bytes_read = 0
        self.bytes_written = 0
        #: TEST_UNIT_READY reports a media-change unit-attention exactly once
        #: per attach, then goes ready. Tracked per-image, not per-engine, so
        #: re-attaching a fresh image correctly re-announces the change.
        self.media_change_reported = False

        mode = "r+b" if self.writable else "rb"
        self._fh = open(resolved, mode)

    @staticmethod
    def _validate_path(path: Path, allowed_directory: str | os.PathLike[str] | None) -> Path:
        # Check the leaf *before* resolving: resolve() would silently follow
        # a symlink and hide exactly the thing we're refusing.
        if path.is_symlink():
            raise ValueError(f"refusing to open {path}: symlinks are not permitted for virtual media images")
        resolved = path.resolve(strict=True)
        if allowed_directory is not None:
            allowed_resolved = Path(allowed_directory).resolve(strict=True)
            if allowed_resolved != resolved and allowed_resolved not in resolved.parents:
                raise ValueError(f"refusing to open {resolved}: outside allowed directory {allowed_resolved}")
        return resolved

    def read(self, offset: int, length: int) -> bytes:
        self._fh.seek(offset)
        data = self._fh.read(length)
        self.bytes_read += len(data)
        return data

    def write(self, offset: int, data: bytes) -> None:
        if not self.writable:
            # Callers (IderEngine) must have already turned this away with a
            # write-protected SCSI sense; reaching here is an internal bug,
            # not a remote input the host controls.
            raise ProtocolError("internal error: write attempted against a read-only media image")
        # Defence in depth: never grow the backing file, whatever the caller
        # asks for. The IDE-R SCSI layer bounds-checks the declared transfer
        # length and the arriving frames, but this is a remote-driven write
        # path, so the primitive that actually touches the filesystem enforces
        # the invariant too rather than trusting a single upstream guard.
        if offset < 0 or offset + len(data) > self.size:
            raise ProtocolError(
                f"refusing out-of-bounds write: offset {offset} + {len(data)} bytes exceeds image size {self.size}",
            )
        self._fh.seek(offset)
        self._fh.write(data)
        self._fh.flush()
        self.bytes_written += len(data)

    def close(self) -> None:
        self._fh.close()


@dataclass
class _PendingWrite:
    """State recorded between WRITE_6/10/AND_VERIFY and the DATA_FROM_HOST
    frame(s) that carry the payload. Firmware may split one logical write
    across several 0x53 frames, so this tracks how much has arrived so far.
    """

    device: int
    image: MediaImage
    byte_offset: int
    expected_length: int
    received: int = 0


@dataclass
class _ReadRequest:
    device: int
    image: MediaImage
    byte_offset: int
    remaining: int
    dma: bool


@dataclass
class _OpenSessionInfo:
    major: int = 0
    minor: int = 0
    fw_major: int = 0
    fw_minor: int = 0
    readbfr: int = 0
    writebfr: int = 0
    proto: int = 0
    iana: int = 0


def _header(cmdid: int, seq: int, *, completed: bool = False, dma: bool = False) -> bytes:
    attributes = 0
    if dma:
        attributes |= 0x01
    if completed and cmdid > 50:
        attributes |= 0x02
    return bytes([cmdid & 0xFF, 0x00, 0x00, attributes]) + struct.pack("<I", seq & 0xFFFFFFFF)


class IderEngine:
    """The IDE-R state machine: framing, sequencing, feature toggle, and SCSI
    target emulation for one redirection session.

    ``send`` is called with complete outbound frames (header included). It is
    typically :meth:`RedirectionSession.send`, but tests pass a plain list-
    appending callable so the whole engine can be driven without a socket.

    Sequence numbers are independent per direction (docs/protocol-notes.md
    section 4): an inbound mismatch tears the session down immediately --
    :meth:`feed` raises :class:`ProtocolError` and no further data is
    processed. There is no resync path; a fresh session is the only recovery.
    """

    def __init__(
        self,
        *,
        send: Callable[[bytes], None],
        start_mode: int = START_MODE_ON_REBOOT,
        rx_timeout: int = 30000,
        tx_timeout: int = 0,
        heartbeat: int = 20000,
    ) -> None:
        self._send_bytes = send
        self._start_mode = start_mode
        self._rx_timeout = rx_timeout
        self._tx_timeout = tx_timeout
        self._heartbeat = heartbeat

        self._in_seq = 0
        self._out_seq = 0
        self._buf = bytearray()
        self._stopped = False

        self._devices: dict[int, MediaImage] = {}
        self.session_info = _OpenSessionInfo()
        self.session_open = False
        self.enabled = False
        self.feature_toggle_ok: bool | None = None
        self.errors_seen: list[int] = []

        self._pending_write: _PendingWrite | None = None
        self._read_state: _ReadRequest | None = None
        self._read_queue: list[_ReadRequest] = []
        self._reset_pending = False

        self.bytes_to_amt = 0
        self.bytes_from_amt = 0

    @property
    def stopped(self) -> bool:
        return self._stopped

    # -- device attachment -------------------------------------------------

    def attach_device(self, image: MediaImage) -> None:
        self._devices[image.device_code] = image

    def device(self, device_code: int) -> MediaImage | None:
        return self._devices.get(device_code)

    # -- session start ----------------------------------------------------

    def start(self) -> None:
        """Send OPEN_SESSION. Call once, immediately after the redirection
        handshake authenticates."""
        payload = struct.pack("<HHHI", self._rx_timeout, self._tx_timeout, self._heartbeat, 1)
        self._send_command(CMD_OPEN_SESSION, payload)

    # -- outbound framing ---------------------------------------------------

    def _send_command(self, cmdid: int, payload: bytes = b"", *, completed: bool = False, dma: bool = False) -> None:
        frame = _header(cmdid, self._out_seq, completed=completed, dma=dma) + payload
        self._out_seq = (self._out_seq + 1) & 0xFFFFFFFF
        self.bytes_to_amt += len(frame)
        self._send_bytes(frame)

    def _send_disable_enable_features(self, feature_type: int, data: bytes = b"") -> None:
        self._send_command(CMD_DISABLE_ENABLE_FEATURES, bytes([feature_type]) + data)

    def _send_command_end_response(self, error: bool, sense: int, device: int, asc: int = 0, asq: int = 0) -> None:
        """COMMAND_END_RESPONSE (docs/protocol-notes.md section 4.3).

        ``error`` selects the wire *shape*, not "is this good or bad news":
        ``error=True`` sends the fixed 0xC5.../status-0x50 form and the
        ``sense``/``asc``/``asq`` arguments are not transmitted at all;
        ``error=False`` sends the 0x87.../status-0x51 form that actually
        carries the sense triple. This mirrors amt-ider-module.js's
        ``SendCommandEndResponse`` exactly, including call sites where it
        passes a sense code alongside ``error=True`` and that sense code is
        consequently never put on the wire (e.g. the no-medium and
        out-of-bounds paths below). That looks like a latent bug in the
        reference, but real firmware has been driven by exactly this
        behaviour, so it is preserved rather than "fixed" -- see the module
        docstring.
        """
        if error:
            payload = bytes(12) + bytes([0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, device, 0x50, 0x00, 0x00, 0x00])
        else:
            payload = bytes(12) + bytes([0x87, (sense << 4) & 0xFF, 0x03, 0x00, 0x00, 0x00, device, 0x51, sense, asc, asq])
        self._send_command(CMD_COMMAND_END_RESPONSE, payload, completed=True)

    def _send_data_to_host(self, device: int, completed: bool, data: bytes, dma: bool = False) -> None:
        dmalen = 0 if dma else len(data)
        prefix = bytes(
            [
                0x00,
                len(data) & 0xFF,
                (len(data) >> 8) & 0xFF,
                0x00,
                0xB4 if dma else 0xB5,
                0x00,
                0x02,
                0x00,
                dmalen & 0xFF,
                (dmalen >> 8) & 0xFF,
                device,
                0x58,
            ]
        )
        if completed:
            suffix = bytes([0x85, 0x00, 0x03, 0x00, 0x00, 0x00, device, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        else:
            suffix = bytes(14)
        self._send_command(CMD_DATA_TO_HOST, prefix + suffix + data, completed=completed, dma=dma)

    def _send_get_data_from_host(self, device: int, chunk: int) -> None:
        payload = bytes([0x00, chunk & 0xFF, (chunk >> 8) & 0xFF, 0x00, 0xB5, 0x00, 0x00, 0x00, chunk & 0xFF, (chunk >> 8) & 0xFF, device, 0x58]) + bytes(11)
        self._send_command(CMD_GET_DATA_FROM_HOST, payload, completed=False)

    # -- inbound framing / dispatch ----------------------------------------

    def feed(self, data: bytes) -> None:
        """Feed newly received bytes. May process zero or more complete
        messages and raise :class:`ProtocolError` (tearing the session down)
        on an out-of-sequence or unrecognised inbound message.
        """
        if self._stopped:
            raise ProtocolError("IDE-R session already torn down; feed() called after teardown")
        self.bytes_from_amt += len(data)
        self._buf.extend(data)

        while len(self._buf) >= 8:
            length = self._peek_length()
            if length is None:
                return
            if len(self._buf) < length:
                return

            seq = struct.unpack_from("<I", self._buf, 4)[0]
            if seq != self._in_seq:
                self._stopped = True
                self._buf.clear()
                raise ProtocolError(f"IDE-R inbound sequence mismatch: expected {self._in_seq}, got {seq}; session torn down, no resync")
            self._in_seq = (self._in_seq + 1) & 0xFFFFFFFF

            message = bytes(self._buf[:length])
            del self._buf[:length]
            self._dispatch(message)
            if self._stopped:
                return

    def _peek_length(self) -> int | None:
        cmdid = self._buf[0]
        fixed = _FIXED_LENGTH_COMMANDS.get(cmdid)
        if fixed is not None:
            return fixed
        if cmdid == CMD_OPEN_SESSION_REPLY:
            if len(self._buf) < 30:
                return None
            return 30 + self._buf[29]
        if cmdid == CMD_DATA_FROM_HOST:
            if len(self._buf) < 14:
                return None
            length = struct.unpack_from("<H", self._buf, 9)[0]
            return 14 + length
        self._stopped = True
        self._buf.clear()
        raise ProtocolError(f"unknown inbound IDE-R command id {cmdid:#x}; session torn down")

    def _dispatch(self, message: bytes) -> None:
        cmdid = message[0]
        if cmdid == CMD_OPEN_SESSION_REPLY:
            self._on_open_session_reply(message)
        elif cmdid == CMD_CLOSE:
            self._stopped = True
        elif cmdid == CMD_KEEPALIVE_PING:
            self._send_command(CMD_KEEPALIVE_PONG)
        elif cmdid == CMD_KEEPALIVE_PONG:
            pass
        elif cmdid == CMD_RESET_OCCURRED:
            self._on_reset_occurred()
        elif cmdid == CMD_STATUS_DATA:
            self._on_status_data(message)
        elif cmdid == CMD_ERROR_OCCURRED:
            # "log; do not stop" -- docs/protocol-notes.md section 4.2.
            self.errors_seen.append(message[8])
        elif cmdid == CMD_HEARTBEAT:
            pass
        elif cmdid == CMD_COMMAND_WRITTEN:
            self._on_command_written(message)
        elif cmdid == CMD_DATA_FROM_HOST:
            self._on_data_from_host(message)

    # -- OPEN_SESSION_REPLY / feature toggle / status --------------------

    def _on_open_session_reply(self, message: bytes) -> None:
        info = _OpenSessionInfo(
            major=message[8],
            minor=message[9],
            fw_major=message[10],
            fw_minor=message[11],
            readbfr=struct.unpack_from("<H", message, 16)[0],
            writebfr=struct.unpack_from("<H", message, 18)[0],
            proto=message[21],
            iana=struct.unpack_from("<I", message, 25)[0],
        )
        if info.proto != 0 or info.readbfr > _MAX_READ_WRITE_BUFFER or info.writebfr > _MAX_READ_WRITE_BUFFER:
            self._stopped = True
            raise ProtocolError(f"OPEN_SESSION_REPLY failed validation: proto={info.proto}, readbfr={info.readbfr}, writebfr={info.writebfr}")
        self.session_info = info
        self.session_open = True
        self._send_disable_enable_features(3, struct.pack("<I", self._start_mode))

    def _on_status_data(self, message: bytes) -> None:
        status_type = message[8]
        value = struct.unpack_from("<I", message, 9)[0]
        if status_type == 1:  # REGS_AVAIL
            if value & 1:
                self._send_disable_enable_features(3, struct.pack("<I", self._start_mode))
        elif status_type == 2:  # REGS_STATUS
            self.enabled = bool(value & 2)
        elif status_type == 3:  # REGS_TOGGLE
            self.feature_toggle_ok = value == 1

    def _on_reset_occurred(self) -> None:
        if self._read_state is None:
            self._send_command(CMD_RESET_OCCURRED_RESPONSE)
        else:
            self._reset_pending = True

    # -- COMMAND_WRITTEN / SCSI dispatch -----------------------------------

    def _on_command_written(self, message: bytes) -> None:
        device_flags = message[14]
        device = DEVICE_CDROM if device_flags & 0x10 else DEVICE_FLOPPY
        feature_register = message[9]
        cdb = message[16:28]
        self._handle_scsi(device, cdb, feature_register, device_flags)

    def _handle_scsi(self, device: int, cdb: bytes, feature_register: int, device_flags: int) -> None:
        dma = bool(feature_register & 1)
        image = self._devices.get(device)
        op = cdb[0]

        if op == 0x00:  # TEST_UNIT_READY
            self._scsi_test_unit_ready(device, image)
        elif op == 0x08:  # READ_6
            lba = ((cdb[1] & 0x1F) << 16) | (cdb[2] << 8) | cdb[3]
            length = cdb[4] or 256
            self._scsi_read(device, image, lba, length, dma)
        elif op == 0x0A:  # WRITE_6
            lba = ((cdb[1] & 0x1F) << 16) | (cdb[2] << 8) | cdb[3]
            length = cdb[4] or 256
            self._scsi_write_request(device, image, lba, length)
        elif op == 0x1A:  # MODE_SENSE_6
            self._scsi_mode_sense_6(device, image, cdb, dma)
        elif op == 0x1B:  # START_STOP
            self._send_command_end_response(True, 0, device)
        elif op == 0x1E:  # ALLOW_MEDIUM_REMOVAL
            if image is None:
                self._send_command_end_response(True, 0x02, device, 0x3A, 0x00)
            else:
                self._send_command_end_response(True, 0x00, device, 0x00, 0x00)
        elif op == 0x23:  # READ_FORMAT_CAPACITIES
            self._scsi_read_format_capacities(device, image, dma)
        elif op == 0x25:  # READ_CAPACITY
            self._scsi_read_capacity(device, image, device_flags, dma)
        elif op == 0x28:  # READ_10
            lba = struct.unpack_from(">I", cdb, 2)[0]
            length = struct.unpack_from(">H", cdb, 7)[0]
            self._scsi_read(device, image, lba, length, dma)
        elif op in (0x2A, 0x2E):  # WRITE_10, WRITE_AND_VERIFY
            lba = struct.unpack_from(">I", cdb, 2)[0]
            length = struct.unpack_from(">H", cdb, 7)[0]
            self._scsi_write_request(device, image, lba, length)
        elif op == 0x43:  # READ_TOC
            self._scsi_read_toc(device, cdb, dma)
        elif op == 0x46:  # GET_CONFIGURATION
            self._scsi_get_configuration(device, cdb, dma)
        elif op == 0x4A:  # GET_EVENT_STATUS_NOTIFICATION
            self._scsi_get_event_status(device, image, cdb, dma)
        elif op == 0x51:  # READ_DISC_INFO -- "not implemented" is accepted by BIOSes
            self._send_command_end_response(False, 0x05, device, 0x20, 0x00)
        elif op == 0x55:  # MODE_SELECT_10
            self._send_command_end_response(True, 0x05, device, 0x20, 0x00)
        elif op == 0x5A:  # MODE_SENSE_10
            self._scsi_mode_sense_10(device, image, cdb, dma)
        elif op == 0xAC:  # GET_PERFORMANCE
            self._send_data_to_host(device, True, _GET_PERFORMANCE_REPLY, dma)
        else:
            self._send_command_end_response(False, 0x05, device, 0x20, 0x00)

    # -- individual SCSI command handlers --------------------------------

    def _scsi_test_unit_ready(self, device: int, image: MediaImage | None) -> None:
        if image is None:
            self._send_command_end_response(True, 0x02, device, 0x3A, 0x00)
            return
        if not image.media_change_reported:
            image.media_change_reported = True
            self._send_command_end_response(True, 0x06, device, 0x28, 0x00)
            return
        self._send_command_end_response(True, 0x00, device, 0x00, 0x00)

    def _scsi_mode_sense_6(self, device: int, image: MediaImage | None, cdb: bytes, dma: bool) -> None:
        if cdb[2] == 0x3F and cdb[3] == 0x00:
            if image is None:
                self._send_command_end_response(True, 0x02, device, 0x3A, 0x00)
                return
            a = 0x00 if device == DEVICE_FLOPPY else 0x05
            b = 0x00 if image.writable else 0x80
            self._send_data_to_host(device, True, bytes([0, a, b, 0]), dma)
            return
        self._send_command_end_response(True, 0x05, device, 0x24, 0x00)

    def _scsi_read_format_capacities(self, device: int, image: MediaImage | None, dma: bool) -> None:
        if image is None or image.size == 0:
            self._send_command_end_response(False, 0x05, device, 0x24, 0x00)
            return
        # NB: the reference computes the real sector count here and then
        # never uses it -- the reply is a fixed canned descriptor regardless
        # of actual media size. Preserved verbatim; see module docstring.
        payload = struct.pack(">I", 8) + bytes([0x00, 0x00, 0x0B, 0x40, 0x02, 0x00, 0x02, 0x00])
        self._send_data_to_host(device, True, payload, dma)

    def _scsi_read_capacity(self, device: int, image: MediaImage | None, device_flags: int, dma: bool) -> None:
        if image is None or image.size == 0:
            self._send_command_end_response(False, 0x02, device, 0x3A, 0x00)
            return
        blocks_minus_one = image.blocks - 1
        blocksize_hi = 0x08 if device == DEVICE_CDROM else 0x02
        payload = struct.pack(">I", blocks_minus_one) + bytes([0x00, 0x00, blocksize_hi, 0x00])
        # Spec-mandated quirk: reply carries deviceFlags, not the normalised
        # device code, in this one command.
        self._send_data_to_host(device_flags, True, payload, dma)

    def _scsi_read_toc(self, device: int, cdb: bytes, dma: bool) -> None:
        if device != DEVICE_CDROM:
            self._send_command_end_response(True, 0x05, device, 0x20, 0x00)
            return
        msf = cdb[1] & 0x02
        fmt = cdb[2] & 0x07
        if fmt == 0:
            fmt = cdb[9] >> 6
        if fmt == 1:
            self._send_data_to_host(device, True, bytes([0x00, 0x0A, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), dma)
        elif fmt == 0:
            if msf:
                toc = bytes([0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0xAA, 0x00, 0x00, 0x00, 0x34, 0x13])
            else:
                toc = bytes([0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00])
            self._send_data_to_host(device, True, toc, dma)
        # else: no reply at all for other formats -- matches the reference,
        # which also leaves these unanswered. Rare enough in practice
        # (R-W subchannel TOC formats) that no BIOS observed relies on it.

    def _scsi_get_configuration(self, device: int, cdb: bytes, dma: bool) -> None:
        sendall = cdb[1] != 2
        firstcode = struct.unpack_from(">H", cdb, 2)[0]
        buflen = struct.unpack_from(">H", cdb, 7)[0]
        if buflen == 0:
            self._send_data_to_host(device, True, struct.pack(">II", 0x003C, 0x0008), dma)
            return

        # Deliberately a cascade of independent ifs, not elif/switch: this
        # reproduces amt-ider-module.js's overwrite-as-you-go selection
        # exactly, including that "send all descriptors" (sendall=True)
        # degenerates to "send only the last matching one". That looks like
        # a bug, but it is the reference's real, firmware-exercised
        # behaviour and is preserved rather than corrected.
        r: bytes | None = None
        if firstcode == 0x0:
            r = _CD_CONFIG_PROFILE_LIST
        if firstcode == 0x1 or (sendall and firstcode < 0x1):
            r = _CD_CONFIG_CORE
        if firstcode == 0x2 or (sendall and firstcode < 0x2):
            r = _CD_CONFIG_MORPHING
        if firstcode == 0x3 or (sendall and firstcode < 0x3):
            r = _CD_CONFIG_REMOVABLE
        if firstcode == 0x10 or (sendall and firstcode < 0x10):
            r = _CD_CONFIG_RANDOM
        if firstcode == 0x1E or (sendall and firstcode < 0x1E):
            r = _CD_CONFIG_READ
        if firstcode == 0x100 or (sendall and firstcode < 0x100):
            r = _CD_CONFIG_POWER
        if firstcode == 0x105 or (sendall and firstcode < 0x105):
            r = _CD_CONFIG_TIMEOUT

        body = struct.pack(">II", 0x0008, 4) if r is None else struct.pack(">II", 0x0008, len(r) + 4) + r
        if len(body) > buflen:
            body = body[:buflen]
        self._send_data_to_host(device, True, body, dma)

    def _scsi_get_event_status(self, device: int, image: MediaImage | None, cdb: bytes, dma: bool) -> None:
        if cdb[1] != 0x01 and cdb[4] != 0x10:
            self._send_command_end_response(True, 0x05, device, 0x26, 0x01)
            return
        present = 0x02 if image is not None else 0x00
        self._send_data_to_host(device, True, bytes([0x00, present, 0x80, 0x00]), dma)

    def _scsi_mode_sense_10(self, device: int, image: MediaImage | None, cdb: bytes, dma: bool) -> None:
        buflen = struct.unpack_from(">H", cdb, 7)[0]
        if buflen == 0:
            self._send_data_to_host(device, True, struct.pack(">II", 0x003C, 0x0008), dma)
            return

        sector_count = image.blocks if image is not None else 0
        page = cdb[2] & 0x3F
        r: bytes | None = None
        if page == 0x01:
            if device == DEVICE_FLOPPY:
                r = _MS_FLOPPY_ERROR_RECOVERY if sector_count <= 0xB40 else _MS_LS120_ERROR_RECOVERY
            else:
                r = _MS_CD_ERROR_RECOVERY
        elif page == 0x05:
            if device == DEVICE_FLOPPY:
                r = _MS_FLOPPY_DISK_PAGE if sector_count <= 0xB40 else _MS_LS120_DISK_PAGE
        elif page == 0x3F:
            if device == DEVICE_FLOPPY:
                r = _MS_3F_FLOPPY if sector_count <= 0xB40 else _MS_3F_LS120
            else:
                r = _MS_3F_CD
        elif page == 0x1A and device == DEVICE_CDROM:
            r = _MS_CD_1A
        elif page == 0x1D and device == DEVICE_CDROM:
            r = _MS_CD_1D
        elif page == 0x2A and device == DEVICE_CDROM:
            r = _MS_CD_2A

        if r is None:
            self._send_command_end_response(False, 0x05, device, 0x20, 0x00)
            return

        writable = image.writable if image is not None else False
        self._send_data_to_host(device, True, _mode_sense_10_page(r, writable=writable), dma)

    # -- read path: state machine, backpressure, reset handling ----------

    def _scsi_read(self, device: int, image: MediaImage | None, lba: int, length: int, dma: bool) -> None:
        if image is None:
            self._send_command_end_response(True, 0x02, device, 0x3A, 0x00)
            return
        if length < 0 or lba + length > image.blocks:
            self._send_command_end_response(True, 0x05, device, 0x21, 0x00)
            return
        if length == 0:
            self._send_command_end_response(True, 0x00, device, 0x00, 0x00)
            return

        byte_offset = lba << image.sector_shift
        byte_len = length << image.sector_shift
        request = _ReadRequest(device=device, image=image, byte_offset=byte_offset, remaining=byte_len, dma=dma)

        if self._read_state is not None:
            self._read_queue.append(request)
            return
        self._read_state = request
        self._pump_read()

    def _pump_read(self) -> None:
        """Drain the current read (and, once it finishes, whatever is queued
        behind it) into successive DATA_TO_HOST frames.

        Explicit state machine, not recursion/callbacks: each iteration sends
        exactly one frame sized to the negotiated ``readbfr``, then decides
        whether to continue the same read, hand off to RESET_OCCURRED, or
        start the next queued read. Local file reads are synchronous, so
        there is no callback boundary to model here the way the JS reference
        does with ``fs.read``.
        """
        readbfr = self.session_info.readbfr or None
        while self._read_state is not None:
            state = self._read_state
            chunk_size = min(state.remaining, readbfr) if readbfr else state.remaining
            data = state.image.read(state.byte_offset, chunk_size)
            state.byte_offset += len(data)
            state.remaining -= len(data)
            completed = state.remaining <= 0
            self._send_data_to_host(state.device, completed, data, state.dma)

            if state.remaining > 0 and not self._reset_pending:
                continue  # more chunks remain for this read; keep draining it

            self._read_state = None
            if self._reset_pending:
                self._send_command(CMD_RESET_OCCURRED_RESPONSE)
                self._read_queue.clear()
                self._reset_pending = False
                return
            if self._read_queue:
                self._read_state = self._read_queue.pop(0)
        # Queue and in-flight read both empty: nothing left to drain.

    # -- write path --------------------------------------------------------

    def _scsi_write_request(self, device: int, image: MediaImage | None, lba: int, length: int) -> None:
        if device != DEVICE_FLOPPY or image is None:
            # CD/DVD never accepts writes regardless of what is attached --
            # guarded on device code, not on the image's writable flag, so a
            # write CDB aimed at 0xB0 cannot reach a floppy's write path even
            # by accident.
            self._send_command_end_response(True, 0x02, device, 0x3A, 0x00)
            return
        if length < 0 or lba + length > image.blocks:
            self._send_command_end_response(True, 0x05, device, 0x21, 0x00)
            return
        if length == 0:
            self._send_command_end_response(True, 0x00, device, 0x00, 0x00)
            return
        if not image.writable:
            # Write-protected, not "no medium" -- misleading sense codes are
            # exactly what docs/protocol-notes.md section 5.2.4 forbids here.
            self._send_command_end_response(False, 0x07, device, 0x27, 0x00)
            return

        self._pending_write = _PendingWrite(device=device, image=image, byte_offset=lba << 9, expected_length=512 * length)
        self._send_get_data_from_host(device, 512 * length)

    def _on_data_from_host(self, message: bytes) -> None:
        length = struct.unpack_from("<H", message, 9)[0]
        data = message[14 : 14 + length]

        pending = self._pending_write
        if pending is None:
            # Firmware sent a write payload we never asked for. Answer with a
            # generic illegal-request sense rather than crashing; there is no
            # device context to attribute this to.
            self._send_command_end_response(False, 0x05, DEVICE_FLOPPY, 0x20, 0x00)
            return

        # Bound the payload against what the WRITE CDB actually asked for.
        # _scsi_write_request validated the *declared* length against the image
        # size, but the bytes arrive separately and in arbitrarily many frames.
        # Without this check a host could declare a one-sector write (passing
        # the bounds check) and then stream frames indefinitely, each written at
        # an advancing offset, walking past the end of the image and extending
        # the backing file. Refuse the overrun rather than truncating it: the
        # host has violated its own declared transfer length, so the session has
        # lost sync and the pending write must not be trusted to complete.
        remaining = pending.expected_length - pending.received
        if len(data) > remaining:
            self._pending_write = None
            # Sense form (error=False), not the error form: the error shape
            # discards sense/asc/asq on the wire, and this is a new code path
            # with no reference precedent -- the Apache-2.0 implementation this
            # engine derives from does not implement writes at all -- so telling
            # the host the actual reason (illegal LBA) is strictly better.
            self._send_command_end_response(False, 0x05, pending.device, 0x21, 0x00)
            return

        pending.image.write(pending.byte_offset + pending.received, data)
        pending.received += len(data)
        if pending.received >= pending.expected_length:
            self._pending_write = None
            self._send_command_end_response(False, 0x00, pending.device, 0x00, 0x00)

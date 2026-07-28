# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Standalone runner: start a :class:`ider_server.IderMockServer`, then drive one
scripted SCSI exchange against whatever client connects to it, and report the outcome.

Used only by the ``amt_media`` integration test target. Unlike ``run_wsman_mock.py``,
this cannot simply sit and answer requests: :class:`ider_server.IderMockServer` plays
*firmware*, which means it is the one that must actively issue SCSI commands
(``issue_scsi``) and, for a write, push the payload back (``send_data_from_host``) --
see that module's docstring. Something has to call those methods against the live
connection once ``amt_media`` (running as a detached background process of its own,
started by a separate Ansible task) has connected and completed the IDE-R handshake.
That "something" is this script's own main thread, blocking on
``wait_for_handshake()`` and then running the fixed sequence below -- there is no
other process in this test that holds a reference to the live ``IderMockServer``
instance and could drive it instead.

The read/write outcome is written into the same ready file the connection info came
from (``handshake``, ``read_ok``, ``write_ok``, ``error``), which the calling playbook
polls for. The exact write payload is supplied by the caller (``--write-payload-b64``),
never invented here, so the playbook's later assertion that the payload landed in the
backing image file on disk is checking a value it already knew, not trusting this
script's self-report.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import struct
import sys
from pathlib import Path

DEVICE_FLOPPY = 0xA0
DEVICE_CDROM = 0xB0
_DEVICE_BY_NAME = {"floppy": DEVICE_FLOPPY, "cdrom": DEVICE_CDROM}

READ_10 = 0x28
WRITE_10 = 0x2A


def _cdb10(op: int, lba: int, length: int) -> bytes:
    """A 12-byte COMMAND_WRITTEN CDB slot carrying a 10-byte READ_10/WRITE_10 SCSI CDB.

    Byte-for-byte the same shape as ``tests/unit/plugins/module_utils/test_ider.py``'s
    ``cdb10()`` helper (docs/protocol-notes.md s4.5): ``op``, a reserved byte, the LBA as
    big-endian uint32, another reserved byte, the transfer length as big-endian uint16,
    then 3 padding bytes -- 1+1+4+1+2+3 = 12.
    """
    return bytes([op, 0x00]) + struct.pack(">I", lba) + bytes([0x00]) + struct.pack(">H", length) + bytes(3)


def _write_json_atomic(path: str, data: dict) -> None:
    target = Path(path)
    tmp = target.with_name(f"{target.name}.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, target)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock-servers-dir", required=True, help="Directory containing ider_server.py")
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--use-tls", action="store_true")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="test-password-not-real")  # fixture default, not a real credential
    parser.add_argument("--readbfr", type=int, default=1024)
    parser.add_argument("--writebfr", type=int, default=1024)
    parser.add_argument("--handshake-timeout", type=float, default=20.0)
    parser.add_argument("--action-timeout", type=float, default=10.0)
    parser.add_argument("--read-device", choices=sorted(_DEVICE_BY_NAME), default=None, help="If set, TEST_UNIT_READY + READ_10 this device once connected")
    parser.add_argument("--read-lba", type=int, default=0)
    parser.add_argument("--read-sectors", type=int, default=1)
    parser.add_argument("--write-payload-b64", default=None, help="If set, WRITE_10 this payload (base64) to the floppy device once connected")
    parser.add_argument("--write-lba", type=int, default=0)
    parser.add_argument("--write-frame-size", type=int, default=0, help="0 means one single DATA_FROM_HOST frame carrying the whole payload")
    return parser.parse_args()


def _drive_read(server, info: dict, args: argparse.Namespace) -> None:
    device = _DEVICE_BY_NAME[args.read_device]
    try:
        server.issue_scsi(bytes(12), device=device)  # TEST_UNIT_READY (opcode 0x00)
        server.next_event(timeout=args.action_timeout)  # drain the CommandEndResponse; a real BIOS ignores it too.
        sector_bytes = 2048 if device == DEVICE_CDROM else 512
        server.issue_scsi(_cdb10(READ_10, args.read_lba, args.read_sectors), device=device)
        data, completed_flags = server.read_data_to_host_stream(timeout=args.action_timeout)
        info["read_ok"] = bool(completed_flags) and completed_flags[-1] is True
        info["read_bytes_len"] = len(data)
        info["read_bytes_expected_len"] = args.read_sectors * sector_bytes
    except Exception as exc:
        info["read_ok"] = False
        info["error"] = f"read drive sequence failed: {exc}"


def _drive_write(server, info: dict, args: argparse.Namespace) -> None:
    payload = base64.b64decode(args.write_payload_b64)
    sectors = (len(payload) + 511) // 512
    try:
        server.issue_scsi(_cdb10(WRITE_10, args.write_lba, sectors), device=DEVICE_FLOPPY)
        get_data_request = server.next_event(timeout=args.action_timeout)
        info["write_requested_chunk"] = getattr(get_data_request, "chunk", None)
        frame_size = args.write_frame_size or len(payload)
        server.send_data_from_host(payload, frame_size=frame_size)
        end_response = server.next_event(timeout=args.action_timeout)
        info["write_ok"] = getattr(end_response, "error", None) is False and getattr(end_response, "sense", None) == 0
    except Exception as exc:
        info["write_ok"] = False
        info["error"] = f"write drive sequence failed: {exc}"


def main() -> None:
    args = _parse_args()
    sys.path.insert(0, args.mock_servers_dir)
    from ider_server import IderMockServer  # local import: only resolvable after the sys.path insert above

    server = IderMockServer(
        username=args.username,
        password=args.password,
        use_tls=args.use_tls,
        readbfr=args.readbfr,
        writebfr=args.writebfr,
    ).start()

    info = {
        "pid": os.getpid(),
        "port": server.port,
        "cert_fingerprint": server.cert_fingerprint,
        "handshake": False,
        "read_ok": None,
        "write_ok": None,
        "error": None,
    }
    _write_json_atomic(args.ready_file, info)

    try:
        server.wait_for_handshake(timeout=args.handshake_timeout)
        info["handshake"] = True
        _write_json_atomic(args.ready_file, info)

        if args.read_device:
            _drive_read(server, info, args)
        if args.write_payload_b64:
            _drive_write(server, info, args)
    except Exception as exc:
        info["error"] = f"handshake failed: {exc}"
    finally:
        _write_json_atomic(args.ready_file, info)

    _idle_until_sigterm()
    server.stop()


def _idle_until_sigterm() -> None:
    state = {"stop": False}

    def _handle_sigterm(_signum: int, _frame: object) -> None:
        state["stop"] = True

    signal.signal(signal.SIGTERM, _handle_sigterm)
    while not state["stop"]:
        signal.pause()


if __name__ == "__main__":
    main()

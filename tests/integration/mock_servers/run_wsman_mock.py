# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Standalone runner: start a :class:`wsman_server.WsmanMockServer`, report its
connection info, then idle until asked to stop.

Used only by ``tests/integration/targets/*`` playbooks (started as a detached background
process from a task, via ``nohup ... & echo $!``) to drive the real modules against a
deterministic fixture over an actual TCP connection -- the whole reason for a *mock
integration* tier rather than only mocked-object unit tests. Never imported by
collection code and never shipped in the built collection artifact (see
``galaxy.yml``'s ``build_ignore``).

There is still no fault-injection *control channel*: nothing here lets a task reach
into an already-running mock and flip a switch. Most scenarios the integration
targets exercise (idempotent state reported by repeated calls, the read-only-field
Put rejection, an authentication failure) are reachable through the mock's *normal*,
stateful behaviour -- a wrong password fails digest auth on the very first request,
`AmtState` is mutated for real by `Put`/method calls and observed by a later `Get`
within the same running instance, and `reject_boot_readonly_fields` defaults to `True`
already.

Some firmware *variations* cannot be reached that way, because they are properties of
the endpoint rather than of anything a client does to it: a firmware that has no
`AMT_EthernetPortSettings` instance 0 at all, one whose `CIM_BIOSElement` refuses a
bare `Get` so only `Enumerate` answers, and one with no `AMT_MessageLog` class at all.
`--empty-message-log` is here for the same reason even though it is state rather than
capability: an event log is emptied by `ClearLog`, so a server that starts empty is the
only way to read an empty log *without* first destroying the records another assertion
in the same target needs. `--amt10-no-enumerate` is the same kind of thing one level up:
it selects a firmware *generation* rather than one class's behaviour, making `Enumerate`
HTTP 400 on `AMT_`-prefixed classes the way AMT 10.0.56 does. The hardware-inventory
flags (`--no-hardware-inventory`, `--no-storage-class`, `--hardware-get-faults`,
`--memory-dimm-count`, `--storage-device-count`) are the same kind of thing: which
`CIM_` asset classes a firmware implements, how many DIMMs and disks are physically
fitted, and whether a bare `Get` answers for the two singletons are all properties of
the endpoint. `--no-storage-class` exists specifically to prove the fact groups degrade
*independently* -- a firmware AMT cannot enumerate disks on must still report its DIMMs
and its serial number, and a single all-or-nothing flag could not tell that apart from
a client that gives up on the first fault. `--baseboard-serial` is one level narrower
again -- not which classes a firmware implements but whether it fills in one property of
one class, and if not, whether it omits the element or sends it empty. Those two are
indistinguishable in the parsed facts and are what issue #84 turns on, so both are
served here rather than reasoned about. `--message-log-empty-slots` is state again rather
than capability, and belongs here for the same reason `--empty-message-log` does, only
more so: it is a log that a `ClearLog` freed slots in and that has only partially
refilled, and *no* sequence of requests against this mock can produce it, because
`ClearLog` here empties the records and the counter together the way firmware's does. The
defining property of the state is that `CurrentNumberOfRecords` and the `GetRecords` array
disagree, and only a server that starts that way can have it. Real firmware does: issue
#105. All are start-up flags
rather than a control channel -- a
target that needs them starts a second mock process configured that way, which keeps
every running server's behaviour fixed for its whole lifetime and therefore keeps a
failure attributable to one endpoint's configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from pathlib import Path


def _write_json_atomic(path: str, data: dict) -> None:
    target = Path(path)
    tmp = target.with_name(f"{target.name}.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, target)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock-servers-dir", required=True, help="Directory containing wsman_server.py")
    parser.add_argument("--ready-file", required=True, help="Path this script writes {pid, port, cert_fingerprint} to once listening")
    parser.add_argument("--use-tls", action="store_true")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="test-password-not-real")  # fixture default, not a real credential
    parser.add_argument("--page-size", type=int, default=2)
    parser.add_argument(
        "--no-ethernet-port",
        action="store_true",
        help="Fault Get AMT_EthernetPortSettings, standing in for firmware with no instance 0",
    )
    parser.add_argument(
        "--bios-get-faults",
        action="store_true",
        help="Fault a bare Get CIM_BIOSElement, leaving only the Enumerate path",
    )
    parser.add_argument(
        "--no-message-log",
        action="store_true",
        help="Fault both Get and Enumerate of AMT_MessageLog, standing in for firmware with no event log",
    )
    parser.add_argument(
        "--empty-message-log",
        action="store_true",
        help="Serve an AMT_MessageLog that exists but holds no records (PositionToFirstRecord returns 2)",
    )
    parser.add_argument(
        "--message-log-empty-slots",
        type=int,
        default=0,
        help=(
            "Pad the GetRecords response with N zero-filled empty record slots after the "
            "real records, WITHOUT counting them in CurrentNumberOfRecords -- the state "
            "real firmware serves after a ClearLog has freed slots the log has not refilled "
            "yet (issue #105)"
        ),
    )
    parser.add_argument(
        "--amt10-no-enumerate",
        action="store_true",
        help=(
            "Answer HTTP 400 to Enumerate on AMT_-prefixed classes, standing in for AMT 10-era "
            "firmware which offers selective instance access only (docs/protocol-notes.md 2.7). "
            "AMT_MessageLog is exempt -- its Enumerate is directly evidenced."
        ),
    )
    parser.add_argument(
        "--no-hardware-inventory",
        action="store_true",
        help=(
            "Fault Get and Enumerate for all six hardware inventory classes (CIM_Chassis, "
            "CIM_Card, CIM_Processor, CIM_Chip, CIM_PhysicalMemory, CIM_MediaAccessDevice), "
            "standing in for firmware that implements none of them"
        ),
    )
    parser.add_argument(
        "--no-storage-class",
        action="store_true",
        help=(
            "Fault only CIM_MediaAccessDevice, leaving the other five. Proves each fact group "
            "degrades independently -- a machine AMT cannot enumerate disks on must still report "
            "its DIMMs and its serial number"
        ),
    )
    parser.add_argument(
        "--hardware-get-faults",
        action="store_true",
        help=(
            "Fault a bare Get of CIM_Chassis and CIM_Card, leaving only the Enumerate path. Both "
            "verbs are evidenced by the vendor fixture set, so the client's fallback has to be "
            "exercised over a real socket"
        ),
    )
    parser.add_argument(
        "--memory-dimm-count",
        type=int,
        default=2,
        help="How many CIM_PhysicalMemory instances to serve. 0 is a legitimate reading, not a fault",
    )
    parser.add_argument(
        "--storage-device-count",
        type=int,
        default=2,
        help="How many CIM_MediaAccessDevice instances to serve",
    )
    parser.add_argument(
        "--baseboard-serial",
        choices=("populated", "empty", "absent"),
        default="populated",
        help=(
            "How CIM_Card reports SerialNumber: populated, present-but-empty, or the element "
            "omitted entirely. The last two both render amt.hardware.baseboard.serial_number "
            "null, which is exactly why issue #84 needed a per-property shape census to tell "
            "them apart -- so both have to be servable over a real socket rather than only "
            "asserted against a parser a unit test mocked away"
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sys.path.insert(0, args.mock_servers_dir)
    from wsman_server import WsmanMockServer  # local import: only resolvable after the sys.path insert above

    server = WsmanMockServer(
        username=args.username,
        password=args.password,
        use_tls=args.use_tls,
        page_size=args.page_size,
    )
    # Set before start(): these describe what this endpoint *is*, so they must
    # hold for its whole lifetime rather than changing under a running client.
    server.state.ethernet_port_present = not args.no_ethernet_port
    server.faults.bios_element_get_faults = args.bios_get_faults
    server.state.message_log_present = not args.no_message_log
    # Which firmware *generation* this endpoint is, so it must hold for the whole
    # lifetime: a server that changed verbs under a running client would make a failure
    # unattributable.
    server.faults.enumerate_faults_for_amt_classes = args.amt10_no_enumerate
    # Also endpoint properties rather than client-visible state: which hardware
    # classes a firmware implements, how many DIMMs and disks are physically
    # fitted, and whether a bare Get answers for the two singletons. None of these
    # changes under a running client, so all are start-up flags.
    if args.no_hardware_inventory:
        server.state.chassis_present = False
        server.state.card_present = False
        server.state.processor_present = False
        server.state.chip_present = False
        server.state.physical_memory_present = False
        server.state.media_access_present = False
    if args.no_storage_class:
        server.state.media_access_present = False
    server.faults.hardware_get_faults = args.hardware_get_faults
    server.state.memory_dimm_count = args.memory_dimm_count
    server.state.storage_device_count = args.storage_device_count
    # Whether this firmware fills in CIM_Card.SerialNumber, and if not, how it says
    # so. `None` omits the element; `""` emits it empty. Both lab machines are one
    # of these two and nothing published so far can say which -- see the flag's help
    # and AmtState.baseboard_serial_number.
    if args.baseboard_serial == "empty":
        server.state.baseboard_serial_number = ""
    elif args.baseboard_serial == "absent":
        server.state.baseboard_serial_number = None
    # How many freed-but-not-yet-refilled record slots this firmware's GetRecords pads
    # its response with. State rather than capability, and not reachable by anything a
    # client does: ClearLog through this mock empties both the records and (as real
    # firmware's counter does) the count, so no sequence of requests against a
    # default server can produce a counter and an array that disagree. It has to be
    # how the endpoint starts.
    server.state.message_log_empty_slots = args.message_log_empty_slots
    if args.empty_message_log:
        # An event log that exists but is empty. Distinct from --no-message-log:
        # "the class is absent" is an unsupported_capability, while "the log holds
        # nothing" is an ordinary successful read of zero records, and a client that
        # conflates them reports a firmware gap where there is only a quiet machine.
        server.state.message_log_records.clear()
    server.start()

    _write_json_atomic(
        args.ready_file,
        {"pid": os.getpid(), "port": server.port, "cert_fingerprint": server.cert_fingerprint},
    )

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

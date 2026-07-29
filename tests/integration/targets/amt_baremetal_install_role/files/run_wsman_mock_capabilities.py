# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Start a mock WS-Man server that advertises a *missing* boot capability, then hand
over to the shared runner unchanged.

``roles/amt_baremetal_install/tasks/probe.yml`` runs ``amt_info`` before it mutates
anything and refuses to arm a boot selection the firmware does not advertise support
for (``AMT_BootCapabilities.IDER`` for the ``ider_cdrom`` provider,
``ForcePXEBoot`` for ``pxe``). That refusal is unreachable against an endpoint that
always answers "supported", so it needs an endpoint that answers "not supported".

The shared runner ``tests/integration/mock_servers/run_wsman_mock.py`` has a start-up
flag for every *other* firmware variation an integration target has needed so far
(``--no-ethernet-port``, ``--bios-get-faults``, ``--no-message-log``,
``--empty-message-log``) but none for an absent boot capability:
``wsman_server._get_boot_capabilities()`` returns a fixed dictionary and ignores
``AmtState`` entirely, so there is no state to set and no fault to inject. Adding such
a flag belongs in ``tests/integration/mock_servers/``, which this change does not own.
This wrapper therefore overrides that single function before the server starts and then
delegates to the shared runner rather than forking a copy of it.

The override is checked against the real function *up front*, in this process, and this
script exits non-zero if the shape it depends on has moved. A silently ineffective
patch would leave the preflight assertions passing against a fully capable endpoint --
precisely the "test that cannot fail" the target using this script exists to avoid.
``tasks/main.yml`` additionally confirms with a direct ``amt_info`` read that this
endpoint really does report the capability absent before it relies on that.
"""

from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path

#: CLI flag -> the AMT_BootCapabilities field it forces to false.
CAPABILITY_FLAGS = {
    "no_ider": "IDER",
    "no_force_pxe": "ForcePXEBoot",
}


def _parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description=__doc__)
    # Consumed here *and* passed through: the shared runner needs it too.
    parser.add_argument("--mock-servers-dir", required=True, help="Directory containing wsman_server.py")
    parser.add_argument("--no-ider", action="store_true", help="Advertise AMT_BootCapabilities.IDER as false")
    parser.add_argument("--no-force-pxe", action="store_true", help="Advertise AMT_BootCapabilities.ForcePXEBoot as false")
    return parser.parse_known_args()


def main() -> None:
    args, passthrough = _parse_args()

    absent = [field for flag, field in CAPABILITY_FLAGS.items() if getattr(args, flag)]
    if not absent:
        sys.exit("run_wsman_mock_capabilities.py: pass at least one of --no-ider / --no-force-pxe, or use run_wsman_mock.py directly")

    sys.path.insert(0, args.mock_servers_dir)
    import wsman_server  # local import: only resolvable after the sys.path insert above

    original = getattr(wsman_server, "_get_boot_capabilities", None)
    if original is None:
        sys.exit("run_wsman_mock_capabilities.py: wsman_server._get_boot_capabilities is gone; this wrapper needs updating")

    # Both verbs must end up patched. GET_HANDLERS holds a direct reference to the
    # original function object, so reassigning the module attribute alone would leave
    # Get answering "supported" while Enumerate answered "not supported".
    # _boot_capabilities_items() looks the module attribute up at call time, so the
    # Enumerate path follows the reassignment.
    if wsman_server.GET_HANDLERS.get(wsman_server.AMT_BOOT_CAPABILITIES) is not original:
        sys.exit("run_wsman_mock_capabilities.py: GET_HANDLERS no longer maps AMT_BootCapabilities to _get_boot_capabilities; this wrapper needs updating")
    if wsman_server.ENUMERATE_HANDLERS.get(wsman_server.AMT_BOOT_CAPABILITIES) is None:
        sys.exit("run_wsman_mock_capabilities.py: AMT_BootCapabilities is no longer served via Enumerate; this wrapper needs updating")

    baseline = original(wsman_server.AmtState())
    for field in absent:
        if baseline.get(field) is not True:
            sys.exit(f"run_wsman_mock_capabilities.py: the unpatched mock does not advertise {field}=True, so forcing it false proves nothing")

    def patched(state: object) -> dict:
        fields = dict(original(state))
        fields.update(dict.fromkeys(absent, False))
        return fields

    # Reaching into a private name is the point here; see the module docstring for why
    # this is a wrapper rather than a flag on the shared runner.
    wsman_server._get_boot_capabilities = patched
    wsman_server.GET_HANDLERS[wsman_server.AMT_BOOT_CAPABILITIES] = patched

    shared_runner = str(Path(args.mock_servers_dir) / "run_wsman_mock.py")
    sys.argv = [shared_runner, "--mock-servers-dir", args.mock_servers_dir, *passthrough]
    runpy.run_path(shared_runner, run_name="__main__")


if __name__ == "__main__":
    main()

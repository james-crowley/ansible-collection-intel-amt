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

No fault-injection control channel is needed here: every scenario the integration
targets exercise (idempotent state reported by repeated calls, the read-only-field
Put rejection, and an authentication failure) is already reachable through the mock's
*normal*, stateful behaviour -- a wrong password fails digest auth on the very first
request, `AmtState` is mutated for real by `Put`/method calls and observed by a later
`Get` within the same running instance, and `reject_boot_readonly_fields` defaults to
`True` already. There was therefore no need to build a way for a task to reach into a
already-running mock and flip a fault switch.
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
    ).start()

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

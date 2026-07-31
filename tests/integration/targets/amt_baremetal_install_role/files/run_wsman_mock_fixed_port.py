# No shebang, and mode 0644, matching tests/integration/mock_servers/run_wsman_mock.py.
# ansible-test's `shebang` sanity test requires that any file carrying a shebang be
# executable; this one is invoked as `python3 <path>` by the target, never directly.
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Start a mock WS-Man server bound to a caller-chosen *fixed* port, then serve exactly
like the shared runner -- everything except the bind call is delegated to
``wsman_server.WsmanMockServer``.

Every other mock in this target binds an ephemeral port
(``tests/integration/mock_servers/run_wsman_mock.py``, and this target's own
``run_wsman_mock_capabilities.py``), because ordinarily nothing needs a *specific* port.
Scenario 18 (see ``tasks/main.yml``) is the one exception: it exists to prove that an
unset ``amt_baremetal_install_port``/``amt_baremetal_install_media_port`` falls through
to the module's own default port (module_utils/tls.py's ``DEFAULT_PLAINTEXT_PORT`` /
``DEFAULT_TLS_PORT``, currently 16992/16993) rather than reaching amt_info/amt_media as
the empty string that used to raise a type-conversion error before amt_media/amt_info
even attempted a connection (issue #87). Proving that by dialing a live endpoint that is
actually sitting on that exact default port, and completing a real handshake against
it, is a stronger proof than only checking that no exception was raised: a caller could
otherwise flip the fix's `default(omit, true)` back to a plain pass-through and still
have this pass by accident if the assertion only checked for absence of a crash.

Unlike run_wsman_mock_capabilities.py, this does not need to reach into any private
name in wsman_server -- WsmanMockServer.start() hardcodes binding port 0, so this
reimplements that one method with the caller's port instead of monkeypatching around
it, then serves forever exactly as the shared runner's main() does.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock-servers-dir", required=True, help="Directory containing wsman_server.py")
    parser.add_argument("--ready-file", required=True, help="Path this script writes {pid, port, cert_fingerprint} to once listening")
    parser.add_argument("--port", type=int, required=True, help="Fixed TCP port to bind, instead of an ephemeral one")
    parser.add_argument("--use-tls", action="store_true")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="test-password-not-real")  # fixture default, not a real credential
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sys.path.insert(0, args.mock_servers_dir)
    from wsman_server import WsmanMockServer, _MockThreadingHTTPServer, _WsmanHandler  # local import: only resolvable after the sys.path insert above

    server = WsmanMockServer(username=args.username, password=args.password, use_tls=args.use_tls)

    # Reimplements WsmanMockServer.start() with args.port instead of the 0 it hardcodes.
    # If this OSErrors ("Address already in use"), that is a real failure this script
    # deliberately does not swallow: the whole point of the scenario is dialing *this*
    # port, so silently falling back to an ephemeral one would prove nothing.
    httpd = _MockThreadingHTTPServer((server.host, args.port), _WsmanHandler)
    httpd.daemon_threads = True
    httpd.mock = server
    if server.use_tls:
        from wsman_server import generate_self_signed_tls_context  # local import, same reason as above

        ctx, fingerprint, tmpdir = generate_self_signed_tls_context(server.host)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        server.cert_fingerprint = fingerprint
        server._tls_tmpdir = tmpdir
    server._httpd = httpd
    server.port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, name="wsman-mock-fixed-port", daemon=True)
    thread.start()
    server._thread = thread

    ready_path = Path(args.ready_file)
    tmp_path = ready_path.with_name(f"{ready_path.name}.tmp")
    tmp_path.write_text(json.dumps({"pid": os.getpid(), "port": server.port, "cert_fingerprint": server.cert_fingerprint}))
    os.replace(tmp_path, ready_path)

    def _stop(*_args: object) -> None:
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()

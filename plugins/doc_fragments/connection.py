# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


class ModuleDocFragment:
    # Shared connection options for the WS-Man management plane. Every module in
    # this collection extends this fragment so the options are documented once.
    DOCUMENTATION = r"""
options:
  host:
    description:
      - Hostname or IP address of the Intel AMT management endpoint.
      - This is the address of the AMT firmware itself, which is usually distinct
        from the address of any operating system running on the same machine.
    type: str
    required: true
  port:
    description:
      - TCP port of the WS-Man management interface.
      - When not set, defaults to V(16993) if O(use_tls=true) and V(16992) otherwise.
    type: int
  username:
    description:
      - AMT account used for Digest authentication.
    type: str
    default: admin
  password:
    description:
      - Password for O(username).
      - Always supply this from a vaulted variable. Never inline it in a playbook.
    type: str
    required: true
  use_tls:
    description:
      - Whether to use TLS for the management connection.
      - Left at the default of V(true), the module connects to port 16993 and
        enforces the trust policy selected by O(validate_certs), O(ca_path) and
        O(tls_fingerprint).
      - Setting this to V(false) is only honoured when O(allow_insecure_transport=true)
        is also set. This is deliberate; see the note about AMT provisioning modes.
    type: bool
    default: true
  allow_insecure_transport:
    description:
      - Explicit acknowledgement required to talk to AMT over unencrypted HTTP.
      - Intel AMT provisioned in Small Business Mode does not implement TLS at all,
        so port 16993 never opens on those machines. Plaintext is the only option
        there, which is why this escape hatch exists, but it is never selected
        implicitly.
      - When plaintext is used, credentials cross the network in a form an on-path
        attacker can recover. Only do this on an isolated management VLAN.
    type: bool
    default: false
  validate_certs:
    description:
      - Whether to verify the AMT TLS certificate chain and hostname.
      - Only meaningful when O(use_tls=true). Ignored when O(tls_fingerprint) is set,
        because pinning is itself the trust decision.
    type: bool
    default: true
  ca_path:
    description:
      - Path to a CA bundle used to verify the AMT certificate chain.
      - Selects CA trust mode. Mutually exclusive with O(tls_fingerprint).
    type: path
  tls_fingerprint:
    description:
      - SHA-256 fingerprint of the expected leaf certificate, for pinning.
      - This is the practical trust mode for AMT, whose certificates are typically
        self-signed and presented on a bare IP address, where chain and hostname
        verification cannot succeed.
      - Accepted with or without colon separators and in any case. An optional
        V(sha256:) prefix is allowed.
      - Mutually exclusive with O(ca_path).
    type: str
  timeout:
    description:
      - Timeout in seconds for an individual WS-Man operation.
    type: int
    default: 30
  connect_timeout:
    description:
      - Timeout in seconds for establishing the TCP and TLS connection.
    type: int
    default: 10
notes:
  - An Intel AMT endpoint is firmware and cannot execute a Python payload, so these
    modules run on the Ansible controller. Use C(delegate_to: localhost) (or
    C(connection: local)) on every task. No agent, SSH access, or Python interpreter
    is required on the target.
  - Because the modules run on the controller, the C(requests) library must be
    installed there, not on the managed node.
  - Power and boot operations are physically disruptive. Delegating to localhost
    does not stop Ansible from fanning a task out across every host in the play,
    so pair these tasks with C(serial: 1) and an explicit single-target selection
    when mutating state.
requirements:
  - requests >= 2.25.0 (on the Ansible controller)
seealso:
  - name: Intel AMT Implementation and Reference Guide
    description: Vendor reference for power state, boot configuration, and redirection.
    link: https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm
"""

    # Attribute descriptions, kept separate so modules can document check-mode and
    # diff-mode support consistently.
    ATTRIBUTES = r"""
options: {}
attributes:
  check_mode:
    description: Can run in C(check_mode) and return a changed-status prediction without modifying the target.
  diff_mode:
    description: Returns details on what has changed, or would change in C(check_mode).
"""

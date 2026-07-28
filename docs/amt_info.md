<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_info`

Read-only facts and capability discovery for an Intel AMT endpoint.

## Purpose

`amt_info` reads whatever the firmware itself reports — provisioning state,
current power state, and which boot/redirection capabilities are actually
present — over WS-Man. It never mutates anything and always returns
`changed: false`.

Capabilities are discovered from live firmware responses (mainly
`AMT_BootCapabilities`), never inferred from an AMT generation or SKU. If the
firmware omits an optional WS-Man class entirely, the corresponding
capability flag degrades to `false`/unknown rather than failing the whole
read — see [`plugins/module_utils/client.py`](../plugins/module_utils/client.py)
`AmtClient.get_facts()` and its `_get_optional()` helper.

This is the module to run first in any playbook that later mutates state: use
its `amt.capabilities.*` flags to fail fast, before AMT is asked to do
something it does not support.

## Options

In addition to the [shared connection options](../plugins/doc_fragments/connection.py),
`amt_info` takes no module-specific options.

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `host` | `str` | — | yes | — |
| `port` | `int` | (16993 if `use_tls` else 16992) | no | — |
| `username` | `str` | `admin` | no | — |
| `password` | `str` (`no_log`) | — | yes | — |
| `use_tls` | `bool` | `true` | no | — |
| `allow_insecure_transport` | `bool` | `false` | no | — |
| `validate_certs` | `bool` | `true` | no | — |
| `ca_path` | `path` | — | no | — |
| `tls_fingerprint` | `str` | — | no | — |
| `timeout` | `int` | `30` | no | — |
| `connect_timeout` | `int` | `10` | no | — |

Verified against the rendered argument spec (`ansible-doc james_crowley.intel_amt.amt_info`)
and `_connection_argument_spec()` in `plugins/modules/amt_info.py`.

## Return values

Everything is nested under a single `amt` key (`type: dict`, `returned: success`):

| Field | Type | Returned | Description |
|---|---|---|---|
| `amt.reachable` | `bool` | always | Whether the WS-Man management plane answered this read at all. |
| `amt.version` | `str` | when available | AMT firmware version string, read from `CIM_SoftwareIdentity` where `InstanceID == "AMT"`, field `VersionString` (see [Capability matrix](capability-matrix.md)). |
| `amt.uuid` | `str` | when available | System UUID from `CIM_ComputerSystem`. |
| `amt.control_mode` | `str` | when available | `AMT_SetupAndConfigurationService.ProvisioningMode`. |
| `amt.provisioning_state` | `str` | when available | `AMT_SetupAndConfigurationService.ProvisioningState`. |
| `amt.hostname` | `str` | when available | `AMT_GeneralSettings.HostName` — firmware-observed, **not** an inventory value. |
| `amt.power_state.normalized` | `str` | when available | One of `on`, `off`, `sleep`, `hibernate`, `unknown`. |
| `amt.power_state.raw` | `int` | when available | The raw `CIM_AssociatedPowerManagementService.PowerState` integer. |
| `amt.capabilities.power` | `bool` | — | Whether power state could be read at all. |
| `amt.capabilities.boot_once_pxe` | `bool` | — | `AMT_BootCapabilities.ForcePXEBoot`. |
| `amt.capabilities.sol` | `bool` | — | `AMT_BootCapabilities.SOL`. |
| `amt.capabilities.storage_redirection` | `bool` | — | `AMT_BootCapabilities.IDER`. |
| `amt.redirection_status.enabled_state` | `int` | when available | Raw `AMT_RedirectionService.EnabledState`. |
| `amt.redirection_status.listener_enabled` | `bool` | when available | `AMT_RedirectionService.ListenerEnabled`. |
| `amt.redirection_status.ider_enabled` | `bool` | when available | Derived: `enabled_state` in `{32769, 32771}`. |
| `amt.redirection_status.sol_enabled` | `bool` | when available | Derived: `enabled_state` in `{32770, 32771}`. |

Note that `amt.capabilities` (what firmware *supports*, per `AMT_BootCapabilities`) and
`amt.redirection_status` (what is currently *enabled*, per `AMT_RedirectionService`) are
deliberately separate — a supported feature is not necessarily switched on. `amt_redirection`
additionally reports whether the redirection ports are actually *reachable* over TCP, a third,
independent signal this module does not probe.

## Examples

```yaml
- name: Read AMT capabilities and state
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt

- name: Require IDE-R support before attempting a media-backed install
  ansible.builtin.assert:
    that:
      - amt.amt.reachable
      - amt.amt.capabilities.storage_redirection
```

```yaml
- name: Fail early if the endpoint cannot do one-time PXE boot
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt

- name: Assert PXE boot capability before arming anything
  ansible.builtin.assert:
    that: amt.amt.capabilities.boot_once_pxe
    fail_msg: "Firmware does not advertise ForcePXEBoot; cannot proceed with a PXE-based install."
```

## Idempotence and check mode

`amt_info` never mutates anything, in check mode or otherwise: `check_mode` support is
`full`, but a full read runs identically whether or not `--check` is passed, and
`changed` is always `false`. `diff_mode` support is `none` — there is no prior/after
state to diff for a read-only module.

## Errors this module can raise

`amt_info` propagates any `AmtError` subclass that a genuine transport failure raises.
Facts-gathering *degrades* rather than fails when an individual optional class (mainly
`AMT_BootCapabilities`) is simply absent from a firmware's implementation — that shows
up as a `false`/`None` field, not an error. What does surface as a failure:

| `error_class` | Meaning here |
|---|---|
| `connection` | TCP/DNS failure reaching the management port. |
| `tls_validation` | Certificate chain/hostname/fingerprint mismatch, or plaintext requested without `allow_insecure_transport`. |
| `authentication` | AMT rejected the Digest credentials (HTTP 401). |
| `timeout` | The read timed out. A read is never mutating, so there is no `indeterminate` case here. |
| `protocol` | Malformed SOAP, or a non-`Envelope` response — includes the firmware simply not implementing a class this module tried to read as a *required* field (e.g. `CIM_AssociatedPowerManagementService` for `get_power_state`-style reads used elsewhere; `amt_info` itself tolerates this for capability discovery, per above). |

`amt_info` never raises `unsupported_capability`, `invalid_state`, `remote_operation`, or
`identity_mismatch` itself — those are specific to modules that request a mutation or
compare caller-supplied identity.

## Limitations

- No caching: every invocation re-reads firmware over the network. There is no facts-cache
  integration.
- `amt.version` depends on `CIM_SoftwareIdentity` exposing an instance with
  `InstanceID == "AMT"`. Firmware that omits this instance (or names it differently)
  reports `amt.version: null` — this collection does not fall back to any other field.
  Earlier attempts to read a version property directly from `AMT_GeneralSettings` or
  `AMT_SetupAndConfigurationService` do not work: neither class carries a version field
  at all (see [Capability matrix](capability-matrix.md)).
- `amt.capabilities` reflects only the four capability flags this collection currently
  cares about (`power`, `boot_once_pxe`, `sol`, `storage_redirection`). `AMT_BootCapabilities`
  reports many more fields (`ForceHardDriveBoot`, `ForceCDorDVDBoot`, `BIOSSetup`,
  `BIOSPause`, `BIOSReflash`, and others) that `amt_info` does not surface; consult
  `amt_boot`'s and `amt_redirection`'s own capability checks, or read the class directly,
  if you need one of those.
- This module is **hardware-qualified against AMT 16.1.30** (firmware version, all four
  capability flags, redirection state and platform UUID all confirmed on real firmware). It
  remains unverified on any other firmware generation — see the
  [Capability matrix](capability-matrix.md).

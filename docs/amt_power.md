<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_power`

Control and query Intel AMT power state.

## Purpose

Reads and changes power state via `CIM_AssociatedPowerManagementService` (read) and
`CIM_PowerManagementService.RequestPowerStateChange` (mutate). `state=on` and
`state=off` are **convergent**: the current state is read first, and nothing is sent
if the endpoint is already there. `state=reboot`, `state=reset`, and `state=cycle` are
**imperative** and always issue a request outside check mode. `state=query` only reads.

`reboot` and `reset` are two names for the *same* AMT action (master-bus-reset,
action code 10) — AMT has no separate graceful-reboot primitive
(`plugins/module_utils/client.py`, `PowerAction`/`_POWER_ACTION_CODES`).

A successful request only means AMT accepted it (`ReturnValue == 0`), not that the
transition finished. This module polls a bounded number of times afterwards
(`AmtClient.request_power_state`: 5 probes, 2 seconds apart, by default) and reports
what it actually observed; it never retries the request itself.

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `state` | `str` | `query` | no | `on`, `off`, `reboot`, `reset`, `cycle`, `query` |
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

Verified against `argument_spec()` in `plugins/modules/amt_power.py` and the rendered
`ansible-doc` output.

## Return values

`amt_power` nests its `intel-amt-operation/v1` receipt under an `operation` key — the
same shape every module in this collection returns it under. `amt_boot`,
`amt_redirection`, and `amt_media` used to spread the receipt's fields at the top level
instead; that inconsistency was normalised in issue #22, and `amt_power`'s shape below
was the template the other four modules were changed to match (see
[Capability matrix](capability-matrix.md) for the full history).

| Field | Type | Returned | Description |
|---|---|---|---|
| `state` | `str` | always | The requested `state`, echoed back. |
| `previous_state.normalized` / `.raw` | `str` / `int` | always | Power state observed before any action. |
| `desired_state` | `str` | when a transition was requested or planned | Absent for `state=query`. |
| `return_value` | `int` | when a request was sent | AMT's `ReturnValue` from `RequestPowerStateChange`. Always `0` here — a non-zero value raises `remote_operation` instead. |
| `probes` | `list` of dict | when a request was sent | Each entry shaped like `previous_state`. Empty if no request was sent, or if every probe itself failed. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | `amt_power.<state>`, e.g. `amt_power.on`. |
| `operation.endpoint` | `str` | always | `host:port` this operation was performed against. |
| `operation.changed` | `bool` | always | Mirrors the top-level `changed`. |
| `operation.previous` | `dict` | always | Same shape as `previous_state`. |
| `operation.desired` | `str` or `null` | always | Same value as `desired_state`. |
| `operation.observed` | `dict` or `null` | always | The last postcondition probe taken, same shape as `previous_state`, or `null`. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 fingerprint of the TLS leaf certificate observed, or `null` over plaintext. |
| `operation.error_class` | `str` or `null` | always | `null` on success; a stable machine-readable failure class on failure. |

## Examples

```yaml
- name: Ensure the endpoint is powered on
  james_crowley.intel_amt.amt_power:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    state: "on"
  delegate_to: localhost
  no_log: true
  register: power
```

```yaml
- name: Master-bus-reset into a freshly attached installer image
  james_crowley.intel_amt.amt_power:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    state: reset
  delegate_to: localhost
  no_log: true
  serial: 1
```

## Idempotence and check mode

| `state` | Idempotent? | `changed` |
|---|---|---|
| `query` | n/a (read-only) | always `false` |
| `on` / `off` | yes (convergent) | `true` only if the observed state differs from the target |
| `reboot` / `reset` / `cycle` | no (imperative) | `true` whenever a request is issued or planned |

`check_mode` support is `full`: the planned transition is computed and returned
exactly as in normal mode, but `RequestPowerStateChange` is never sent. `diff_mode`
support is `none` — use `previous_state`/`desired_state` instead of `--diff`.

## Errors this module can raise

| `error_class` | Meaning here |
|---|---|
| `connection` | TCP/DNS failure. |
| `tls_validation` | Certificate/fingerprint problem, or plaintext without acknowledgement. |
| `authentication` | Digest credentials rejected. |
| `timeout` | If raised *after* `RequestPowerStateChange` was transmitted, carries `indeterminate: true` — the mutation may have applied; re-probe with `state=query` rather than retrying. |
| `protocol` | Malformed SOAP or unexpected response shape. |
| `remote_operation` | AMT accepted the request but returned a non-zero `ReturnValue`. |

A failed postcondition probe (during the bounded polling after a request) does **not**
turn a successful request into a reported failure — see
`AmtClient.request_power_state`'s `except AmtError: continue`. Only the initial
`invoke()` call's own errors (`remote_operation`, `timeout`, etc.) propagate.

## Limitations

- There is no separate "graceful shutdown" or "graceful reboot": `reset` and `reboot`
  both issue a master bus reset. There is also no ACPI soft-shutdown request exposed —
  `off` requests AMT's power-off action (code 8), not an OS-level shutdown.
- Postcondition polling is bounded (5 attempts × 2 seconds by default, not
  configurable via module options) and best-effort; `probes` can be empty even
  after a successful, accepted request if every probe read itself failed.
- `sleep`/`hibernate` power actions exist in the underlying `PowerAction` enum
  (`plugins/module_utils/client.py`) but are **not** exposed through this module's
  `state` choices — only `on`, `off`, `reboot`, `reset`, `cycle`, `query` are reachable
  from the module.
- `delegate_to: localhost` does not protect against inventory fan-out: a play over
  ten hosts still issues ten resets. Pair mutating tasks with `serial: 1`.
- Hardware-unverified — see the [Capability matrix](capability-matrix.md). The action
  codes are "as used by MeshCmd, verified against firmware" per
  `docs/protocol-notes.md` §2.4, but this collection's own implementation of them has
  not been re-verified against real AMT hardware.

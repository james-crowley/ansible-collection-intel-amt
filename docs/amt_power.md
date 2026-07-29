<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_power`

Control and query Intel AMT power state.

## Purpose

Reads and changes power state via `CIM_AssociatedPowerManagementService` (read) and
`CIM_PowerManagementService.RequestPowerStateChange` (mutate). `state=on`,
`state=off` and `state=hibernate` are **convergent**: the current state is read
first, and nothing is sent if the endpoint is already there. `state=reboot`,
`state=reset`, `state=cycle`, `state=sleep-light` and `state=sleep-deep` are
**imperative** and always issue a request outside check mode. `state=query` only reads.

`reboot` and `reset` are two names for the *same* AMT action (master-bus-reset,
action code 10) — AMT has no separate graceful-reboot primitive
(`plugins/module_utils/client.py`, `PowerAction`/`_POWER_ACTION_CODES`).

### Why the sleep depths are not convergent, but hibernate is

`sleep-light` (ACPI S1, CIM code 3) and `sleep-deep` (ACPI S3, CIM code 4) both
read back through `_POWER_STATE_TABLE` as the single normalized state `sleep`
(`plugins/module_utils/models.py`). So "already asleep" is indistinguishable from
"asleep, but at the other depth" — treating them as convergent would report
`changed: false` for a transition that was never issued. They therefore always
send. `hibernate` is convergent because CIM code 7 is the only value normalizing
to `hibernate`, so that reading can be trusted.

### Firmware and OS support

**`sleep-light`, `sleep-deep` and `hibernate` are unverified against real
firmware** — see [`capability-matrix.md`](capability-matrix.md). They carry the
correct CIM codes, but no hardware qualification stage has exercised them.

They also depend on the **target operating system** supporting the corresponding
ACPI state and on it being enabled in firmware. Where it is not, AMT answers with
a non-zero return code, surfaced as `error_class=remote_operation` rather than
being treated as success. A powered-off machine cannot be put to sleep at all;
AMT rejects that rather than ignoring it.

A successful request only means AMT accepted it (`ReturnValue == 0`), not that the
transition finished. This module polls a bounded number of times afterwards
(`AmtClient.request_power_state`: 5 probes, 2 seconds apart, by default) and reports
what it actually observed; it never retries the request itself.

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `state` | `str` | `query` | no | `on`, `off`, `reboot`, `reset`, `cycle`, `sleep-light`, `sleep-deep`, `hibernate`, `query` |
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

A reset is the fan-out hazard in this collection, and `serial` is a **play**
keyword — a task carrying it fails with "conflicting action statements". Constrain
it at the play level:

```yaml
- name: Master-bus-reset into a freshly attached installer image
  hosts: "{{ target }}"
  serial: 1                     # play-level; never fan out a reset
  gather_facts: false
  tasks:
    - name: Issue the reset
      james_crowley.intel_amt.amt_power:
        host: "{{ amt_host }}"
        username: "{{ amt_username }}"
        password: "{{ amt_password }}"
        tls_fingerprint: "{{ amt_tls_fingerprint }}"
        state: reset
      delegate_to: localhost
      no_log: true
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
  ten hosts still issues ten resets. Constrain the **play** with `serial: 1` and an
  explicit single-target selection — `serial` cannot be set on a task.
- **Hardware-qualified against AMT 16.1.30 and AMT 19.0.5.** Stage 4 exercised this
  module against real firmware on both lab machines, with the same outcomes on each:
  convergent `on` reported `changed: false` on an already-on machine, `off` reported
  `changed: true`, and the starting state was restored afterwards; stages 5 and 7
  issued real resets. So the action codes — "as used by MeshCmd, verified against
  firmware" per `docs/protocol-notes.md` §2.4 — are now confirmed as this
  collection implements them, on two firmware generations, and remain unverified on
  every other. `sleep-light`, `sleep-deep` and `hibernate` **are** selectable (they
  were exposed after being implemented-but-unreachable for three releases), but no
  hardware stage has issued any of them on either machine -- stage 4 exercised only
  `on` and `off`. See the [Capability matrix](capability-matrix.md).

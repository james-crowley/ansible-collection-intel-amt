<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_redirection`

Report and optionally toggle Intel AMT redirection-service enablement.

## Purpose

Reads (and, if `state` is given, mutates) whether the Intel AMT redirection service —
IDE-R and/or Serial-over-LAN — is enabled at the WS-Man management layer, plus whether
the redirection ports are actually reachable over TCP.

Three signals are always reported separately and never collapsed into one boolean
(`docs/protocol-notes.md` §2.6):

1. **supported** — does firmware implement IDE-R/SOL at all? From `AMT_BootCapabilities`.
2. **enabled** — is the redirection service turned on? From `AMT_RedirectionService`.
3. **transport_reachable** — does a bare TCP connect to 16994/16995 actually succeed?

A machine can be supported and enabled yet unreachable behind a firewall, or reachable
on the port while the service itself is disabled — collapsing these would hide exactly
the distinction an operator needs.

**This module does not move media and does not open a redirection session itself** —
it only reports and toggles the WS-Man-level enablement flag. Attaching and streaming
IDE-R media is `amt_media`'s job.

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `state` | `str` | — (absent = read-only) | no | `disabled`, `ider`, `sol`, `all` |
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

When `state` is absent (the default), this module is read-only and `changed` is always
`false`. `state=disabled` turns both IDE-R and SOL off; `state=ider`/`state=sol` enable
one; `state=all` enables both. Requesting `ider`/`sol`/`all` when firmware does not
advertise the corresponding capability fails with `unsupported_capability` **before**
any mutation (`redirection_service.validate_state_change()`).

Verified against `_argument_spec()` in `plugins/modules/amt_redirection.py` and the
rendered `ansible-doc` output.

## Return values

`amt_redirection` nests its `intel-amt-operation/v1` receipt under an `operation` key,
the same shape every module in this collection returns it under (see
[Capability matrix](capability-matrix.md) — this was previously inconsistent across
modules and was normalised in issue #22).

| Field | Type | Returned | Description |
|---|---|---|---|
| `changed` | `bool` | always | `true` only when `state` was given, differed from the observed state, and (outside check mode) `RequestStateChange` was invoked. Always `false` when `state` is absent. |
| `supported.ider` / `supported.sol` | `bool` | always | What `AMT_BootCapabilities` advertises. |
| `enabled.enabled_state` | `int` | always | Raw `AMT_RedirectionService.EnabledState` (32768/32769/32770/32771). |
| `enabled.listener_enabled` | `bool` | always | `AMT_RedirectionService.ListenerEnabled`. |
| `enabled.ider_enabled` / `.sol_enabled` | `bool` | always | Derived from `enabled_state`. |
| `transport_reachable` | `dict` | always | Keyed by port number (`16994`, `16995`); whether a bare TCP connect succeeded. No redirection-protocol handshake is attempted. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | Always `amt_redirection`. |
| `operation.endpoint` | `str` | always | `host:port`. |
| `operation.changed` | `bool` | always | Mirrors the top-level `changed`. |
| `operation.previous` | `str` or `null` | always | The redirection-service state name observed before any action. |
| `operation.desired` | `str` or `null` | always | The `state` requested, or `null` when `state` is absent. |
| `operation.observed` | `dict` | always | Same shape as the top-level `enabled`. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 fingerprint of the TLS leaf certificate observed, or `null` over plaintext. |
| `operation.error_class` | `str` or `null` | always | `null` on success; a stable machine-readable failure class on failure. |

Note `supported`, `enabled`, and `transport_reachable` are this module's own
module-specific return values, not part of the shared `operation` receipt — they stay
at the top level exactly as before. `error_class` also appears at the **top level** of
a failed module's result (what `fail_json`/rescue blocks read), independent of
`operation.error_class`, which is always `null` on the successful-exit path documented
above.

## Examples

```yaml
- name: Report redirection-service support, enablement, and reachability
  james_crowley.intel_amt.amt_redirection:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt_redirection_status
```

```yaml
- name: Enable IDE-R ahead of a virtual-media attach
  james_crowley.intel_amt.amt_redirection:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    state: ider
  delegate_to: localhost
  no_log: true
```

## Idempotence and check mode

Without `state`, always a no-op read (`changed: false`). With `state` set, mutation is
convergent: `changed` reflects whether the requested state actually differs from what
was observed — requesting the state that is already in effect is a no-op.

`check_mode` support is `full`: with `state` set, reports the state that would be
requested and whether it differs from current, without invoking `RequestStateChange`.
`diff_mode` support is `full`: previous and (with `state` set) intended enabled-state
are both in the receipt.

## Errors this module can raise

| `error_class` | Meaning here |
|---|---|
| `unsupported_capability` | `state=ider`/`sol`/`all` requested but the corresponding `AMT_BootCapabilities` field is not set, or `AMT_BootCapabilities` did not return exactly one instance. Raised before `RequestStateChange`. |
| `connection` / `tls_validation` / `authentication` / `timeout` | Standard transport failures. |
| `protocol` | Malformed SOAP or unexpected response shape. |
| `remote_operation` | `RequestStateChange` returned a non-zero `ReturnValue`. |

Note that the `transport_reachable` TCP probe (`redirection_service.probe_transport_reachable`)
swallows `OSError` itself and reports `false` for that port rather than raising — a
closed or firewalled redirection port is not a module failure, it is exactly the signal
this field exists to report.

## Limitations

- This module cannot enable redirection support the firmware does not advertise —
  there is no override.
- `transport_reachable` is a bare TCP connect-and-close. It proves nothing about
  authentication or protocol correctness on that port; a firewall that completes a TCP
  handshake but then drops a real redirection session would still show `true` here.
- `IPS_OptInService`, which governs user consent on some AMT configurations (per
  `docs/protocol-notes.md` §2.6), is not read or reported by this module at all.
- **Hardware-qualified: the read path against AMT 16.1.30 and 19.0.5, the mutating
  path against 16.1.30 only.** Stage 8 ran two consecutive read-only calls against
  both lab machines and confirmed they agreed, across two different
  `EnabledState` values (`32769` = IDER only, `32771` = SOL+IDER). The
  `state: ider` mutation ran on real firmware in stages 5 and 6, on the 16.1.30
  machine alone. The `IDER`/`SOL` field-name mapping this module relies on for the
  `supported` signal is still flagged in the
  [Capability matrix](capability-matrix.md) — read that section before trusting
  `supported.*` against a firmware generation this collection has not seen.

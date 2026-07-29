<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_boot`

Arm a one-time boot device selection on an Intel AMT endpoint.

## Purpose

Arms exactly one upcoming reset to boot from a specific device, using the five-step
`AMT_BootSettingData` / `CIM_BootConfigSetting` / `CIM_BootService` sequence in
[`docs/protocol-notes.md`](protocol-notes.md) §2.5. The selection is a one-shot
`IsNextSingleUse` role, consumed by the *next* reset the endpoint experiences however
that reset happens — this module never issues a power action itself. Pair it with
`amt_power` (or an external reset) to actually apply the boot selection.

This is the highest-consequence operation in the collection: a machine left with a
wrong boot configuration typically needs physical or KVM recovery
(see [`docs/testing.md`](testing.md) "If a machine ends up in a bad boot state"). The
module refuses to arm anything without an explicit `action_token`, enumerates the
endpoint's boot capabilities and sources before touching anything
(`discover_and_validate()` in `plugins/module_utils/boot.py`), and never re-arms
automatically.

**Native one-time PXE/HDD/CD boot and IDE-R boot are mutually exclusive.** Naming a
native boot source in `ChangeBootOrder`'s step 5 would override IDE-R redirection —
this is enforced structurally by `BootPlan.__post_init__` in `boot.py`, not just by the
six-value `device` choice.

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `device` | `str` | — | yes | `pxe`, `hdd`, `cd`, `bios`, `ider_floppy`, `ider_cdrom` |
| `mode` | `str` | `once` | no | `once` (the only value; there is no persistent boot-order mode) |
| `action_token` | `str` | — | yes | — |
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

`action_token` must be present and non-empty on **every** call — including check-mode
calls — or the module fails with `invalid_state` before any WS-Man call is made
(`arm_one_time_boot()` in `boot.py`). There is no internal re-arm path: a caller that
hits an indeterminate result must supply a fresh token to try again.

Verified against `_argument_spec()` in `plugins/modules/amt_boot.py` and the rendered
`ansible-doc` output.

### What each `device` value actually selects

| `device` | Native boot source named? | `AMT_BootSettingData` fields set |
|---|---|---|
| `pxe` | `CIM_BootSourceSetting` `InstanceID="Intel(r) AMT: Force PXE Boot"` | `UseIDER=false` |
| `hdd` | `InstanceID="Intel(r) AMT: Force Hard-drive Boot"` | `UseIDER=false` |
| `cd` | `InstanceID="Intel(r) AMT: Force CD/DVD Boot"` | `UseIDER=false` |
| `bios` | none (null `Source` in step 5) | `BIOSSetup=true`, `UseIDER=false` |
| `ider_floppy` | none (null `Source`) | `UseIDER=true`, `IDERBootDevice=0` |
| `ider_cdrom` | none (null `Source`) | `UseIDER=true`, `IDERBootDevice=1` |

`ider_floppy`/`ider_cdrom` only arm the boot *selection* — they do not attach media or
enable the redirection service. Pair with `amt_redirection` (`state: ider`) and
`amt_media` (`state: attached`) beforehand.

## Return values

`amt_boot` nests its `intel-amt-operation/v1` receipt under an `operation` key, the
same shape every module in this collection returns it under (see
[Capability matrix](capability-matrix.md) — this was previously inconsistent across
modules and was normalised in issue #22).

| Field | Type | Returned | Description |
|---|---|---|---|
| `changed` | `bool` | always | Always `true` on success — arming is not idempotent against prior state; every successful call re-clears and re-sets the boot order. |
| `device` | `str` | always | The `device` value that was armed. |
| `boot_config_selector` | `dict` | always | The `CIM_BootConfigSetting` selector used in steps 2, 4, and 5. |
| `boot_source_selector` | `dict` or `null` | always | The `CIM_BootSourceSetting` selector named in step 5, or `null` for `bios`/`ider_floppy`/`ider_cdrom`. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | Always `amt_boot`. |
| `operation.endpoint` | `str` | always | `host:port` this operation ran against. |
| `operation.changed` | `bool` | always | Mirrors the top-level `changed`. |
| `operation.previous` | `dict` | always | `AMT_BootSettingData` properties as read before mutation. |
| `operation.desired` | `dict` | always | `AMT_BootSettingData` properties attempted (or, in check mode, that would be attempted) via `Put`. |
| `operation.observed` | `dict` | always | `AMT_BootSettingData` read back after the sequence completed. Equal to `previous` in check mode. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 fingerprint of the TLS leaf certificate observed, or `null` over plaintext. |
| `operation.error_class` | `str` or `null` | always | `null` on success; a stable machine-readable failure class on failure. |

Note `error_class` also appears at the **top level** of a failed module's result — that
is what Ansible's `fail_json` surfaces and what rescue blocks read
(`ansible_failed_result.error_class`); it is unrelated to `operation.error_class`, which
is always `null` on the successful-exit path documented above.

## Examples

`serial` is a **play** keyword, not a task keyword: putting it on a task makes
Ansible fail with "conflicting action statements". Arming a boot is a fan-out
hazard, so the example below shows the play wrapper that actually constrains it.

```yaml
- name: Arm a one-time PXE boot for an unattended install
  hosts: "{{ target }}"
  serial: 1                     # play-level; never fan out an arm-then-reset
  gather_facts: false
  tasks:
    - name: Arm the one-time PXE boot
      james_crowley.intel_amt.amt_boot:
        host: 10.0.0.5
        username: admin
        password: "{{ vaulted_amt_password }}"
        tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
        device: pxe
        action_token: "{{ lookup('ansible.builtin.password', '/dev/null length=32') }}"
      delegate_to: localhost
      no_log: true
```

```yaml
- name: Arm IDE-R CD-ROM boot for an attached installer ISO
  james_crowley.intel_amt.amt_boot:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    device: ider_cdrom
    action_token: "{{ boot_action_token }}"
  delegate_to: localhost
  no_log: true
```

## Idempotence and check mode

**Not idempotent by design.** `changed` is always `true` on success, because every
call re-clears and re-arms the one-shot boot order regardless of what it observed
beforehand — there is no "already armed for this device" convergence check, since the
one-shot role is consumed by the next reset regardless of whether this call ran once
or five times before it.

`check_mode` support is `full`: discovery and the `AMT_BootSettingData` `Get` both run
(neither mutates anything), but none of the four mutating WS-Man calls (the two
`ChangeBootOrder` invokes, the `Put`, and `SetBootConfigRole`) execute.
`action_token` is still required and validated in check mode. `diff_mode` support is
`full`: `previous`/`desired` in the receipt serve as the diff.

## Errors this module can raise

| `error_class` | Meaning here |
|---|---|
| `invalid_state` | `action_token` missing/empty, or (structurally, not reachable through the module's own six-value `device` choice) an internal `use_ider` + native-boot-source combination. |
| `unsupported_capability` | Discovery failed closed: `AMT_BootCapabilities` does not report exactly one instance, the target's capability field (see [Capability matrix](capability-matrix.md)) is not `true`, or `CIM_BootSourceSetting` does not have exactly one matching instance for a native target. Raised *before* any of the four mutating calls. |
| `connection` / `tls_validation` / `authentication` / `timeout` | Standard transport failures, same as every other module. A `timeout` raised after any of steps 2–5 has been transmitted must be treated as indeterminate — see Limitations. |
| `protocol` | Malformed SOAP or unexpected shape from any of the five WS-Man calls. |
| `remote_operation` | Any of the four mutating calls (`ChangeBootOrder` ×2, `Put`, `SetBootConfigRole`) returned a non-zero `ReturnValue`; the sequence aborts at that step. |

## Limitations

- **No partial-failure recovery.** If step 2, 3, or 4 fails after step 1 succeeded, the
  boot configuration may be left in an intermediate state (for example, boot order
  cleared but the one-shot role not yet set). There is no automatic rollback; re-run
  with a fresh `action_token` once you have confirmed the endpoint's actual state
  (`amt_info` or a fresh `AMT_BootSettingData` read).
- **`bios` and the two `ider_*` targets share the same capability-field mapping
  concern**: this collection's mapping of `device` onto `AMT_BootCapabilities` field
  names is per `docs/protocol-notes.md` §2.5's table — see the
  [Capability matrix](capability-matrix.md) for exactly what is and is not
  independently verified.
- **One-shot only.** There is no persistent boot-order mode (`mode` accepts only
  `once`), and the arm is consumed by literally the next reset — if something else
  resets the machine before your intended `amt_power` task runs, the boot selection is
  spent.
- **Hardware-qualified against AMT 16.1.30 and AMT 19.0.5.** Real firmware has
  processed this five-step sequence on both lab machines: stage 7 armed a native
  one-time PXE boot, read it back as armed, and found `AMT_BootSettingData`
  unchanged after the reset, and stage 5 armed `ider_cdrom` through the
  `amt_baremetal_install` role. No generation other than those two has been touched
  at all. See the [Capability matrix](capability-matrix.md).
- **Issue #13 (the WS-Addressing EPR byte-form question) is settled for 16.1.30 and
  19.0.5.** Stage 7's `ChangeBootOrder` named a real endpoint reference for
  `Intel(r) AMT: Force PXE Boot` and succeeded on both, so the prefixed-namespace
  form this module emits **is** accepted by real firmware on two generations. That
  result is meaningful rather than merely permissive because the same firmware
  rejected an empty `<Source/>` with HTTP 400 — it demonstrably enforces its own
  schema on this call. The form remains *inferred* for every other firmware
  generation, since a conformant XML parser treats both byte-forms as identical and
  no test can distinguish them.

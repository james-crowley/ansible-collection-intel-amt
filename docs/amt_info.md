<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_info`

Read-only facts and capability discovery for an Intel AMT endpoint.

## Purpose

`amt_info` reads whatever the firmware itself reports — provisioning state,
current power state, network configuration, system state, and which
boot/redirection capabilities are actually present — over WS-Man. It never
mutates anything and always returns `changed: false`.

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
| `amt.uuid` | `str` | when available | System UUID, read from `CIM_ComputerSystemPackage.PlatformGUID` as 32 undashed hex characters and rendered in canonical dashed form. The SMBIOS Type 1 UUID carries its first three fields **little-endian**, so those fields are reversed on the way out (`_canonical_uuid()` in [`plugins/module_utils/client.py`](../plugins/module_utils/client.py)); without that reversal the value does not match what the machine's own OS reports. It is **not** read from `CIM_ComputerSystem`, which has no such property. |
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
| `amt.domain_name` | `str` | when available | `AMT_GeneralSettings.DomainName`. |
| `amt.idle_wake_timeout` | `int` | when available | `AMT_GeneralSettings.IdleWakeTimeout`, in minutes. |
| `amt.ping_response_enabled` | `bool` | when available | `AMT_GeneralSettings.PingResponseEnabled` — ICMP echo. **This** is the ping toggle, not `amt.network.ip_sync_enabled`. |
| `amt.rmcp_ping_response_enabled` | `bool` | when available | `AMT_GeneralSettings.RmcpPingResponseEnabled`. |
| `amt.network_interface_enabled` | `bool` | when available | `AMT_GeneralSettings.NetworkInterfaceEnabled`. |
| `amt.ddns_update_enabled` | `bool` | when available | `AMT_GeneralSettings.DDNSUpdateEnabled`. |
| `amt.network.mac_address` | `str` | when available | `AMT_EthernetPortSettings.MACAddress` (instance 0), normalized to colon-separated lowercase. |
| `amt.network.mac_address_raw` | `str` | when available | `AMT_EthernetPortSettings.MACAddress` exactly as firmware reported it. Real AMT 10 firmware returns **dashes**. |
| `amt.network.ip_address` | `str` | when available | `AMT_EthernetPortSettings.IPAddress`. |
| `amt.network.subnet_mask` | `str` | when available | `AMT_EthernetPortSettings.SubnetMask`. |
| `amt.network.default_gateway` | `str` | when available | `AMT_EthernetPortSettings.DefaultGateway`. |
| `amt.network.primary_dns` | `str` | when available | `AMT_EthernetPortSettings.PrimaryDNS`. |
| `amt.network.secondary_dns` | `str` | when available | `AMT_EthernetPortSettings.SecondaryDNS`. |
| `amt.network.dhcp_enabled` | `bool` | when available | `AMT_EthernetPortSettings.DHCPEnabled`. |
| `amt.network.link_is_up` | `bool` | when available | `AMT_EthernetPortSettings.LinkIsUp`. |
| `amt.network.ip_sync_enabled` | `bool` | when available | `AMT_EthernetPortSettings.IpSyncEnabled` — whether AMT **shares the host OS's IP address**. Not a ping toggle. |
| `amt.network.link_policy` | `list[int]` | when available | Raw `AMT_EthernetPortSettings.LinkPolicy`. `null` if the property is absent, `[]` if present but empty. |
| `amt.network.link_policy_names` | `list[str]` | when available | `link_policy` decoded element-wise: `s0_ac` (1), `sx_ac` (2), `s0_dc` (14), `sx_dc` (15), `always_on` (16); anything else `unknown(<raw>)`. |
| `amt.network.wake_on_lan_capable` | `bool` | when available | Derived: whether `link_policy` contains `16`. `null` when `LinkPolicy` was not reported at all. |
| `amt.system_state.element_name` | `str` | when available | `CIM_ComputerSystem.ElementName` (read instead of `Name`, which is just the selector value). |
| `amt.system_state.enabled_state` | `int` | when available | Raw DMTF `CIM_ComputerSystem.EnabledState`. |
| `amt.system_state.enabled_state_text` | `str` | when available | `enabled_state` decoded per DMTF; see the table below. |
| `amt.system_state.requested_state` | `int` | when available | Raw DMTF `CIM_ComputerSystem.RequestedState`, undecoded on purpose. |
| `amt.system_state.operational_status` | `list[int]` | when available | Raw DMTF `CIM_ComputerSystem.OperationalStatus`. Always a list — CIM types it as an array. |
| `amt.system_state.operational_status_text` | `list[str]` | when available | `operational_status` decoded element-wise per DMTF; see the table below. |
| `amt.bios_version` | `str` | when available | `CIM_BIOSElement.Version` — the **host BIOS**, not the AMT firmware version (`amt.version`). Weakest-evidenced field this module returns. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | Always `get_facts`. |
| `operation.endpoint` | `str` | always | `host:port` this read was performed against. |
| `operation.changed` | `bool` | always | Always `false`. |
| `operation.previous` | `null` | always | Always `null` — a read-only module has no prior state to report. |
| `operation.desired` | `null` | always | Always `null` — a read-only module has no intended state to report. |
| `operation.observed` | `null` | always | Always `null`. See `amt` above instead, which carries the actual observed facts; it is not duplicated here. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 fingerprint of the TLS leaf certificate observed, or `null` over plaintext. |
| `operation.error_class` | `str` or `null` | always | `null` on success; a stable machine-readable failure class on failure. |

`amt_info` previously had neither the nested-`operation` shape nor the spread shape —
see [Capability matrix](capability-matrix.md). It now gets the same `operation` receipt
every other module in this collection returns, per issue #22, so that a caller can read
`error_class`/`tls_peer_fingerprint` uniformly regardless of which module produced the
result. `previous`/`desired`/`observed` are deliberately left `null` rather than
populated with something invented for a module that has no mutation to describe.

### `wake_on_lan_capable`: what both lab machines actually reported

`wake_on_lan_capable` is derived, not read: it is `true` only when
`AMT_EthernetPortSettings.LinkPolicy` contains `16`. **Both** lab machines report it
`false`, and they agree on why:

| | 16.1.30 (machine 1) | 19.0.5 (machine 2) |
|---|---|---|
| `network.link_policy` | `[1, 14]` | `[1, 14]` |
| `network.link_policy_names` | `["s0_ac", "s0_dc"]` | `["s0_ac", "s0_dc"]` |
| `16` ("network link always on") present? | **No** | **No** |
| `network.wake_on_lan_capable` | `false` | `false` |

`s0_ac` and `s0_dc` are both **S0** policies — S0 is the powered-on ACPI state — one
for AC power and one for battery. Read literally, that is AMT keeping its network
link up only while the host is already running.

> **The raw values are hardware fact; the value table interpreting them is not.**
> That both machines return `[1, 14]` is measured. The mapping of `1`, `14` and `16`
> to those meanings comes from `parmstro`'s constants table, corroborated by a single
> dump of *their* machine showing `[1, 14, 16]` — see `docs/protocol-notes.md` §2.7.
> No Intel documentation for this enum has been read directly, so the table is Tier 1
> only in the weak sense of "a third party's hardware", not "a vendor reference".
>
> There is a specific reason to hold it loosely. Intel's own AMT documentation states
> that after network access is activated, the power policy is set to
> *"ON in S0, ME Wake in S3, S4-5"* — a wake-capable policy — which does not sit
> comfortably beside an S0-only `LinkPolicy` on two freshly provisioned machines. Note
> also that `LinkPolicy` governs whether the network **link** is maintained, while the
> MEBx setting `Intel ME ON in Host Sleep States` governs whether the **ME itself** is
> powered; these interact but are not the same field, and this collection reads only
> the former.
>
> **Before acting on a `false` here, confirm it out of band**: the AMT Web UI's
> *Power Policies* page, or Intel Manageability Commander's `Power Policy` row, both
> report the active policy without a reboot. If those disagree with this field, the
> value table above is what is wrong, not the firmware.

**Why this is the field to check first when a power-on fails.** If that reading holds
in practice, `amt_power state=on` against a genuinely powered-off endpoint cannot
reach the management plane at all, and the failure arrives as
`error_class: connection` — the same shape as a wrong address, a dead switch port, or
a firewall rule. That is a diagnosis you will not reach by re-checking the inventory,
which is exactly why the field is surfaced. The example further down this page turns
it into a pre-flight warning.

**What has not been established.** Nothing in the hardware evidence shows whether
either machine can or cannot be woken from off by AMT. No qualification stage powers
a machine off, independently confirms it is off, and then tries to reach it. Machine
1's stage 4 did report an `off` transition and a restore, which sits awkwardly beside
an endpoint that is unreachable while off — most plausibly it was already off when the
stage began, making both transitions no-ops, but that is a reading of the result and
not something the result says. So: the policy value that would *guarantee* link-up-
while-off is absent on both machines, its absence is the first thing to suspect if a
remote power-on ever fails, and whether wake-from-off works here is untested. See
[Capability matrix](capability-matrix.md) Tier 4.

`null` rather than `false` still means something different and is worth keeping
straight: `LinkPolicy` was not reported at all, so nothing is known either way. Both
machines reported it, so neither is that case.

### DMTF state tables

`amt.system_state.enabled_state_text` (DMTF `CIM_EnabledLogicalElement.EnabledState`):

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| `unknown` | `other` | `enabled` | `disabled` | `shutting_down` | `not_applicable` | `enabled_but_offline` | `in_test` | `deferred` | `quiesce` | `starting` |

`amt.system_state.operational_status_text` (DMTF `CIM_ManagedSystemElement.OperationalStatus`):

| Value | Name | Value | Name |
|---|---|---|---|
| 0 | `unknown` | 10 | `stopped` |
| 1 | `other` | 11 | `in_service` |
| 2 | `ok` | 12 | `no_contact` |
| 3 | `degraded` | 13 | `lost_communication` |
| 4 | `stressed` | 14 | `aborted` |
| 5 | `predictive_failure` | 15 | `dormant` |
| 6 | `error` | 16 | `supporting_entity_in_error` |
| 7 | `non_recoverable_error` | 17 | `completed` |
| 8 | `starting` | 18 | `power_mode` |
| 9 | `stopping` | 19 | `relocating` |

A value outside either table renders as `unknown(<raw>)` rather than a bare `unknown`,
which both tables already use for the *defined* value `0`. The raw integer is always
reported alongside the decoded name.

### Round-trip cost

One `amt_info` invocation performs **ten WS-Man HTTP requests**: eight `Get` operations
plus an `Enumerate`/`Pull` pair for `CIM_SoftwareIdentity`.

| WS-Man operation | Verb | Sources |
|---|---|---|
| `AMT_GeneralSettings` | `Get` | `hostname`, `domain_name`, `idle_wake_timeout`, `ping_response_enabled`, `rmcp_ping_response_enabled`, `network_interface_enabled`, `ddns_update_enabled` |
| `AMT_SetupAndConfigurationService` | `Get` | `control_mode`, `provisioning_state` |
| `CIM_AssociatedPowerManagementService` | `Get` | `power_state`, `capabilities.power` |
| `AMT_BootCapabilities` | `Get` | `capabilities.boot_once_pxe`, `.sol`, `.storage_redirection` |
| `AMT_RedirectionService` | `Get` | `redirection_status` |
| `CIM_SoftwareIdentity` | `Enumerate`+`Pull` | `version` |
| `CIM_ComputerSystemPackage` | `Get` | `uuid` |
| `AMT_EthernetPortSettings` (instance 0) | `Get` | **new** — all of `network` |
| `CIM_ComputerSystem` (`Name=ManagedSystem`) | `Get` | **new** — all of `system_state` |
| `CIM_BIOSElement` | `Get` | **new** — `bios_version` |

That is three more round trips than 0.1.0 made, and being blunt about one of them: the
`CIM_ComputerSystem` read was **deliberately removed** in 0.1.0, with the changelog
noting that "it existed only to source the UUID and contributed nothing else, so removing
it also saves a WS-Man round trip per call." It is back. The justification is not that the
saving did not matter — it is that the class now sources three genuinely useful state
fields (`EnabledState`, `RequestedState`, `OperationalStatus`) plus `ElementName`, rather
than a `UUID` property it never had. `amt.uuid` still comes from
`CIM_ComputerSystemPackage.PlatformGUID` and is deliberately not read here.

`CIM_BIOSElement` may cost one further `Enumerate`/`Pull` pair, but only on firmware where
the bare `Get` faults.

The three new reads all use `Get` with an explicit selector where the class has one.
`Enumerate` is not used for any of them: on AMT 10 it returns HTTP 400 for
`AMT_EthernetPortSettings` and several other `AMT_`-prefixed classes, while a `Get` with an
exact selector works — see [protocol notes §2.7](protocol-notes.md#27-network-and-system-state-facts).

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

Diagnosing the failure mode that looks like a network fault but is not:

```yaml
- name: Read AMT facts before trying to power a machine on
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt

- name: Warn when this endpoint will not answer WS-Man while powered off
  ansible.builtin.debug:
    msg: >-
      LinkPolicy is {{ amt.amt.network.link_policy }} and lacks 16 (network link always on),
      so this endpoint drops off the network when the host powers down. A subsequent
      `amt_power state=on` will fail looking like a connection fault rather than a
      configuration one.
  when:
    - amt.amt.network is not none
    - amt.amt.network.wake_on_lan_capable is false
```

Cross-checking identity against a second, independent anchor:

```yaml
- name: Refuse to act unless both identity anchors match the reviewed inventory binding
  ansible.builtin.assert:
    that:
      - amt.amt.uuid == amt_expected_uuid
      - amt.amt.network.mac_address == (amt_expected_mac | lower)
    fail_msg: >-
      Endpoint evidence disagrees with inventory. Do not proceed: a reset issued against
      the wrong machine is not recoverable from Ansible.
  when: amt_expected_uuid is defined and amt_expected_mac is defined
```

`amt.network.mac_address` is normalized to colon-separated lowercase precisely so a
comparison like that one works; compare against `mac_address_raw` only if you deliberately
want to detect a change in how the firmware formats it.

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
- This module is **hardware-qualified against AMT 16.1.30 and AMT 19.0.5** — the two
  lab machines both ran it in stages 1 and 8, and on both the firmware version, all
  four capability flags, redirection state, power state and platform UUID came back
  from real firmware. It remains unverified on every generation other than those two
  — see the [Capability matrix](capability-matrix.md).
- **The network and system-state facts are hardware-verified on both lab
  generations.** `amt.network`, `amt.system_state`, `amt.bios_version` and the six
  extra `AMT_GeneralSettings` fields came back **fully populated** from real AMT
  19.0.5 and real AMT 16.1.30 firmware on 2026-07-29 — nothing `null`, no class
  faulted, on either. Their property names were originally derived from *someone
  else's* AMT 10.0.56 hardware dump (`parmstro`, GPL-3.0-or-later), so these fields
  now rest on evidence spanning three firmware generations: named on 10.0.56, read
  back populated here on 16.1.30 and 19.0.5. Every generation outside those three
  is still unverified for them. See [Capability matrix](capability-matrix.md) Tier 3.
- **Whether this module can be reached at all while the target is powered off is
  untested**, and both lab machines report `wake_on_lan_capable: false` — see the
  subsection above. That is the expected explanation for a remote power-on failing
  with `error_class: connection`; it is not a demonstration that wake-from-off is
  broken, because no test has tried it.
- `amt.system_state.operational_status` is an **array** (`uint16[]`), hardware-
  confirmed as such by both lab generations returning a single-element list. Do not
  treat it as a scalar even where only one element is present.
- `amt.bios_version` was the weakest-evidenced field in the module and is much less
  so now. The source notes claim `CIM_BIOSElement` works on AMT 10.0.56 but record
  no dumped value, and the implementation they claim it from swallows failure to
  `None`, so their result proves nothing either way. Both lab generations have now
  returned a value. `null` remains legitimate on firmware that does not expose the
  class, which is why it is still read through the optional path.
- `amt.network` covers `AMT_EthernetPortSettings` **instance 0 only**. Multi-NIC parts
  expose higher indices; this module does not look for them, and an endpoint with no
  instance 0 reports `amt.network: null` rather than failing.
- `AMT_GeneralSettings.PowerSource` and `PrivacyLevel` are read by the same `Get` that
  supplies `amt.hostname` but are deliberately **not** surfaced: both were dumped as
  `0`, and nothing documents what their integers mean. An uninterpretable number in a
  return value invites someone to invent a meaning for it.
- IPv6 is not reported. `AMT_EthernetPortSettings` carries IPv6 properties; nothing in
  the available hardware evidence dumps them, so they are not claimed here.

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
`amt_info` takes one module-specific option: `gather_subset`, added in 0.5.0. See
[Hardware/asset inventory](#hardwareasset-inventory-gather_subset) below.

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `gather_subset` | `list` of `str` | `["config"]` | no | `all`, `min`, `config`, `hardware`, `system`, `processor`, `memory`, `storage`, plus each of those prefixed with `!` |
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
| `amt.network.link_policy_names` | `list[str]` | when available | `link_policy` decoded element-wise: `s0_ac` (1), `sx_ac` (14), `s0_dc` (16), `sx_dc` (224); anything else `unknown(<raw>)`. |
| `amt.network.wake_on_lan_capable` | `bool` | when available | Derived: whether `link_policy` contains an **Sx** value — `14` (Sx AC) or `224` (Sx DC). `null` when `LinkPolicy` was not reported at all. |
| `amt.system_state.element_name` | `str` | when available | `CIM_ComputerSystem.ElementName` (read instead of `Name`, which is just the selector value). |
| `amt.system_state.enabled_state` | `int` | when available | Raw DMTF `CIM_ComputerSystem.EnabledState`. |
| `amt.system_state.enabled_state_text` | `str` | when available | `enabled_state` decoded per DMTF; see the table below. |
| `amt.system_state.requested_state` | `int` | when available | Raw DMTF `CIM_ComputerSystem.RequestedState`, undecoded on purpose. |
| `amt.system_state.operational_status` | `list[int]` | when available | Raw DMTF `CIM_ComputerSystem.OperationalStatus`. Always a list — CIM types it as an array. |
| `amt.system_state.operational_status_text` | `list[str]` | when available | `operational_status` decoded element-wise per DMTF; see the table below. |
| `amt.bios_version` | `str` | when available | `CIM_BIOSElement.Version` — the **host BIOS**, not the AMT firmware version (`amt.version`). Weakest-evidenced field this module returns. |
| `amt.hardware` | `dict` or `null` | when a hardware `gather_subset` was requested | Hardware/asset inventory. `null` unless opted into — which is not the default. See [Hardware/asset inventory](#hardwareasset-inventory-gather_subset) for the full field list, the value-table provenance, and the three-state contract for each group. |
| `amt.hardware.chassis` | `dict` or `null` | subset `system` | `CIM_Chassis` — the **system serial number**, model, manufacturer, version, `tag`, and both package-type enumerations. |
| `amt.hardware.baseboard` | `dict` or `null` | subset `system` | `CIM_Card` — the baseboard's model, manufacturer, version, `can_be_frued`, package type, and its own `serial_number`. **`serial_number` is `null` on both lab machines** even though the rest of the class populates, so do not build on it; see [Limits](#limits-what-amt-does-not-expose-on-these-classes) and issue #84. |
| `amt.hardware.processors` | `list[dict]` or `null` | subset `processor` | `CIM_Processor`, one entry per **physical package**. Clocks, socket (`upgrade_method`), stepping, status. No core or thread count — AMT does not expose one. `family` is raw and undecoded. |
| `amt.hardware.chips` | `list[dict]` or `null` | subset `processor` | `CIM_Chip`. `version` here is the **human-readable processor name**, which `CIM_Processor` cannot supply. Reported unfiltered: `CIM_PhysicalMemory` is a subclass, so memory chips may appear — use `element_name` to tell them apart. |
| `amt.hardware.memory` | `list[dict]` or `null` | subset `memory` | `CIM_PhysicalMemory`, one entry per DIMM. `capacity_bytes`, `memory_type`/`_text`, bank label, part/serial number. `form_factor` is raw and undecoded; read the speed-field trap below before using `speed_ns`. |
| `amt.hardware.storage` | `list[dict]` or `null` | subset `storage` | `CIM_MediaAccessDevice`, one entry per disk. `device_id`, `max_media_size_kb` (KBytes, unconverted), `capabilities`/`_text`, `security`/`_text`. No model, vendor or serial — the class carries none. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | Always `get_facts`. |
| `operation.endpoint` | `str` | always | `host:port` this read was performed against. |
| `operation.changed` | `bool` | always | Always `false`. |
| `operation.previous` | `null` | always | Always `null` — a read-only module has no prior state to report. |
| `operation.desired` | `null` | always | Always `null` — a read-only module has no intended state to report. |
| `operation.observed` | `null` | always | Always `null`. See `amt` above instead, which carries the actual observed facts; it is not duplicated here. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 fingerprint of the TLS leaf certificate observed, or `null` over plaintext. |
| `operation.error_class` | `str` or `null` | always | `null` on success; a stable machine-readable failure class on failure. |
| `operation.gather_subset` | `list[str]` | always | **New in 0.5.0.** What `gather_subset` actually resolved to, sorted. Worth checking when `!`-negation is in play: `['!memory']` resolves to everything but memory, which is *more* than the default. |
| `operation.wsman_requests_estimated` | `int` | always | **New in 0.5.0.** Best-case WS-Man HTTP request count for the resolved subsets. "Best case" is load-bearing — a faulting `Get` costs a further `Enumerate`/`Pull` pair on top. |
| `operation.hardware_reads` | `dict` | when a hardware subset was requested | **New in 0.6.0.** What happened when each inventory class was read, keyed by WS-Man class name. Each entry carries `fact_group` (which `amt.hardware` key the result was filed under), `outcome` (`read`/`empty`/`absent`), `verb` (`Get`/`Enumerate`), `instances`, and `error_class` when refused. Diagnostics **alongside** the facts, never instead of them — an unreadable class still yields `null`. See [Three distinguishable outcomes per fact group](#three-distinguishable-outcomes-per-fact-group). |
| `operation.hardware_reads[<class>].property_shapes` | `dict` or `null` | `CIM_Chassis` and `CIM_Card` only | **New in 0.7.0.** Per-property census of the instance that was read: property name → one of `absent`, `empty`, `text`, `nested`, `repeated`. **Names and shapes only — no property value appears here, in any form.** `null` when there was no instance to census, which is not the same as a census in which everything is `absent`. See [Why one `null` field is not the same as a `null` class](#why-one-null-field-is-not-the-same-as-a-null-class). |
| `operation.hardware_reads[<class>].property_names_dropped` | `int` | `CIM_Chassis` and `CIM_Card` only | **New in 0.7.0.** How many property names were withheld from `property_shapes` for not being CIM identifiers. Normally `0`; anything else means a firmware sent a shape nobody has seen. |

`amt_info` previously had neither the nested-`operation` shape nor the spread shape —
see [Capability matrix](capability-matrix.md). It now gets the same `operation` receipt
every other module in this collection returns, per issue #22, so that a caller can read
`error_class`/`tls_peer_fingerprint` uniformly regardless of which module produced the
result. `previous`/`desired`/`observed` are deliberately left `null` rather than
populated with something invented for a module that has no mutation to describe.

### `wake_on_lan_capable`: what it means and what both lab machines report

`wake_on_lan_capable` is derived, not read. It is `true` when
`AMT_EthernetPortSettings.LinkPolicy` contains an **Sx** value — `14` (Sx AC) or `224`
(Sx DC) — meaning AMT maintains the network link while the host is *not* in S0: asleep,
hibernating, or off. `LinkPolicy` crosses two axes, ACPI state (S0 versus any Sx) and
power source (AC versus DC), and its four values are the whole enum:

| Value | Meaning | Implies reachable while off? |
|---|---|---|
| `1` | available on S0 AC — powered on, mains | No |
| `14` | available on Sx AC — asleep/off, mains | **Yes** |
| `16` | available on S0 DC — powered on, battery | No |
| `224` | available on Sx DC — asleep/off, battery | **Yes** |

The table is vendor-sourced: `device-management-toolkit/go-wsman-messages`
`pkg/wsman/amt/ethernetport`. See [Protocol notes](protocol-notes.md) §2.7 for the
citation and for the correction history — 0.2.0 and 0.3.0 shipped a wrong table
transcribed from a third party and returned the **inverse** of this field on
mains-powered hardware.

**Both** lab machines report `[1, 14]`, so both are `true`:

| | 16.1.30 (machine 1) | 19.0.5 (machine 2) |
|---|---|---|
| `network.link_policy` | `[1, 14]` | `[1, 14]` |
| `network.link_policy_names` | `["s0_ac", "sx_ac"]` | `["s0_ac", "sx_ac"]` |
| An Sx value present? | **Yes** (`14`) | **Yes** (`14`) |
| `network.wake_on_lan_capable` | `true` | `true` |

Firmware configuration on one of these machines was checked independently: its MEBx
`ME ON in Host Sleep States` is set to *"Desktop: ON in S0, ME Wake in S3, S4-5"* — the
wake-capable option — and its `Idle Timeout` reads `65535`, matching the
`idle_wake_timeout` this module reports. So the MEBx screen and the corrected
`LinkPolicy` table agree with each other, and it was the old derivation that disagreed
with both. Note that `LinkPolicy` governs whether the network **link** is maintained
while the MEBx setting governs whether the **ME itself** is powered; they are related
but not the same field, and this module reads only the former.

**Why this is still the field to check first when a power-on fails.** An endpoint whose
`LinkPolicy` carries no Sx value cannot be reached over WS-Man once the host leaves S0.
`amt_power state=on` against it fails as `error_class: connection` — the same shape as a
wrong address, a dead switch port, or a firewall rule. That is a diagnosis you will not
reach by re-checking the inventory, which is exactly why the field is surfaced. The
example further down this page turns it into a pre-flight warning. A `true` here is not a
guarantee that a wake will succeed; it is the removal of one specific, easily-missed
explanation for why it did not.

**What has not been established.** No qualification stage powers a machine off,
independently confirms it is off, and then tries to reach it, so reachability-while-off
remains empirically untested on both machines — the evidence now points *towards* it
rather than against it, which is a different thing from having measured it. Machine 1's
stage 4 did report an `off` transition and then a successful restore; under the old table
that sat awkwardly beside "unreachable while off", and with `14` = Sx AC it reconciles
cleanly. See [Capability matrix](capability-matrix.md) Tier 4.

**About the name.** This field reads only `LinkPolicy`. AMT's own wake plumbing — the
MEBx sleep-state setting, `IdleWakeTimeout`, a magic packet actually arriving — is
adjacent but distinct, so `wake_on_lan_capable` is an approximate name for "the link is
maintained outside S0". It is kept regardless: it shipped in 0.2.0 and 0.3.0 and removing
a return key is a breaking change, and a correct field under an imperfect name is better
than two fields whose difference a caller has to look up.

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

## Hardware/asset inventory (`gather_subset`)

**New in 0.5.0, and opt-in.** Because AMT runs beneath the host operating system, it
can report a machine's serial number, model, manufacturer, baseboard, processors, DIMMs
and disks **while that machine is powered off** — which is frequently the only way to
get them. Where an agent is running, use `ansible.builtin.setup`. Where one is not, AMT
is the only source of truth.

That distinction is not this collection's invention. MeshCentral fetches exactly this
batch of classes only when the device group is **AMT-only** — `amtmanager.js`'s
`attemptFetchHardwareInventory()` is gated on `mesh.mtype == 1`, i.e. a group of
machines with no agent to ask instead.

### Why an option on `amt_info` rather than a separate `amt_hardware_info` module

Two modules for "tell me about this endpoint" is a worse interface than one module with
a subset selector, and `gather_subset` is a vocabulary every Ansible user already knows
from `ansible.builtin.setup`. The honest counter-argument, recorded because it is real:
`gather_subset` is overwhelmingly a **facts**-module idiom (`setup` and the network
`*_facts` modules), and the closest domain analogue —
`community.general.redfish_info`, which gathers this same class of hardware inventory
out-of-band over Redfish — chose `category`/`command` instead. So this is deliberately
the more *familiar* name over the closest *precedent*, and that trade is only defensible
if the familiar semantics are honoured in full. They are; see below.

Note this module returns everything under `amt` in the result dictionary and puts
**nothing** into `ansible_facts`. That is the `_info` versus `_facts` convention, and it
is unaffected by borrowing `setup`'s option name.

### Subsets and what each costs

| Subset | Classes read | Verb | Requests | Populates |
|---|---|---|---|---|
| `config` | the ten in [Round-trip cost](#round-trip-cost) below | — | **10** | everything `amt_info` returned before 0.5.0 |
| `system` | `CIM_Chassis`, `CIM_Card` | `Get` | **2** | `amt.hardware.chassis`, `amt.hardware.baseboard` |
| `processor` | `CIM_Processor`, `CIM_Chip` | `Enumerate`+`Pull` | **4** | `amt.hardware.processors`, `amt.hardware.chips` |
| `memory` | `CIM_PhysicalMemory` | `Enumerate`+`Pull` | **2** | `amt.hardware.memory` |
| `storage` | `CIM_MediaAccessDevice` | `Enumerate`+`Pull` | **2** | `amt.hardware.storage` |
| `hardware` | alias for `system` + `processor` + `memory` + `storage` | — | **10** | all of `amt.hardware` |
| `all` | `config` + `hardware` | — | **20** | everything |
| `min` | `config` | — | **10** | everything `amt_info` returned before 0.5.0 |

`system`'s two reads are bare `Get`s with an `Enumerate` fallback, so that subset can
cost up to **6** on firmware that refuses `Get` for both classes — the same shape as
`CIM_BIOSElement` in the `config` set. An `Enumerate` costs one further `Pull` per 64
instances beyond the first; no realistic machine reaches that, but the arithmetic is
stated rather than assumed. The receipt reports the best-case figure as
`operation.wsman_requests_estimated`, and what the subset list actually resolved to as
`operation.gather_subset`.

Two subsets deliberately cover **two classes each**, because asking for one without the
other is always a mistake:

- `system` — a chassis serial without a baseboard serial cannot tell a board swap from
  a re-rack, and the two are genuinely different values on the vendor's recorded
  firmware response. **On both lab machines the baseboard serial is empty**, so that
  particular inference is not available there — but the rest of `CIM_Card` is, and
  keeping the two classes in one subset is still right: reading a board's manufacturer,
  model and version alongside the chassis is what makes the gap visible instead of
  invisible. See the limits section below.
- `processor` — `CIM_Processor` carries clocks, socket and stepping but identifies the
  part only by a `Family` integer this collection **does not decode** (see below).
  `CIM_Chip.Version` is what carries the human-readable processor name. Neither is
  useful alone.

### Resolution semantics

Identical to `ansible.builtin.setup`, deliberately, because that is the entire
justification for reusing the option's name. In order:

1. `all` adds every subset.
2. `min` adds the minimal subset (`config`).
3. `!all` excludes everything **except** `config`.
4. `!min` and `!config` are **inert** — see below.
5. `!<name>` excludes that subset; `!hardware` removes exactly what `hardware` adds.
6. If the list contains **no positive entry**, every subset is added *first* and the
   exclusions applied to that. So `gather_subset: ['!memory']` means "everything except
   memory" and costs **18** requests — *more* than the default, not less. Surprising the
   first time, but it is what `setup` does and what a `setup` user's habits will expect.
   Pass `config` explicitly if the default cost is what you want.
7. Exclusions are applied **last**, so a contradiction resolves in favour of the
   exclusion: `['all', '!memory']` gathers everything but memory.

`config` is the minimal subset and therefore **cannot be excluded**. `!min` and
`!config` are inert exactly as `!min` is inert in `setup`. This is load-bearing rather
than incidental: it means **no value of `gather_subset` can remove a key `amt_info`
returned before 0.5.0**, so the option cannot break an existing caller, and
`roles/amt_baremetal_install`, the integration targets and `tests/hardware` all keep
working unchanged.

An unrecognised subset name is rejected by argument validation (`choices` on the
argument spec) **before any connection is attempted** — the same treatment `state` gets
on `amt_power` and `amt_boot`.

### The one deliberate divergence from `setup`: the default

`setup` defaults to gathering everything. **This module defaults to `config` only.**
Gathering everything here costs ten extra WS-Man round trips against firmware, and no
existing caller should start paying for inventory they never asked for. A reader who
knows `setup` will otherwise assume they are getting everything, so it is stated
plainly here, in the module's own documentation, and in the option description.

### Three distinguishable outcomes per fact group

`amt.hardware` is `null` when no hardware subset was requested at all. Within it, each
key is present **only** if its subset was requested, which gives three separate answers
that operators genuinely need to tell apart:

| Reading | Means | Confirm it with |
|---|---|---|
| `amt.hardware is none` | **no hardware subset was requested at all** — no inventory request was issued | `operation.hardware_reads` is absent |
| `'memory' not in amt.hardware` | that subset was not requested — nothing was asked of the endpoint for it | `CIM_PhysicalMemory` is absent from `operation.hardware_reads` |
| `amt.hardware.memory is none` | requested, but the class faulted or this firmware does not implement it | `operation.hardware_reads['CIM_PhysicalMemory'].outcome == 'absent'`, with `error_class` naming the refusal |
| `amt.hardware.memory == []` | the class answered with **zero** instances — a real reading of a diskless or unpopulated machine, not a gap | `operation.hardware_reads['CIM_PhysicalMemory'].outcome == 'empty'` |

Each of the six groups degrades **independently**: a firmware that cannot enumerate
disks still reports its DIMMs, its processors and its serial number. A missing class is
never a module failure — same contract `amt_info` already applies to
`AMT_EthernetPortSettings` and `CIM_BIOSElement`.

**Read the third column.** The first two rows both render as a bare `null`/absent key and
are easy to mistake for one another, and the difference between "I never asked" and "I
asked and this firmware cannot answer" is the whole point of the distinction.
`operation.hardware_reads` is what makes each row checkable rather than inferred, and it
exists because that exact confusion happened: the first hardware run's summary read
`amt.hardware.system` and `amt.hardware.processor` — key names this module has never
emitted, since `system` and `processor` are *subset* names and the *fact groups* they
populate are `chassis`+`baseboard` and `processors`+`chips` — and `| default(none)` turned
those undefined lookups into four convincing `null`s while firmware had returned every
group populated.

**So: never index `amt.hardware` by a `gather_subset` name.** There is no
`amt.hardware.system` and no `amt.hardware.processor`. The six keys are `chassis`,
`baseboard`, `processors`, `chips`, `memory` and `storage`, and
`operation.hardware_reads[<class>].fact_group` states the mapping for every class in
every response.

### Why one `null` field is not the same as a `null` class

The table above is about a whole fact **group** being `null`. A different reading, which
`outcome` cannot describe at all, is a single `null` **field** on a class that answered
perfectly: `amt.hardware.baseboard.serial_number` is `null` on both lab machines while
`model`, `manufacturer`, `version`, `can_be_frued` and `package_type` all populate and
`outcome` is `read`.

`null` there has four possible causes, and they are exactly the inputs this collection's
string coercion refuses:

| `property_shapes[<Property>]` | Firmware sent | Whose limitation |
|---|---|---|
| `absent` | no such element in the response | firmware's — `null` is the honest answer |
| `empty` | the element, carrying no text | firmware's — a different answer, and a different fact about the firmware |
| `text` | the element with text in it | **nobody's — if the fact is still `null`, this is a contradiction and one of the two is wrong** |
| `nested` | the element, carrying child elements | **this collection's** — the coercion refuses a mapping, so a value that arrived was dropped |
| `repeated` | the element more than once | **this collection's** for a scalar property; expected for a CIM array |

Two consequences worth being explicit about:

- **A one-element CIM array reads `text`, not `repeated`.** The parser collapses a lone
  repeated element to a bare string, so that is genuinely what reached the coercion. The
  census reports the shape the parser saw, not the shape the schema declares — reporting
  the schema's would make it lie about which shape produced the `null`.
- **The census is scoped to `CIM_Chassis` and `CIM_Card`.** A census is a statement about
  one instance, so a multi-instance class would need one per DIMM and grow the receipt
  with the machine rather than with the question. Those two are also the pair whose
  asymmetry is the open question, so having both censuses in one receipt *is* the finding.

Property names firmware sent that this collection does not read are included, deliberately:
"the board serial arrives under a property we never look at" is a live hypothesis for #84,
and the census is the only place it would be visible.

### Value tables: where every mapping came from

This is the part of the feature most likely to be wrong, and this project has the scar
tissue to prove it — `LinkPolicy` shipped inverted in 0.2.0 and 0.3.0 from a
transcribed constants table, and neither the mock tier nor the hardware tier could
catch it (see [Capability matrix](capability-matrix.md)). So: **every table below is
transcribed from `device-management-toolkit/go-wsman-messages` at tag `v2.48.3` or from
the DMTF CIM schema. None is inferred from a hardware dump.** A dump proves a value was
*returned*; it can never establish what the value *means*.

| Property | Values | Source |
|---|---|---|
| `CIM_Chassis.ChassisPackageType` | 37 (0–36) | `pkg/wsman/cim/chassis/decoder.go` — `ChassisPackageType` const block + `chassisPackageTypeToString` |
| `PackageType` (on chassis **and** card) | 18 (0–17) | `pkg/wsman/cim/chassis/decoder.go` and `pkg/wsman/cim/card/decoder.go` — `packageTypeMap`, byte-identical in both |
| `CIM_PhysicalMemory.MemoryType` | 37 (0–36) | `pkg/wsman/cim/physical/decoder.go` — `memoryTypeMap` |
| `CIM_MediaAccessDevice.Capabilities` | 13 (0–12) | `pkg/wsman/cim/mediaaccess/decoder.go` — `capabilitiesToString`, corroborated by the DMTF `ValueMap`/`Values` annotation inline in that package's `types.go` |
| `CIM_MediaAccessDevice.Security` | 7 (1–7) | `pkg/wsman/cim/mediaaccess/decoder.go` — `securityToString`, likewise corroborated by the inline DMTF annotation |
| `CIM_MediaAccessDevice.EnabledDefault` | 6 (sparse) | `pkg/wsman/cim/mediaaccess/decoder.go` — `enabledDefaultToString` |
| `CIM_Processor.CPUStatus` | 6 (0–5) | `pkg/wsman/cim/processor/decoder.go` — `cpuStatusMap` |
| `CIM_Processor.HealthState` | 7 (sparse, steps of 5) | `pkg/wsman/cim/processor/decoder.go` — `healthStateMap` |
| `CIM_Processor.UpgradeMethod` | 85 (0–84) | `pkg/wsman/cim/processor/decoder.go` — `upgradeMethodMap` |
| `EnabledState` (processor, storage) | 11 (0–10) | **DMTF `CIM_EnabledLogicalElement`**, the full standard table this collection already holds for `CIM_ComputerSystem` — see below |
| `OperationalStatus` (all six classes) | 20 (0–19) | **DMTF `CIM_ManagedSystemElement`**, likewise already held |

Three points worth stating rather than leaving implicit:

- **`EnabledState` is decoded with the DMTF table, not the vendor library's.**
  `go-wsman-messages`' `pkg/wsman/cim/processor/decoder.go` `enabledStateMap` **omits
  values 0, 1 and 2**, so its own decoder answers "Value not found in map" for its own
  captured firmware response, which reports `EnabledState` 2. Its `mediaaccess` copy of
  the same enumeration *is* complete and agrees with DMTF exactly — which is what makes
  the processor one identifiable as an omission rather than a disagreement. The full
  DMTF table is used for both.
- **`EnabledState` and `OperationalStatus` exist in exactly one place** in the codebase
  (`plugins/module_utils/models.py`), imported by the inventory code rather than
  redeclared. A value table that exists twice can drift against itself, which is
  precisely the `LinkPolicy` failure mode.
- **A value outside a table renders `unknown(<raw>)`**, never a bare `unknown` — most
  of these enumerations define `0` as `unknown`, and "firmware said 0" and "firmware
  said something this table has never heard of" are different findings. The raw integer
  is always reported alongside every decoded name.

### What is reported raw and undecoded, and why

Where no table could be sourced, the raw integer ships with **no name attached**.
Shipping a raw integer is honest; shipping a confident wrong label is what the 0.3.1
release cycle was spent undoing.

| Property | Why undecoded |
|---|---|
| `CIM_Processor.Family` | `go-wsman-messages` types it as a plain `int` and defines **no** map for it — there is no `familyMap` anywhere in the library. The DMTF `Family` ValueMap runs to several hundred entries and no offline copy of the CIM schema was available to transcribe it from. Real firmware reports `198`; what 198 *means* is exactly the sort of claim this project has twice got wrong by guessing. Use `amt.hardware.chips[].version` for the processor's actual name. |
| `CIM_PhysicalMemory.FormFactor` | The sharper case. Also typed a plain `int` with no map, and **two published tables disagree about the value real firmware actually reports**: the recorded response says `13`, which is `SODIMM` under the SMBIOS type-17 form-factor enumeration but `SRIMM` under the DMTF `CIM_PhysicalMemory.FormFactor` ValueMap. The part in that response *is* a SODIMM, so SMBIOS looks right — but "looks right on one machine" is a hardware-dump inference, which is the one form of evidence that cannot establish a meaning. |
| `RequestedState` (processor, storage) | Consistent with how `amt_info` already reports `amt.system_state.requested_state`: raw. Tables do exist in the vendor library for both classes, but the processor one omits value 0, and this collection has already chosen not to publish an unverified decode for the identical property on a sibling class. Reporting the same property two different ways in one module's output would be worse than reporting it plainly in both. |

### Properties that do not exist, and are therefore not reported

Each of these is something an operator might reasonably expect and AMT does not
provide. Stated explicitly so nobody concludes it was overlooked:

- **No asset tag.** `CIM_Chassis` has no `AssetTag` property — the string does not occur
  anywhere in `go-wsman-messages`. What exists is `Tag`, reported as
  `amt.hardware.chassis.tag`, whose DMTF description says it "can contain information
  such as asset tag or serial number data". Real firmware puts the literal class name in
  it — `CIM_Chassis` on the chassis and `CIM_Card` on the baseboard, on **both** lab
  machines as well as on the vendor's recorded response — carrying no asset information
  at all. It is reported because it is what firmware sends, and deliberately **not**
  named `asset_tag`.
- **No processor core or thread count.** `CIM_Processor` as AMT implements it exposes
  `DeviceID`, `Role`, `Family`, `OtherFamilyDescription`, `UpgradeMethod`,
  `MaxClockSpeed`, `CurrentClockSpeed`, `ExternalBusClockSpeed`, `Stepping`,
  `CPUStatus`, `HealthState`, `EnabledState`, `RequestedState`, `OperationalStatus` and
  the four key properties — and nothing else. DMTF's `CIM_Processor` defines
  `NumberOfEnabledCores` in later schema versions; AMT's implementation does not expose
  it. There is one instance per **physical package**, so a two-socket machine returns
  two entries, not one per core.
- **No disk model, vendor or serial.** `CIM_MediaAccessDevice` carries none of them, and
  its `ElementName` is the constant string `Managed System Media Access Device` on every
  instance, so that identifies nothing either. What distinguishes one disk from another
  is `device_id` (`MEDIA DEV 0`, `MEDIA DEV 1`) and `max_media_size_kb`. A disk model
  number is not obtainable from AMT through this class.
- **`CIM_PhysicalPackage` is not read at all.** `CIM_Card` and `CIM_Chassis` are both
  subclasses of it, and the recorded `Enumerate` of `CIM_PhysicalPackage` returns a
  `CIM_Card` instance — so reading it would return the same instances under a third
  resource URI, costing a round trip for no information.
- **No baseboard serial number on the lab firmware.** This one is a *property* that
  exists and is simply not filled in, rather than a property AMT lacks, so it is the
  odd entry in this list — but the practical effect is the same. `CIM_Card.SerialNumber`
  is declared, the vendor's own recorded response carries a value for it, and **both lab
  machines return nothing for it** while returning `manufacturer`, `model`, `version`,
  `can_be_frued` and `package_type` normally, and while `CIM_Chassis.SerialNumber`
  populates.

  Which of the two firmware is doing is **now visible, and was not before 0.7.0**.
  `optional_str()` maps four different findings onto one `null` — element absent, element
  present but empty, element carrying child elements, element repeated — and every
  evidence artifact is already-parsed module output, taken after that collapse. This was
  previously described here as needing a raw SOAP body to settle. It does not:
  `operation.hardware_reads['CIM_Card'].property_shapes['SerialNumber']` reports which of
  the four it was, because the parsed instance still carries the distinction (an omitted
  element has no key; an empty one has a key holding `""`) and the census is taken before
  the coercion runs. Tracked as issue **#84**, which stays open until a hardware run
  reports that value.

  Two of the four shapes would change who is at fault. `absent` or `empty` means firmware
  is not supplying a board serial and `null` is the honest answer. `nested` or `repeated`
  would mean firmware sent something and **this collection dropped it** — a defect here,
  not a firmware limitation.

  **The consequence is worth stating plainly, because the `system` subset's own
  documentation claims otherwise above:** a chassis serial plus a board serial is what
  tells a board swap from a re-rack. On this firmware only the chassis serial is
  available, so that inference cannot be made here. Treat
  `amt.hardware.baseboard.serial_number` as optional in anything you build.

### Two unit traps worth reading before using these values

- **Memory speed is four fields and nothing is derived from them.**
  `CIM_PhysicalMemory.IsSpeedInMhz` selects which property holds the speed, and the two
  are in **different units**: `true` means the speed is `max_memory_speed_mhz` in MHz,
  `false` means it is `speed_ns` in nanoseconds. Real firmware has been recorded
  reporting `Speed` as `0` with `IsSpeedInMhz` `true`, so anything reading `Speed`
  naively reports every DIMM on that machine as zero. No single derived `speed` field is
  offered, because there is no honest value for it in the `false` branch — the
  arithmetically correct conversion (1000/ns) is not the memory clock rate anyone is
  looking for. `configured_clock_speed_mhz` is what the DIMM is *actually* clocked at,
  which may be below its rated speed.
- **`max_media_size_kb` is KBytes and is not converted.** The class definition says
  KBytes. The recorded values `960197124` and `500107862` read as a 960 GB and a 500 GB
  device under KB = 1000, which is suggestive — but nothing establishes whether firmware
  means 1000 or 1024, and a `_bytes` field would silently bake that guess in at a 2.4%
  error. Convert it yourself, knowing you are choosing.

Likewise `capacity_bytes` on a DIMM **is** bytes, per the class definition and
corroborated by the recorded value being exactly 16 GiB.

### Verification status

**Hardware-verified for existence and shape; the decoded labels remain
source-cited.** All six classes were read from real Intel AMT firmware on both lab
machines — **AMT 16.1.30 and 19.0.5** — and all six fact groups came back populated.
Stage 1b of `tests/hardware/qualify_readonly.yml`, CircleCI pipeline 167, job UUID
`65ddc061-b273-4777-8c51-174a48e74402`. See
[Capability matrix](capability-matrix.md) Tier 3, "`amt_info`'s hardware/asset inventory",
for the per-class table and the run citation.

What that does **not** establish is what any decoded *label* means. A dump proves a value
was returned and never what it signifies — the mistake that left `wake_on_lan_capable`
inverted for two releases — so every mapping above stays sourced from
`go-wsman-messages` and the DMTF schema, with the raw integer reported alongside. That
convention immediately earned its keep: AMT 19.0.5 returned
`CIM_Processor.UpgradeMethod` = `85`, one past the end of the vendor's own 0-84 table,
and it renders `unknown(85)` with the raw value intact rather than as a guessed socket
name.

Two observed limits on real firmware, both documented above rather than buried here:

- **`baseboard.serial_number` is `null` on both machines** while `chassis.serial_number`
  populates. `CIM_Card` is otherwise fully readable. Tracked as issue #84 — and as of
  0.7.0 the next hardware run reports *why*, in
  `operation.hardware_reads['CIM_Card'].property_shapes['SerialNumber']`.
- **`operational_status` is `[0]` (`"unknown"`) wherever it appears**, and absent
  entirely on `CIM_PhysicalMemory`. Reported as received; infer no health from it.

## Round-trip cost

The `config` subset — the default, and everything `amt_info` returned before 0.5.0 —
performs **ten WS-Man HTTP requests**: eight `Get` operations plus an `Enumerate`/`Pull`
pair for `CIM_SoftwareIdentity`. Hardware subsets add to this and are listed under
[Subsets and what each costs](#subsets-and-what-each-costs) above.

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
      LinkPolicy is {{ amt.amt.network.link_policy }} and carries no Sx value (14 = Sx AC,
      224 = Sx DC), so this endpoint drops off the network when the host leaves S0. A
      subsequent `amt_power state=on` will fail looking like a connection fault rather
      than a configuration one.
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
  untested**, though both lab machines now report `wake_on_lan_capable: true` — see
  the subsection above. No stage powers a machine off, confirms it, and then tries to
  reach it, so the evidence points towards reachability rather than establishing it. A
  `false` on some other endpoint remains the first explanation to check when a remote
  power-on fails with `error_class: connection`.
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

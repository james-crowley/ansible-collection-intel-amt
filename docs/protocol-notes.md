# Intel AMT protocol notes (implementation reference)

This document is the authoritative wire-format reference for this collection. It was
produced by reading the Apache-2.0 licensed Intel/MeshCentral implementation
(`amt/amt-wsman.js`, `amt/amt.js`, `amt/amt-redir-mesh.js`, `amt/amt-ider-module.js`,
`agents/meshcmd.js`) and the GPL-3.0-or-later `parmstro/intel_amt` collection, plus
Intel's AMT Implementation and Reference Guide.

Implementers: treat the byte layouts here as normative. Do not "improve" them.
They are what real firmware accepts.

---

## 1. Two distinct protocol planes

| Plane | Transport | Port (plain / TLS) | Nature |
|---|---|---|---|
| WS-Man management | HTTP(S) + SOAP + HTTP Digest | 16992 / 16993 | Stateless request/response |
| Redirection (SOL, IDE-R) | Raw TCP(+TLS), binary framing | 16994 / 16995 | Stateful, long-lived, bidirectional |

These share credentials but **nothing else**. A WS-Man call that enables redirection
does not move a single byte of media. Serving media requires a full IDE-R client,
which is implemented in this collection (`plugins/module_utils/ider.py`).

### 1.1 Transport availability is NOT universal

Verified on real hardware by `parmstro` (Intel NUC5i5MYBE, AMT 10.0.56 build 3002):
**port 16993 never opens.** AMT provisioned in *Small Business Mode* does not implement
TLS at all — there is no TLS PKI menu in MEBx, and WS-Man TLS-enable returns
`400 Bad Request`. This is architectural, not a bug.

| AMT generation | TLS (16993) |
|---|---|
| 6.x–9.x | Varies by SKU |
| 10.0.56, Small Business Mode | **No** — HTTP 16992 only (hardware-verified) |
| 11.x+ Enterprise | Yes |
| 12.x+ | Yes, enhanced |

**Design consequence.** TLS is the default, but the collection MUST support an
explicit plaintext path or it is unusable on a large class of real machines.
The rule is *no silent downgrade*, not *no plaintext*:

- `use_tls: true` (default) → port 16993, certificate validation enforced.
- `use_tls: false` → port 16992, **and** the caller must also pass
  `allow_insecure_transport: true`. If `use_tls: false` is given without that
  acknowledgement, fail with `error_class: tls_validation` and a message telling
  the user exactly which flag to set and why (credentials cross the wire in a
  form recoverable by an on-path attacker; use an isolated management VLAN).

Never auto-probe 16993 and quietly fall back to 16992.

---

## 2. WS-Man management plane

### 2.1 Endpoint and auth

- URL: `http{s}://<host>:<port>/wsman`
- Auth: **HTTP Digest** (`requests.auth.HTTPDigestAuth`). Basic auth exists on old
  firmware; do not use it.
- Content-Type: `application/soap+xml;charset=UTF-8`

### 2.2 Namespaces

```
s (SOAP envelope) http://www.w3.org/2003/05/soap-envelope
a (WS-Addressing) http://schemas.xmlsoap.org/ws/2004/08/addressing
w (WS-Management) http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
```

Resource URI prefixes:

```
CIM_*  http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/<ClassName>
AMT_*  http://intel.com/wbem/wscim/1/amt-schema/1/<ClassName>
IPS_*  http://intel.com/wbem/wscim/1/ips-schema/1/<ClassName>
```

Actions:

```
Get       http://schemas.xmlsoap.org/ws/2004/09/transfer/Get
Put       http://schemas.xmlsoap.org/ws/2004/09/transfer/Put
Enumerate http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate
Pull      http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull
Method    <ResourceURI>/<MethodName>      (e.g. .../CIM_BootService/SetBootConfigRole)
```

### 2.3 Envelope shape

```xml
<s:Envelope xmlns:s="..." xmlns:a="..." xmlns:w="...">
  <s:Header>
    <a:Action s:mustUnderstand="true">{action}</a:Action>
    <a:To s:mustUnderstand="true">{base_url}</a:To>
    <w:ResourceURI s:mustUnderstand="true">{resource_uri}</w:ResourceURI>
    <a:MessageID s:mustUnderstand="true">uuid:{unique-per-request}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:OperationTimeout>PT60S</w:OperationTimeout>
    <!-- optional -->
    <w:SelectorSet><w:Selector Name="{k}">{v}</w:Selector></w:SelectorSet>
  </s:Header>
  <s:Body>{...}</s:Body>
</s:Envelope>
```

`MessageID` must be unique per request. MeshCentral/parmstro reuse a constant UUID;
that works but is sloppy — generate a fresh `uuid:` each call.

Method invocation body pattern:

```xml
<s:Body>
  <r:{MethodName}_INPUT xmlns:r="{resource_uri}">
    <r:{ParamName}>{value}</r:{ParamName}>
  </r:{MethodName}_INPUT>
</s:Body>
```

### 2.4 Power

**Read current state** — `Get CIM_AssociatedPowerManagementService`, field
`PowerState`. CIM values:

| Value | Meaning | Normalized |
|---|---|---|
| 2 | On | `on` |
| 3 | Sleep - Light | `sleep` |
| 4 | Sleep - Deep | `sleep` |
| 5 | Power Cycle (Off-Soft) | `on` |
| 6 | Off - Hard | `off` |
| 7 | Hibernate | `hibernate` |
| 8 | Off - Soft | `off` |
| 9 | Power Cycle (Off-Hard) | `off` |
| 13 | Off - Hard Graceful | `off` |

Two notes on that table, because it has a soft spot and a decoy.

**The decoy.** go-wsman-messages' `pkg/wsman/cim/power/decoder.go` names these values
differently — `5` is `PowerCycleOffHard`, `6` `PowerCycleOffSoft`, `8` `PowerOffHard`,
`9` `PowerOffSoft` — transposing the soft/hard qualifier within each pair relative to
the names above. That file is **not** the authority for this property: it lists *action*
codes to send to `RequestPowerStateChange`, not the observed-state ValueMap, and it
carries a `TODO: This list of contants needs to be scrubbed` with most entries marked
`?`. The names above are the DMTF CIM ValueMap for
`CIM_AssociatedPowerManagementService.PowerState`, which MeshCmd's own
`DMTFPowerStates` array (`agents/meshcmd.js`) reproduces identically. Two independent
sources agreeing beats one self-flagged draft, so the table stands as written — but the
divergence is recorded here so nobody "fixes" it in the wrong direction.

**The soft spot.** Values `5` and `9` are both *power cycles*, so both end powered
**on**, yet this table normalizes `5` to `on` and `9` to `off`. That asymmetry is
inherited rather than reasoned, and it is deliberately left alone: changing it is a
behaviour change and nothing has measured it. It should also never matter in practice —
`5`, `9`, `10` and `11` are transitional or action-only codes and firmware reports a
settled state. If a real endpoint is ever observed returning `5` or `9` here, that
observation, not a table, is what should decide how it normalizes.

**Change state** — `CIM_PowerManagementService.RequestPowerStateChange`.
Input params: `PowerState`, plus a `ManagedElement` EPR pointing at
`CIM_ComputerSystem` with selector `Name=ManagedSystem`.

Action codes (as used by MeshCmd, verified against firmware):

| Code | Action |
|---|---|
| 2 | Power on |
| 3 | Sleep (light) |
| 4 | Sleep (deep) |
| 5 | Power cycle (off then on) |
| 7 | Hibernate |
| 8 | Power off (soft) |
| 10 | Reset (master bus reset) |

`ReturnValue == 0` means the request was accepted. It does **not** mean the
transition finished. Poll `CIM_AssociatedPowerManagementService` with a bounded
number of probes afterwards.

If the HTTP request times out *after* the bytes were sent, the result is
`indeterminate` — never retry a power mutation automatically.

### 2.5 Boot configuration — the exact five-step sequence

This is the sequence MeshCmd uses and it is load-bearing. Order matters.

1. **`Get AMT_BootSettingData`** — read the whole instance.

2. **`CIM_BootConfigSetting.ChangeBootOrder(null)`** — clear the boot order first.
   Some AMT versions do not clear it automatically. **Omit the `Source` element
   entirely** — do not send an empty `<Source/>`.

   This distinction is load-bearing and was verified the hard way. `Source` is
   typed as an endpoint reference, so it requires `Address` and
   `ReferenceParameters` children. An empty element is schema-invalid and real
   AMT 16.1.30 rejects the whole request:

   ```
   HTTP 400 -- "The supplied SOAP violates the corresponding XML schema definition."
   ```

   An absent element is valid, because these method parameters are optional
   (`minOccurs=0`). "Pass a null Source" therefore means *send no element*, which
   is what MeshCmd does when it passes `null`.

   Must return `ReturnValue == 0`.

3. **`Put AMT_BootSettingData`** with the mutated instance. Fields to set:

   ```
   ConfigurationDataReset = false
   BIOSPause              = false
   EnforceSecureBoot      = false
   BIOSSetup              = (target == 'bios')
   BootMediaIndex         = 0            # non-zero only for indexed CD/HDD targets
   FirmwareVerbosity      = 0
   ForcedProgressEvents   = false
   IDERBootDevice         = 0            # 0 = floppy/USB-R, 1 = CD-ROM
   LockKeyboard           = false
   LockPowerButton        = false
   LockResetButton        = false
   LockSleepButton        = false
   ReflashBIOS            = false
   UseIDER                = <bool>
   UseSOL                 = <bool>       # MeshCmd sets this equal to UseIDER
   UseSafeMode            = false
   UserPasswordBypass     = false
   SecureErase            = false        # only if present in the read instance
   PlatformErase          = false        # only if present in the read instance
   ```

   **Fields that must be DELETED from the instance before Put** (newer firmware
   rejects the Put if they are echoed back):

   ```
   WinREBootEnabled, UEFILocalPBABootEnabled, UEFIHTTPSBootEnabled,
   SecureBootControlEnabled, BootguardStatus, OptionsCleared,
   BIOSLastStatus, UefiBootParametersArray
   ```

   And if `UefiBootNumberOfParams` is present, set it to `0`.

   This delete-list is why a naive read-modify-write Put fails on modern firmware.
   Implement it as a data-driven allow/deny list, not ad hoc.

4. **`CIM_BootService.SetBootConfigRole`** with `BootConfigSetting` EPR selector
   `InstanceID=Intel(r) AMT: Boot Configuration 0` and `Role = 1`
   (1 = **IsNextSingleUse**, the one-shot role). Must return `ReturnValue == 0`.

5. **`CIM_BootConfigSetting.ChangeBootOrder(<EPR>)`** with an EPR naming the chosen
   `CIM_BootSourceSetting` instance:

   ```
   pxe → InstanceID = "Intel(r) AMT: Force PXE Boot"
   hdd → InstanceID = "Intel(r) AMT: Force Hard-drive Boot"
   cd  → InstanceID = "Intel(r) AMT: Force CD/DVD Boot"
   ```

   EPR body form:

   ```xml
   <Address xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">
     http://schemas.xmlsoap.org/ws/2004/08/addressing</Address>
   <ReferenceParameters xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">
     <ResourceURI xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
       http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootSourceSetting</ResourceURI>
     <SelectorSet xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
       <Selector Name="InstanceID">Intel(r) AMT: Force PXE Boot</Selector>
     </SelectorSet>
   </ReferenceParameters>
   ```

   **For IDE-R boot, pass `null`** — no `CIM_BootSourceSetting`. `UseIDER=true` in
   step 3 plus a cleared boot order is what redirects the boot to the IDE-R device.
   This is why native one-time PXE and IDE-R boot are **mutually exclusive**:
   selecting `Force PXE Boot` here overrides the IDE-R intent.

6. Then issue the power action (reset/power-on/power-cycle) from §2.4.

**Discovery before mutation.** Enumerate `CIM_BootSourceSetting` and confirm exactly
one instance matches the requested target before doing any of this. Fail with
`unsupported_capability` if absent or ambiguous. Enumerate `AMT_BootCapabilities`
to confirm support rather than assuming.

`AMT_BootCapabilities` field names, verified against a real firmware response
fixture in `device-management-toolkit/go-wsman-messages`
(`pkg/wsman/wsmantesting/responses/amt/boot/capabilities/get.xml`):

| Target / feature | Capability field |
|---|---|
| `pxe` | `ForcePXEBoot` |
| `hdd` | `ForceHardDriveBoot` |
| `cd` | `ForceCDorDVDBoot` |
| `bios` | `BIOSSetup` |
| IDE-R (`ider_floppy`, `ider_cdrom`) | `IDER` |
| Serial-over-LAN | `SOL` |

The same instance also carries `BIOSPause`, `BIOSReflash`, `BIOSSecureBoot`,
`ConfigurationDataReset`, `ForceDiagnosticBoot`, `ForceHardDriveSafeModeBoot`,
`ForcedProgressEvents`, `KeyboardLock`, `PowerButtonLock`, `ResetButtonLock`,
`SleepButtonLock`, `SecureErase`, `UserPasswordBypass`, and the three
`Verbosity*` flags. Treat a missing field as "not supported" rather than
defaulting to true — a wrong field name then fails closed (the module refuses)
instead of attempting an unsupported boot.

**The `bios` target takes the same step-5 path as IDE-R**: `ChangeBootOrder` is
called with a null `Source`, because `bios` has no `CIM_BootSourceSetting`
instance. `BIOSSetup=true` in step 3 is what selects it. This matches MeshCmd,
whose boot-source map contains only `pxe`, `hdd`, and `cd` and which passes a
null parameter for anything outside that map.

### 2.6 Redirection service state

`AMT_RedirectionService` — key fields:

- `EnabledState`: `32768` = disabled, `32769` = IDER only, `32770` = SOL only,
  `32771` = both enabled.
- `ListenerEnabled`: bool.

Mutate via `AMT_RedirectionService.RequestStateChange` with
`RequestedState` = one of the above. Also `IPS_OptInService` governs user consent
on some configurations.

`AMT_BootCapabilities` reports what the firmware *supports*; `AMT_RedirectionService`
reports what is *enabled*. A TCP connect to 16994/16995 reports what is *reachable*.
Report all three separately — never collapse them into one boolean.

### 2.7 Network and system-state facts

The class names, ResourceURIs, `InstanceID` selector strings and property names in this
subsection are derived from `parmstro`'s hardware research notes
(`development/research/AMT_RESOURCE_DISCOVERY.md` and
`development/research/AMT_10_CAPABILITIES.md`, GPL-3.0-or-later), which record property
values dumped from a real Intel NUC5i5MYBE running AMT 10.0.56 build 3002. **Protocol
facts were taken from those notes; no code was taken from that collection**, and their
module code and user-facing prose are explicitly *not* treated as reliable here — their
`amt_tls_config` wraps both mutation paths in `except Exception` and falls through to
`exit_json()`, so any failure exits `ok` (and its certificate upload is a self-described
placeholder that discards the private key); their
`amt_system_settings_refactored.py` returns `changed: False` in check mode before
computing anything, so `--check` can never report drift; their power constants map
`reset` to CIM code 11 (Diagnostic Interrupt / NMI) rather than 10 (Master Bus Reset);
and their `LinkPolicy` value table was wrong in three of its five entries (see the
correction under `AMT_EthernetPortSettings` below) — **a table this collection also
shipped, in 0.2.0 and 0.3.0, before fixing it in 0.3.1.** See `NOTICE` and
`docs/capability-matrix.md`.

The **`LinkPolicy` value table is the exception**: it is now taken from
`device-management-toolkit/go-wsman-messages`, a vendor reference implementation, not
from those notes. Property *names* from a hardware dump are good evidence; the *meaning*
of an enumeration value is not something a dump can establish, and trusting a
transcription for it is precisely what produced the 0.2.0/0.3.0 defect corrected below.

**Corroborated on this collection's own hardware, on both generations.** Every fact in
this subsection came back populated from AMT **19.0.5** and from AMT **16.1.30** — so
these property names and selectors resolve on firmware this collection can reach, not
only on someone else's AMT 10.0.56. Machine 1 (16.1.30) was re-run after v0.2.0 added
these fields and returned every one of them populated, so the earlier note here that
"16.1.30 has never been asked for them" is no longer true and has been removed. Where a
subsection below marks something unverified, that still holds for every generation other
than 16.1.30 and 19.0.5 — and AMT 10.0.56 remains third-party-reported only.

#### `Enumerate` is HTTP 400 on `AMT_`-prefixed classes — use `Get` with a selector

Hardware-verified on AMT 10.0.56: `Enumerate` returns **HTTP 400** for

```
AMT_EthernetPortSettings, AMT_GeneralSettings, AMT_BootCapabilities,
AMT_BootSettingData, AMT_TLSSettingData
```

while a `Get` carrying an exact `SelectorSet` works. AMT's WS-Man implementation offers
**selective instance access only** for most `AMT_` resources: you must already know the
`InstanceID`.

This cuts against the enumerate-first habit elsewhere in this collection —
`plugins/module_utils/boot.py` (`discover_and_validate()`) and
`plugins/module_utils/redirection_service.py` (`get_capabilities()`) both reach
`AMT_BootCapabilities` via Enumerate+Pull, and that is *known to work on AMT 16.1.30*
(Tier 3, hardware-verified). Both readings are real: the verb a given class accepts
varies by firmware generation. So:

- **Every new `AMT_`-prefixed read must use `Get` with an explicit selector.** Never
  `Enumerate`.
- The existing `Enumerate` call sites are not changed here. They are hardware-verified
  on 16.1.30, and switching them would trade a verified path for an unverified one. If a
  10.x endpoint ever needs them, add a `Get`-with-selector fallback — do not swap the
  verb outright.
- `CIM_`-prefixed classes are not affected by this finding.

#### `AMT_GeneralSettings`

```
ResourceURI  http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings
Selector     InstanceID = "Intel(r) AMT: General Settings"
```

Properties dumped from AMT 10.0.56 hardware:

| Property | Type | Notes |
|---|---|---|
| `HostName` | str | Firmware-observed hostname |
| `DomainName` | str | |
| `IdleWakeTimeout` | int | Minutes |
| `PingResponseEnabled` | bool | ICMP echo. **This** is the ping toggle |
| `RmcpPingResponseEnabled` | bool | |
| `NetworkInterfaceEnabled` | bool | |
| `DDNSUpdateEnabled` | bool | |
| `PowerSource` | int | **Not surfaced** — no documented value table |
| `PrivacyLevel` | int | **Not surfaced** — no documented value table |

`PowerSource` and `PrivacyLevel` are deliberately not reported by `amt_info`. Both were
dumped as `0`, and nothing available documents what their integers mean; publishing a
number an operator cannot interpret invites someone to invent a meaning for it.

This class also carries `DigestRealm`. It carries **no** version property — see §2.5 and
`docs/capability-matrix.md`; the AMT firmware version is on `CIM_SoftwareIdentity`
(`InstanceID == "AMT"`, `VersionString`). `IPS_GeneralSettings.FirmwareVersion` exists but
is deliberately not used: the `CIM_SoftwareIdentity` path is better evidenced.

#### `AMT_EthernetPortSettings`

```
ResourceURI  http://intel.com/wbem/wscim/1/amt-schema/1/AMT_EthernetPortSettings
Selector     InstanceID = "Intel(r) AMT Ethernet Port Settings 0"
Action       Get   (Enumerate is HTTP 400 — see above)
```

| Property | Type | Notes |
|---|---|---|
| `MACAddress` | str | Observed **dash-separated lowercase**, e.g. `00-00-5e-00-53-01` |
| `IPAddress`, `SubnetMask`, `DefaultGateway`, `PrimaryDNS`, `SecondaryDNS` | str | IPv4 |
| `DHCPEnabled` | bool | |
| `LinkIsUp` | bool | |
| `IpSyncEnabled` | bool | AMT **shares the host OS's IP address**. Not a ping toggle |
| `LinkPolicy` | int array | See the value table below |

**Normalize the MAC on ingest and keep the raw reading.** The firmware returned dashes;
`parmstro`'s own documented RETURN sample claims colons. Both shapes are in circulation
for the same property, and this value is used as an identity anchor and as a PXE
reservation key — comparisons a stray separator silently breaks.

**`IpSyncEnabled` is not a ping-response toggle.** `parmstro`'s `amt_network_settings`
writes `IpSyncEnabled` from an option named `ping_response_enabled`, conflating it with
`AMT_GeneralSettings.PingResponseEnabled`. They are different properties on different
classes with different meanings.

**Instance 0 only.** Multi-NIC parts expose higher indices. Do not assume they exist, and
make a missing instance degrade to "unknown" rather than failing a read.

`LinkPolicy` values — **vendor-sourced**, from `device-management-toolkit/go-wsman-messages`
`pkg/wsman/amt/ethernetport` (`decoder.go` named constants; `types.go` carries the schema
annotation `ValueMap={1, 14, 16, 224}` / `Values={available on S0 AC, available on Sx AC,
available on S0 DC, available on Sx DC}`, with the doc comment *"Enumeration values for
link policy restrictions for better power consumption. If Intel® AMT will not be able to
determine the exact power state, the more restrictive closest configuration applies."*):

| Value | Go constant | Meaning |
|---|---|---|
| 1 | `LinkPolicyS0AC` | available on S0 AC — host powered on, mains |
| 14 | `LinkPolicySxAC` | available on Sx AC — host asleep/hibernating/off, mains |
| 16 | `LinkPolicyS0DC` | available on S0 DC — host powered on, battery |
| 224 | `LinkPolicySxDC` | available on Sx DC — host asleep/hibernating/off, battery |

The enum crosses two axes — ACPI state (S0 versus any Sx) and power source (AC versus
DC) — and **there is no "always on" value**. Those four are the whole enum; a value
outside it is reported raw and named `unknown(<raw>)`, which is what go-wsman-messages
itself does (its decoder returns the string `"Value not found in map"`).

> **Correction, 2026-07-29 — the previous table here was wrong, and it came from
> `parmstro`.** Their constants file gives `1: s0_ac, 2: sx_ac, 14: s0_dc, 15: sx_dc,
> 16: always_on`. Three of those five entries are wrong: `14` is Sx AC and not S0 DC,
> `16` is S0 DC and not an "always on" bit, and `2`/`15` are not in Intel's enum at all.
> `224` (Sx DC) was missing entirely. This collection shipped that table in 0.2.0 and
> 0.3.0, and because `wake_on_lan_capable` was derived from `16`, the boolean tested "is
> this endpoint reachable while on battery?" and returned `false` on every mains-powered
> desktop — the inverse of the truth. See `CHANGELOG` for 0.3.1.
>
> **This is the second wrong table from the same source.** The first is noted above:
> their power constants map `reset` to CIM code 11 (Diagnostic Interrupt / NMI) rather
> than 10 (Master Bus Reset). Their *research notes* — dumped property values, class
> names, selector strings, which verb each class accepts — have held up. Their
> *constants and derived meanings* have now been wrong twice. Do not adopt a third
> table from them without checking it against go-wsman-messages or a firmware fixture
> first, and do not treat "corroborated by their hardware dump" as covering the
> meaning of a value — a dump corroborates that a value was *returned*, never what it
> *means*.

**Why the Sx values matter operationally.** An endpoint whose `LinkPolicy` carries
neither `14` nor `224` keeps its network link up only while the host is in S0, so it
does not answer WS-Man at all once the host sleeps or powers down. `amt_power` with
`state: on` against such an endpoint therefore fails looking exactly like a network
fault — wrong VLAN, wrong address, firewall — when the actual cause is a link policy.
Surfacing it read-only converts a confusing failure into a diagnosis. The derived
`wake_on_lan_capable` boolean is exactly this test: *is any Sx value present?*

**Hardware agreement on the corrected table.** Both lab machines (AMT 16.1.30 and
19.0.5) report `[1, 14]` — S0 AC plus Sx AC. The MEBx screen on one of them was
photographed: `ME ON in Host Sleep States` is set to *"Desktop: ON in S0, ME Wake in S3,
S4-5"*, the wake-capable option, and `Idle Timeout` reads `65535`, matching the
`idle_wake_timeout` `amt_info` reports. Firmware configuration and the corrected table
agree; it was the old derivation that disagreed with both. Note that `LinkPolicy`
governs whether the network **link** is maintained while the MEBx setting governs
whether the **ME itself** is powered — related, not the same field, and this collection
reads only the former.

**Wire shape of `LinkPolicy` is not settled.** AMT's schema types it as a `uint32` array,
which WS-Man renders as a repeated plain element. `parmstro`'s module code instead parses
`<PolicyValue>` children inside a `LinkPolicy` wrapper, and their notes record only the
decoded result (`[1, 14, 16]`), never the XML. Neither shape is ruled out by the
available evidence, so a parser should accept both; the cost of guessing wrong is an
empty policy list and a `wake_on_lan_capable` that reads `false` on a machine that is in
fact wakeable.

#### `CIM_ComputerSystem`

```
ResourceURI  http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem
Selector     Name = "ManagedSystem"
Properties   EnabledState (int), RequestedState (int),
             OperationalStatus (uint16[]), ElementName (str)
```

Read `ElementName`, not `Name` — `Name` is the selector value the caller already
supplied. **This class has no `UUID` property**; the platform UUID is
`CIM_ComputerSystemPackage.PlatformGUID` (§2.5 and `docs/capability-matrix.md`). Reading
`UUID` here was a real defect in this collection, and it is why the class was removed
from facts gathering in 0.1.0 before being reintroduced for the state fields above.

`EnabledState` (DMTF `CIM_EnabledLogicalElement`):

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| unknown | other | enabled | disabled | shutting down | not applicable | enabled but offline | in test | deferred | quiesce | starting |

`OperationalStatus` (DMTF `CIM_ManagedSystemElement`) — an **array**, decoded
element-wise: 0 unknown, 1 other, 2 OK, 3 degraded, 4 stressed, 5 predictive failure,
6 error, 7 non-recoverable error, 8 starting, 9 stopping, 10 stopped, 11 in service,
12 no contact, 13 lost communication, 14 aborted, 15 dormant, 16 supporting entity in
error, 17 completed, 18 power mode, 19 relocating. Firmware reporting one value is an
array of length one; a client that reads only the first element drops exactly the
statuses that explain a degraded machine. **The array shape is hardware-confirmed on both
generations**: AMT 19.0.5 and AMT 16.1.30 each returned a single-element list, not a
scalar (see `docs/capability-matrix.md` Tier 3).

`RequestedState` is reported raw. AMT 10.0.56 was observed reporting `12`, which DMTF
defines as "Not Applicable". No value table for it is claimed by this collection.

#### `CIM_BIOSElement`

```
ResourceURI  http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BIOSElement
Action       Get (no selector), falling back to Enumerate
Property     Version   e.g. "EXAMPLE10H.86A.0000.2026.0101.0000"
```

This was the **weakest-evidenced** item in this subsection. `parmstro`'s notes list the
class as working on AMT 10.0.56 but record no dumped value, and their implementation
swallows any failure to `None` — so their "it works" is not evidence either way. AMT
19.0.5 and AMT 16.1.30 both returned a populated value (`docs/capability-matrix.md`
Tier 3), which settles the read path on those two generations and nothing more. Keep the defensive shape
regardless: read it through an optional-degradation path so a fault yields `null`
rather than failing, and try `Enumerate` if a bare `Get` faults, since a class with no
selector may require enumeration.

This is the **host BIOS** version, not the AMT firmware version.

#### Deliberately not implemented

- `IPS_GeneralSettings.FirmwareVersion` — the `CIM_SoftwareIdentity` path (§2.5) is
  better evidenced; do not switch.
- `CIM_ComputerSystem.OnTimeCounter` as an uptime source — unevidenced.
- Any AMT time field. `parmstro`'s `amt_host_status` fabricates `amt_time` from the
  *controller's* own clock (`datetime.utcnow()`), which is not a fact about the endpoint
  at all. The real source would be `AMT_TimeSynchronizationService`, unverified.
- Any write path to any class in this subsection.

### 2.8 Event log — `AMT_MessageLog`

Backs `amt_event_log` (read) and `amt_log_clear` (clear), implemented in
`plugins/module_utils/message_log.py`.

**Nothing in this subsection has been exercised against real firmware by this
collection.** No hardware qualification stage covers either module. What follows is
sourced from third-party material, and each fact below names the file — and, where one
exists, the response fixture — that establishes it. Anything that remains inferred says
so explicitly.

#### Sources used

| Short name | What it is | License |
|---|---|---|
| **go-wsman** | `device-management-toolkit/go-wsman-messages`, `pkg/wsman/amt/messagelog/` (`log.go`, `types.go`, `decoder.go`, `log_test.go`) | Apache-2.0, Intel-authored |
| **fixtures** | The same repository's **real firmware response captures** at `pkg/wsman/wsmantesting/responses/amt/messagelog/` — `get.xml`, `enumerate.xml`, `pull.xml`, `getrecords.xml`, `positiontofirstrecord.xml` | Apache-2.0 |
| **MeshCentral** | `agents/modules_meshcmd/amt.js` — the `AMT_MessageLog_*` wrappers and `GetMessageLog()` | Apache-2.0 |

A **fixture** row is the strongest evidence available short of hardware: it is a captured
firmware response, not somebody's model of one. Where go-wsman and MeshCentral agree
*and* a fixture corroborates, the fact is treated as settled. Where the two code sources
disagree, nothing is claimed — see "Deliberately not decoded" below.

The prior art (`parmstro/intel_amt`'s `amt_event_log`) contributed **nothing** here. It
queries `CIM_RecordLog` — the log *container* — and scans for `RecordData` elements that
do not exist on it, so it always returns `[]` while reporting success. Its own comments
concede it is "a framework for future enhancement", and its documented `log_type`
parameter is absent from its code. It is not a source.

#### Resource and methods

```
ResourceURI  http://intel.com/wbem/wscim/1/amt-schema/1/AMT_MessageLog
Action       Get (no selector), falling back to Enumerate
Methods      PositionToFirstRecord, GetRecords, ClearLog
```

| Fact | Source |
|---|---|
| Class is `AMT_MessageLog`, **not** `CIM_RecordLog` | fixtures (all five are `AMT_MessageLog`); go-wsman `decoder.go` `AMTMessageLog` |
| Method names are `PositionToFirstRecord` and `GetRecords` | fixtures `positiontofirstrecord.xml`, `getrecords.xml` (both are `*_OUTPUT` responses under the `AMT_MessageLog` namespace); go-wsman `log.go` |
| `ClearLog` exists on this class and takes **no parameters** | MeshCentral `AMT_MessageLog_ClearLog = function (callback_func) { obj.Exec("AMT_MessageLog", "ClearLog", { }, ...) }` |
| Firmware itself advertises clear support | fixture `get.xml`: `Capabilities` includes `6`, which go-wsman `decoder.go` names `CapabilitiesClearLogSupported` |

**`PositionAtRecord` and `GetRecord` (singular) also exist** — MeshCentral wraps both —
and are deliberately **not** used. `GetRecords` (plural) is the batched form both sources
use for a full read, and a per-record method would multiply round trips for no gain.

**Why a bare `Get`, against §2.7's rule.** §2.7 requires every new `AMT_`-prefixed read to
use `Get` with an explicit selector. That rule cannot be followed here, for an evidential
reason rather than a stylistic one: **no source names a selector for this class.** The
fixture `get.xml` is a response to a `Get` carrying no `SelectorSet` at all, and the
instance it returns has no `InstanceID` property from which one could be built — its keys
are `CreationClassName` and `Name`. Constructing `InstanceID = "Intel(r) AMT:MessageLog 1"`
would be inventing a selector. So this follows the `CIM_BIOSElement` pattern instead:
bare `Get`, falling back to `Enumerate`.

Unusually for an `AMT_` class, **`Enumerate` is also evidenced here**: `enumerate.xml` and
`pull.xml` exist alongside `get.xml` and return the same instance. Both verbs are
therefore real on the generation those fixtures came from. The fallback is still worth
having, because §2.7 records `Enumerate` as HTTP 400 on `AMT_` classes on AMT 10, so on
that generation only the `Get` can work.

#### Container properties

From fixture `get.xml` (identical in `pull.xml`):

| Property | Fixture value | Used for |
|---|---|---|
| `CurrentNumberOfRecords` | `390` | `total_records`; the clear module's before/after receipt |
| `MaxNumberOfRecords` | `390` | Reported. Also the origin of `MAX_READ_RECORDS`/`max_records` default |
| `MaxRecordSize` | `21` | **Independent corroboration of the 21-byte record struct** |
| `SizeOfRecordHeader` | `0` | Records have no header — the struct starts at byte 0 |
| `SizeOfHeader` | `0` | The log has no header either |
| `Capabilities` | `5, 6, 8, 7` | `6` = ClearLogSupported (see above) |
| `CharacterSet` | `10` | `OctetString` — i.e. records are binary, not text |
| `ElementName`, `Name` | `Intel(r) AMT:MessageLog 1` | Reported |
| `IsFrozen`, `LogState`, `OverwritePolicy` | `false`, `4`, `2` | Reported raw |

`LogState` is `4` in the fixture, which is **not** in the DMTF value map go-wsman itself
carries for it (`0` Unknown, `2` Normal, `3` Erasing, `5` NotApplicable). It is therefore
reported as a raw integer with no name attached. Same for `OverwritePolicy`. Reporting a
number an operator cannot interpret is the lesser error; naming it wrongly is not.

#### The iteration

The sequence, from MeshCentral's `GetMessageLog()`:

```
PositionToFirstRecord()                            -> IterationIdentifier
GetRecords(IterationIdentifier, 390)               -> RecordArray[], NoMoreRecords, IterationIdentifier
  while NoMoreRecords != true:
    GetRecords(<returned IterationIdentifier>, 390)
```

| Fact | Source |
|---|---|
| `GetRecords` inputs are `IterationIdentifier` and `MaxReadRecords` | go-wsman `GetRecords_INPUT`; fixture request body in `log_test.go`: `<h:IterationIdentifier>1</h:IterationIdentifier><h:MaxReadRecords>10</h:MaxReadRecords>`; MeshCentral passes the same two |
| `GetRecords` outputs `IterationIdentifier`, `NoMoreRecords`, repeated `RecordArray`, `ReturnValue`, **in that order** | fixture `getrecords.xml` |
| `RecordArray` elements are base64 | go-wsman `parseEventLogResult` (`base64.StdEncoding.DecodeString`); MeshCentral `Buffer.from(ra[i], 'base64')` |
| Iteration continues until `NoMoreRecords` is true, feeding back the returned identifier | MeshCentral `GetMessageLog`; go-wsman `log.go`: "If NoMoreRecords returns false, call this again setting the identifier to the start of the next IterationIdentifier" |
| `PositionToFirstRecord` takes no parameters | fixture request body: empty `PositionToFirstRecord_INPUT` |
| Identifier is 1-based | go-wsman `GetRecords` doc comment: "a numeric value (starting at 1) which is the position of the first record in the log" |
| `MaxReadRecords` cap is 390 | go-wsman `MaxAMTRecords = 390` with the comment "Intel AMT can return 400 records in a single GetRecords call, but we limit it to 390"; MeshCentral passes `390` |
| Log is stored **newest first** | go-wsman `messagelog` package comment: "In most implementations, log entries are stored backwards, i.e. the newest record is the first record" |

**`ReturnValue` maps, from the `ValueMap`/`Values` annotations in go-wsman `types.go`:**

| Method | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `GetRecords` | Completed with No Error | Not Supported | Invalid record pointed | No record exists in log |
| `PositionToFirstRecord` | Completed with No Error | Not Supported | No record exists | — |

The two methods use **different values for the same condition**: an empty log is `3` from
`GetRecords` and `2` from `PositionToFirstRecord`. Both are ordinary outcomes, not
failures, so `message_log.py` tolerates them rather than letting `WsmanClient.invoke`'s
non-zero-`ReturnValue` rule turn a quiet machine into a `remote_operation` error. `1`
(Not Supported) on `PositionToFirstRecord` is escalated to `unsupported_capability`.

**Inferred, not established: the returned `IterationIdentifier`'s arithmetic.** The
fixture returns `3` after serving three records starting from position `1`, which fits no
obvious rule (`1 + 3 = 4`). Firmware's bookkeeping is therefore *unknown*, and this
collection treats the returned identifier as an **opaque token fed back verbatim** — which
is what MeshCentral does, and the only approach that cannot be wrong. The mock WS-Man
server deliberately does *not* reproduce the fixture's unexplained value, because doing so
would bake an arithmetic no client should rely on into the one place it could be relied on.

`PositionToFirstRecord` is called even though go-wsman documents it as inert on current
firmware — "In current implementation this method doesn't have any affect. In order to get
the events from the log user should just call GetRecord or GetRecords" — because
MeshCentral calls it, because it is the documented way to *obtain* an identifier rather
than assume one, and because its `ReturnValue` is an unambiguous empty-log signal.

#### Record layout — 21 bytes

```c
struct {
  UINT32 TimeStamp;        // little endian
  UINT8  DeviceAddress;
  UINT8  EventSensorType;
  UINT8  EventType;
  UINT8  EventOffset;
  UINT8  EventSourceType;
  UINT8  EventSeverity;
  UINT8  SensorNumber;
  UINT8  Entity;
  UINT8  EntityInstance;
  UINT8  EventData[8];
} EVENT_DATA;                // 4 + 9 + 8 = 21
```

| Fact | Source |
|---|---|
| The struct, verbatim, including field order | go-wsman `log.go` package comment: "Records have no header and the record data is combined of 21 binary bytes" |
| Same field order by index | MeshCentral: `e[4]` DeviceAddress … `e[12]` EntityInstance, then `for (j = 13; j < 21; j++)` into `EventData` |
| Total size is 21 | fixture `get.xml` `MaxRecordSize` = `21`; every `RecordArray` element in `getrecords.xml` decodes to exactly 21 bytes |
| Timestamp is little-endian | go-wsman `// little endian` plus `binary.LittleEndian` reads; MeshCentral `ReadIntX(e, 0)` |
| Timestamp byte order, **arithmetically confirmed** | fixture record `Y8iYZf8GbwVoEP8mYaoKAAAAAAAA` begins `63 c8 98 65`, and go-wsman's `log_test.go` asserts `TimeStamp: 0x6598c863` for it — byte-reversed |

The single-byte fields have no byte order, so only the timestamp's needed establishing.

**Two independent sources agree byte-for-byte on this layout, and a real firmware record
plus its Intel-authored expected decode confirms it.** `tests/unit/plugins/module_utils/test_message_log.py`
asserts this collection's decode of both real fixture records against the exact values
go-wsman's own `log_test.go` asserts, so a drift here stops agreeing with published output
for real firmware data rather than merely failing an internal expectation.

**Timestamp semantics: Unix epoch seconds, UTC** — go-wsman's `time.Unix(int64(event.TimeStamp), 0)`.
MeshCentral instead adds the *management station's* local timezone offset before
constructing the date, making the rendered instant depend on where the reader is sitting;
that is a property of the reader, not the event, and is not reproduced. The raw integer is
always returned next to the rendered form so a caller who disagrees still has the number.
`0` and `0xFFFFFFFF` render as `null` rather than 1970 or 2106; MeshCentral drops such
records entirely, but dropping records silently is the prior art's defect, so they are kept
with a null timestamp.

**Records are always returned raw as well as decoded** (`raw_base64`, `raw_hex`,
`raw_length`), including records that failed to decode. This is non-negotiable: the decode
has never met real firmware from here, so the raw bytes are the only thing that makes a
wrong decode diagnosable rather than merely wrong. A record shorter than 21 bytes yields a
`decode_error` and **no** decoded fields at all — a partial struct read at wrong offsets
produces values that look real.

`Capabilities` contains `8` (`VariableLengthRecordsSupported`) while `MaxRecordSize` is
`21`, which is mildly contradictory. Nothing describes what a longer record would contain,
so any bytes past the 21st are preserved in `raw_hex` and not guessed at.

#### Value tables

Both code sources carry these identically; go-wsman `decoder.go` is the transcription
source.

**`EventSeverity`** — sparse and non-contiguous, so a **lookup, not an ordered ladder**.
`ok` (4) is numerically greater than `information` (2) without being worse, which is why
`amt_event_log`'s `severity` option filters by *name* and never compares numerically.

| 0 | 1 | 2 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|
| unspecified | monitor | information | ok | non_critical | critical | non_recoverable |

**`Entity`** — the 53-entry IPMI-style system-entity table (`0` Unspecified … `52`
Processor front side bus), transcribed in full into `message_log.py`'s
`SYSTEM_ENTITY_TABLE`. Both sources list `35` **and** `38` as "Intel(r) ME"; that is not a
transcription slip. Fixture-corroborated at two points: `Entity` `38` decodes to
"Intel(r) ME" and `34` to "BIOS", matching the `RefinedEventData` go-wsman's own test
asserts for those records.

**Descriptions** are derived per `EventSensorType`, implementing go-wsman's
`decodeEventDetailString`:

| `EventSensorType` | Description source |
|---|---|
| 6 | Authentication-failure count, little-endian 16-bit in `EventData[1..2]` |
| 15, `EventOffset == 0` | `SystemFirmwareError[EventData[1]]` (14 entries) |
| 15, other offsets | `SystemFirmwareProgress[EventData[1]]` (26 entries) — **but see below** |
| 15, `EventData[0] == 0xEB` | "Invalid Data" |
| 18 | Agent watchdog: GUID prefix from `EventData[1..6]`, state from `WatchdogCurrentStates[EventData[7]]`. Gated on `EventData[0] == 0xAA` |
| 30, 32, 35, 37 | Fixed strings: no bootable media / OS lockup or power interrupt / system boot failure / system firmware started |

Any value outside a table renders as `unknown(<raw>)`, never as the table's own defined
"Unknown" entry — "firmware said Unknown" and "we do not know what firmware said" are
different findings and must not render identically.

#### Deliberately not decoded

- **`EventType`, `EventOffset`, `EventSourceType`, `DeviceAddress`, `SensorNumber`** —
  reported as raw integers only. No value table for any of them is established by any
  source here. MeshCentral does carry a 12-entry `_EventTrapSourceTypes` list, but real
  firmware records show `EventSourceType == 104`, far outside it, so that list plainly
  does not describe this field and is **not** applied. A unit test asserts no
  `*_text` companion exists for these five, so adding one requires recording a source here
  first.
- **`EventSensorType == 15` at a non-zero `EventOffset` when `EventData[0] == 0xAA`** — the
  one place the two sources **contradict** each other. go-wsman reads the
  firmware-progress table; MeshCentral's `meshcmd` decoder treats offsets 3 and 5 with that
  marker as One-Click-Recovery / platform-erase / OEM-specific events with an entirely
  different layout. Two sources disagreeing is not a source, so **no description is
  produced** for that case and the raw `EventData` is returned instead. Emitting a progress
  string where MeshCentral says the event is a One-Click-Recovery report is exactly the
  plausible-looking garbage worth avoiding.
- **Sensor types MeshCentral alone decodes** (5 case intrusion, 36 packet-filter match,
  192 SOL/IDE-R session and security policy) — single-sourced, and 36 and 192 need
  multi-byte handle/NIC decoding that nothing corroborates. Records of those types are
  returned with `description: null` and their raw bytes.
- **`IPS_ProvisioningRecordLog.ClearLog`** — investigated and **not implemented**.
  MeshCentral wraps it, but with a `_method_dummy` parameter
  (`obj.Exec("IPS_ProvisioningRecordLog", "ClearLog", { "_method_dummy": _method_dummy })`)
  whose type, permitted values and purpose no available source explains. There is no
  fixture for the class anywhere in the `go-wsman-messages` response captures, and
  `go-wsman-messages` does not implement it at all — so whether it exists on modern
  firmware is unestablished, and its one parameter cannot be filled in without guessing.
  It is also a *different* log (provisioning/audit history, not platform events), so it is
  not a substitute for `AMT_MessageLog.ClearLog` and its absence costs the motivating use
  case nothing. `AMT_AuditLog.ClearLog` and `CIM_RecordLog.ClearLog` are likewise wrapped
  by MeshCentral and likewise out of scope here for the same reason: no fixture, different
  log.
- **`FreezeLog`, `CancelIteration`, `RequestStateChange`** on `AMT_MessageLog` — MeshCentral
  wraps all three. Out of scope: nothing in the motivating use case needs them, and
  `FreezeLog` in particular could leave an endpoint refusing log writes.

### 2.9 Hardware / asset inventory — the `CIM_` physical-asset classes

Backs `amt_info`'s `gather_subset` inventory subsets, implemented in
`plugins/module_utils/hardware.py`.

**Nothing in this subsection has been exercised against real firmware by this
collection.** No hardware qualification stage covers it. Unusually for this document,
though, almost everything here rests on **real firmware response fixtures** rather than
on a third party's prose: `device-management-toolkit/go-wsman-messages` (Intel's own
toolkit, Apache-2.0, read at tag `v2.48.3`) ships captured responses for every class
below under `pkg/wsman/wsmantesting/responses/`. Those fixtures are the primary source
for the property sets, and the packages' `decoder.go` files are the primary source for
every value table. See `docs/capability-matrix.md` Tier 2.

**Why AMT for this at all.** These classes are readable while the host is powered off,
because the ME answers independently of the OS. Where an agent is running,
`ansible.builtin.setup` is the right tool. MeshCentral encodes exactly that judgement:
`amtmanager.js`'s `attemptFetchHardwareInventory()` is gated on `mesh.mtype == 1` — an
**AMT-only** device group — and fetches this batch only there.

#### Classes, verbs and fixtures

MeshCentral's `BatchEnum` list is the best available evidence for the verb each class
takes. Its `*` prefix means "issue a `Get` instead of an `Enumerate`, to reduce round
trips" (`agents/modules_meshcmd/amt.js`), so its own choice per class is explicit:

```
'*CIM_ComputerSystemPackage', 'CIM_SystemPackaging', '*CIM_Chassis', 'CIM_Chip',
'*CIM_Card', '*CIM_BIOSElement', 'CIM_Processor', 'CIM_PhysicalMemory',
'CIM_MediaAccessDevice', 'CIM_PhysicalPackage'
```

| Class | Verb | Fixtures shipped | Notes |
|---|---|---|---|
| `CIM_Chassis` | `Get`, `Enumerate` both evidenced | `get.xml`, `enumerate.xml`, `pull.xml` | System serial, model, manufacturer |
| `CIM_Card` | `Get`, `Enumerate` both evidenced | `get.xml`, `enumerate.xml`, `pull.xml` | Baseboard serial |
| `CIM_Processor` | `Enumerate` | `get.xml`, `pull.xml`, `enumerate.xml` | One instance per physical package |
| `CIM_Chip` | `Enumerate` | `get.xml`, `pull.xml`, `enumerate.xml` | `Version` is the readable CPU name |
| `CIM_PhysicalMemory` | `Enumerate` | `pull.xml`, `enumerate.xml` — **no** `get.xml` | Per DIMM |
| `CIM_MediaAccessDevice` | `Enumerate` | `pull.xml`, `enumerate.xml` — **no** `get.xml` | Per disk |

**§2.7's `Enumerate`-is-HTTP-400 finding does not apply here.** That finding is scoped
to five `AMT_`-prefixed classes and states outright that `CIM_`-prefixed classes are
unaffected. Every class in this subsection is `CIM_`-prefixed, and the fixture set ships
`enumerate.xml` + `pull.xml` for all six — so `Enumerate` is directly evidenced and needs
no `Get` fallback. This was checked rather than assumed, because it was the most likely
way for this whole subsection to be wrong.

The two singletons are read `Get`-first with an `Enumerate` fallback, following
`CIM_BIOSElement`'s precedent (§2.7): both verbs are evidenced for both classes, so
which one a given firmware accepts is genuinely unsettled, and the cheap verb is tried
first.

`CIM_PhysicalPackage` is **deliberately not read**. `CIM_Card` and `CIM_Chassis` are both
subclasses of it, and `responses/cim/physical/package/pull.xml` — the captured
`Enumerate` of `CIM_PhysicalPackage` — returns a `CIM_Card` instance. Reading it would
return the same instances under a third resource URI: one round trip, no information.
`CIM_SystemPackaging` is likewise not read; it is an association class, not an asset.

#### Value tables — all vendor- or DMTF-sourced, none from a dump

This is the risk that has twice cost this project a release. **Every mapping below comes
from `go-wsman-messages`' `decoder.go` const/map pairs or from the DMTF CIM schema.** The
mappings were extracted mechanically from the Go source rather than retyped.

| Property | Values | `go-wsman-messages` source |
|---|---|---|
| `CIM_Chassis.ChassisPackageType` | 37, 0–36 | `cim/chassis/decoder.go` — `chassisPackageTypeToString` |
| `PackageType` (chassis and card) | 18, 0–17 | `cim/chassis/decoder.go` + `cim/card/decoder.go` — `packageTypeMap`, byte-identical |
| `CIM_PhysicalMemory.MemoryType` | 37, 0–36 | `cim/physical/decoder.go` — `memoryTypeMap` |
| `CIM_MediaAccessDevice.Capabilities` | 13, 0–12 | `cim/mediaaccess/decoder.go` — `capabilitiesToString`, plus the inline DMTF `ValueMap`/`Values` in that package's `types.go` |
| `CIM_MediaAccessDevice.Security` | 7, **1–7** | `cim/mediaaccess/decoder.go` — `securityToString` (`iota + 1`), plus the same inline annotation |
| `CIM_MediaAccessDevice.EnabledDefault` | 6, sparse | `cim/mediaaccess/decoder.go` — `enabledDefaultToString` |
| `CIM_Processor.CPUStatus` | 6, 0–5 | `cim/processor/decoder.go` — `cpuStatusMap` |
| `CIM_Processor.HealthState` | 7, sparse (steps of 5) | `cim/processor/decoder.go` — `healthStateMap` |
| `CIM_Processor.UpgradeMethod` | 85, 0–84 | `cim/processor/decoder.go` — `upgradeMethodMap` |
| `EnabledState` | 11, 0–10 | **DMTF `CIM_EnabledLogicalElement`** — see the warning below |
| `OperationalStatus` | 20, 0–19 | **DMTF `CIM_ManagedSystemElement`** |

Three traps in these tables, each of which would produce a plausible-looking wrong
answer:

- **`Security` is inverted relative to every other table here**: `1` is `Other` and `2`
  is `Unknown`. `responses/cim/mediaaccess/pull.xml` reports `Security` 2 on both
  devices, so a transposed table would report every disk as "other" and look entirely
  reasonable doing it.
- **`UpgradeMethod` has the same inversion**: `0` is `Other`, `1` is `Unknown`.
- **`CIM_Chassis` carries `ChassisPackageType` *and* `PackageType`**, two different
  enumerations, on the same instance — `responses/cim/chassis/get.xml` reports 0 and 3
  respectively. Decoding one with the other's table is silent.

**Do not use `go-wsman-messages`' `cim/processor` `enabledStateMap`.** It omits values
0, 1 and 2, so its own decoder returns "Value not found in map" for its own captured
firmware response, which reports `EnabledState` 2. Its `cim/mediaaccess` copy of the same
enumeration is complete and agrees with DMTF exactly, which is what identifies the
processor one as an omission rather than a disagreement. The full DMTF table is used for
both classes here, and it is the same single table `amt_info` already applies to
`CIM_ComputerSystem` — held in one place in `plugins/module_utils/models.py` and imported,
never redeclared.

#### Deliberately undecoded

| Property | Why |
|---|---|
| `CIM_Processor.Family` | `go-wsman-messages` types it a plain `int` and defines **no** map; there is no `familyMap` in the library. The DMTF `Family` ValueMap has several hundred entries and no offline copy of the schema was available. Firmware reports `198`; the meaning ships unclaimed. `CIM_Chip.Version` supplies what a caller wanted from it anyway. |
| `CIM_PhysicalMemory.FormFactor` | Also a plain `int` with no map, and **two published tables disagree about the value firmware actually reports**: the fixture says `13`, which is `SODIMM` under SMBIOS type 17 and `SRIMM` under the DMTF `CIM_PhysicalMemory.FormFactor` ValueMap. The fixture's part *is* a SODIMM, so SMBIOS looks right — but that is a hardware-dump inference about a *meaning*, which is the one thing a dump cannot establish. |
| `RequestedState` | Reported raw, matching §2.7's treatment of the identical property on `CIM_ComputerSystem`. |

#### Properties that do not exist on these classes

Each is something a reader might reasonably go looking for. Verified absent from both
the class definitions and the fixtures:

- **No asset tag anywhere.** The string `AssetTag` does not occur in `go-wsman-messages`
  at all. `CIM_Chassis`, `CIM_Card`, `CIM_Chip` and `CIM_PhysicalMemory` each carry
  `Tag`, the DMTF key property, whose description says it "can contain information such
  as asset tag or serial number data" — but on the fixtures firmware populates it with
  the **class name** (`CIM_Chassis`, `CIM_Card`) or a bare number with a `(#1)`
  disambiguating suffix for the second DIMM. Surfaced as `tag`, never as `asset_tag`.
- **No processor core or thread count.** `CIM_Processor`'s full property set is
  `DeviceID`, `CreationClassName`, `SystemName`, `SystemCreationClassName`,
  `ElementName`, `OperationalStatus`, `HealthState`, `EnabledState`, `RequestedState`,
  `Role`, `Family`, `OtherFamilyDescription`, `UpgradeMethod`, `MaxClockSpeed`,
  `CurrentClockSpeed`, `Stepping`, `CPUStatus`, `ExternalBusClockSpeed`. DMTF defines
  `NumberOfEnabledCores` in later schema versions; AMT does not expose it.
- **No disk model, vendor or serial.** `CIM_MediaAccessDevice` carries only
  `Capabilities`, `CreationClassName`, `DeviceID`, `ElementName`, `EnabledDefault`,
  `EnabledState`, `MaxMediaSize`, `OperationalStatus`, `RequestedState`, `Security`,
  `SystemCreationClassName`, `SystemName`. `ElementName` is the constant string
  `Managed System Media Access Device` on both fixture devices, so it identifies nothing
  either; `DeviceID` (`MEDIA DEV 0`/`1`) and `MaxMediaSize` are the only discriminators.

#### Units, and two traps in them

- **`CIM_PhysicalMemory.Capacity` is bytes.** The fixture's `17179869184` is exactly
  16 GiB, which corroborates the class definition.
- **`CIM_MediaAccessDevice.MaxMediaSize` is KBytes**, per the class definition. The
  fixture's `960197124` and `500107862` read as a 960 GB and a 500 GB device under
  KB = 1000. Suggestive, but nothing establishes 1000 versus 1024, so no conversion is
  performed and the field is named `_kb`.
- **`CIM_PhysicalMemory` has two speed properties in different units, and a flag
  selecting between them.** The class definition: "A value of TRUE [for `IsSpeedInMhz`]
  shall indicate that the speed is represented by the `MaxMemorySpeed` property. A value
  of FALSE shall indicate that the speed is represented by the `Speed` property."
  `Speed` is in **nanoseconds**; `MaxMemorySpeed` is in **MHz**. The fixture reports
  `Speed` 0 with `IsSpeedInMhz` true and `MaxMemorySpeed` 2400 — so a naive read of
  `Speed` reports every DIMM on that machine as zero. All four inputs (`Speed`,
  `MaxMemorySpeed`, `ConfiguredMemoryClockSpeed`, `IsSpeedInMhz`) are reported and
  nothing is derived, because the false branch has no honest single answer.
- **`CIM_Processor.Stepping` is a free-form string**, not an integer, per the class
  definition — firmware may report `B0`.

#### Deliberately not read

- `CIM_PhysicalPackage`, `CIM_SystemPackaging` — see above.
- `CIM_Battery`, `CIM_Fan`, `CIM_Sensor` — fixtures exist in `go-wsman-messages` and
  these are plausible future subsets, but nothing in the motivating use case (asset
  inventory of a powered-off machine) needs them, and each would be another value table.
- Any write path to any class in this subsection. Several carry methods
  (`CIM_MediaAccessDevice.LockMedia`, `CIM_Processor.RequestStateChange`); all are out of
  scope for a read-only capability.

---

## 3. Redirection plane — session handshake

All multi-byte integers in the redirection/IDE-R protocols are **little-endian**
unless stated. Length-prefixed strings are `[1-byte length][bytes]`.

Connect TCP to 16994, or TLS to 16995. On TLS, if pinning, compare the peer leaf
certificate SHA-256 before sending any bytes.

### 3.1 Start session

Send 8 bytes:

```
IDER: 10 00 00 00 49 44 45 52   ("IDER")
SOL:  10 00 00 00 53 4F 4C 20   ("SOL ")
KVM:  10 01 00 00 4B 56 4D 52   ("KVMR")
```

Receive `0x11` StartRedirectionSessionReply:

```
[0]     0x11
[1]     status   (0 = STATUS_SUCCESS; anything else → abort)
[2..11] reserved / version info
[12]    oemLen
total   13 + oemLen
```

### 3.2 Authenticate

Query supported auth types — send 9 bytes:

```
13 00 00 00 00 00 00 00 00
```

Receive `0x14` AuthenticateSessionReply:

```
[0]     0x14
[1]     status
[4]     authType
[5..8]  authDataLen  (LE uint32)
[9..]   authData     (authDataLen bytes)
total   9 + authDataLen
```

Dispatch on `authType`:

- **`authType == 0`** — `authData` is a list of supported auth type bytes.
  Require `4` (digest with cnonce/qop) to be present. If absent, abort:
  do not fall back to type `1` (basic, cleartext password) or `3` (digest
  without cnonce).

  Send the digest *query*:

  ```
  13 00 00 00 04
  <LE uint32 length = len(user) + len(uri) + 8>
  <len(user)> <user>
  00 00
  <len(uri)>  <uri>
  00 00 00 00
  ```

  where `uri` is the literal string **`/RedirectionService`**.

- **`authType == 4` and `status == 1`** — challenge. Parse `authData` sequentially,
  each field `[1-byte len][value]`:

  ```
  realm
  nonce
  qop
  ```

  Then:

  ```
  cnonce = 32 random hex chars
  snc    = "00000002"                  # literal, not a counter
  HA1    = MD5(user + ":" + realm + ":" + password)
  HA2    = MD5("POST:" + "/RedirectionService")
  digest = MD5(HA1 + ":" + nonce + ":" + snc + ":" + cnonce + ":" + qop + ":" + HA2)
  ```

  Reply:

  ```
  13 00 00 00 04
  <LE uint32 totallen>
  <lp(user)> <lp(realm)> <lp(nonce)> <lp(uri)>
  <lp(cnonce)> <lp(snc)> <lp(digest)> <lp(qop)>
  ```

  `totallen = len(user)+len(realm)+len(nonce)+len(uri)+len(cnonce)+len(snc)+len(digest)+7`
  and, for `authType == 4`, `+ len(qop) + 1`.

  Note `MD5` here is protocol-mandated (RFC 2617 digest). It is not a security
  choice we get to make. Use `hashlib.md5(..., usedforsecurity=False)` so FIPS
  builds and linters do not object.

- **`status == 0`** — authenticated. For IDE-R, the session is now live: start the
  IDE-R engine and feed it any bytes remaining in the accumulator past this message.

Note `authType == 3` (digest without cnonce) exists; MeshCentral has it commented out.
Do not implement it.

---

## 4. IDE-R protocol

Once authenticated, every message uses an 8-byte header:

```
[0]     command id
[1..2]  0x00 0x00
[3]     attributes
[4..7]  sequence number (LE uint32)
```

`attributes`: bit 0 (`0x01`) = DMA; bit 1 (`0x02`) = "completed", set only when
`cmdid > 50`. Sequence numbers increment independently per direction. If a received
sequence number does not match the expected inbound counter, tear the session down —
do not attempt resync.

### 4.1 Open session

Client sends `0x40` with 10 bytes of payload:

```
LE uint16 rx_timeout   (default 30000)
LE uint16 tx_timeout   (default 0)
LE uint16 heartbeat    (default 20000)
LE uint32 version      (1)
```

Firmware replies `0x41` OPEN_SESSION_REPLY:

```
[8]     major
[9]     minor
[10]    fw major
[11]    fw minor
[16..17] readbfr   (LE uint16)  max bytes per read reply
[18..19] writebfr  (LE uint16)
[21]    proto      must be 0
[25..28] iana      (LE uint32)
[29]    len        trailing data length
total   30 + len
```

Validate: `proto == 0`, `readbfr <= 8192`, `writebfr <= 8192`. Abort otherwise.
`readbfr` is the hard chunk size for `SendDataToHost` — respect it.

Immediately after, send `0x48` DisableEnableFeatures with type `3` (REGS_TOGGLE)
and a 4-byte LE payload selecting when IDE-R engages:

| Start mode | Payload |
|---|---|
| On next reboot | `0x01 + 0x08` = `0x09` |
| Graceful | `0x01 + 0x10` = `0x11` |
| Immediate | `0x01 + 0x18` = `0x19` |

### 4.2 Command IDs

Inbound (firmware → us):

| ID | Name | Fixed len | Handling |
|---|---|---|---|
| `0x41` | OPEN_SESSION_REPLY | 30+len | validate, send feature toggle |
| `0x43` | CLOSE | 8 | stop session |
| `0x44` | KEEPALIVE_PING | 8 | reply `0x45` |
| `0x45` | KEEPALIVE_PONG | 8 | no-op |
| `0x46` | RESET_OCCURRED | 9 | if idle reply `0x47`; if a read is in flight, defer `0x47` until it drains and flush the read queue |
| `0x49` | STATUS_DATA | 13 | see below |
| `0x4A` | ERROR_OCCURRED | 11 | log; do **not** stop |
| `0x4B` | HEARTBEAT | 8 | no-op |
| `0x50` | COMMAND_WRITTEN (SCSI CDB) | 28 | dispatch SCSI |
| `0x53` | DATA_FROM_HOST | 14+len | **write path — see §5** |

`0x49` STATUS_DATA: `[8]` = type, `[9..12]` = LE uint32 value.
- type `1` REGS_AVAIL: if `value & 1`, re-send the feature toggle.
- type `2` REGS_STATUS: `enabled = bool(value & 2)`.
- type `3` REGS_TOGGLE: `value != 1` means the toggle failed.

Outbound (us → firmware):

| ID | Name |
|---|---|
| `0x40` | OPEN_SESSION |
| `0x45` | KEEPALIVE_PONG |
| `0x47` | RESET_OCCURRED_RESPONSE |
| `0x48` | DISABLE_ENABLE_FEATURES |
| `0x51` | COMMAND_END_RESPONSE (SCSI sense) |
| `0x52` | GET_DATA_FROM_HOST (request write payload) |
| `0x54` | DATA_TO_HOST (SCSI read reply) |

`0x50` COMMAND_WRITTEN layout: `[9]` = feature register (bit 0 = DMA),
`[14]` = device flags (bit 4 set → device `0xB0` CD/DVD, else `0xA0` floppy),
`[16..27]` = 12-byte SCSI CDB.

### 4.3 Outbound frame payloads

**`0x51` COMMAND_END_RESPONSE** — 23-byte payload, `completed = True`.

Error form:
```
00*12, 0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, <device>, 0x50, 0x00, 0x00, 0x00
```
Sense form:
```
00*12, 0x87, (sense << 4), 0x03, 0x00, 0x00, 0x00, <device>, 0x51, <sense>, <asc>, <asq>
```

**`0x54` DATA_TO_HOST** — 26-byte prefix then the data:

```
00,
len & 0xFF, len >> 8,
00,
0xB4 if dma else 0xB5,
00, 02, 00,
dmalen & 0xFF, dmalen >> 8,      # dmalen = 0 when dma else len
<device>, 0x58,
# then, if completed:
0x85, 00, 03, 00, 00, 00, <device>, 0x50, 00, 00, 00, 00, 00, 00
# else fourteen 0x00 bytes
```

**`0x52` GET_DATA_FROM_HOST** — 23-byte payload, `completed = False`:

```
00, chunk & 0xFF, chunk >> 8, 00, 0xB5, 00, 00, 00,
chunk & 0xFF, chunk >> 8, <device>, 0x58, 00 * 11
```

### 4.4 Device model and sector sizes

| Device | Code | Sector size | Blocks |
|---|---|---|---|
| Floppy / USB-R | `0xA0` | **512** | `size >> 9` |
| CD/DVD | `0xB0` | **2048** | `size >> 11` |

Image files must be a multiple of 512 bytes. Reject otherwise.
An LBA from the host is in sectors; convert with the device's shift before seeking.

### 4.5 SCSI commands to implement

| CDB[0] | Command | Behaviour |
|---|---|---|
| `0x00` | TEST_UNIT_READY | If no medium: sense `0x02`, asc `0x3A`. First call per device: report the media-change unit-attention (sense `0x06`, asc `0x28`) once, then ready |
| `0x08` | READ_6 | lba = `((cdb[1]&0x1F)<<16)|(cdb[2]<<8)|cdb[3]`, len = `cdb[4]` (0 → 256) |
| `0x0A` | WRITE_6 | **write path** |
| `0x1A` | MODE_SENSE_6 | For `cdb[2]==0x3F`: 4-byte reply `[0, a, b, 0]`; floppy a=`0x00`, CD a=`0x05`; `b` = `0x80` write-protected, `0x00` writable |
| `0x1B` | START_STOP | ack |
| `0x1E` | ALLOW_MEDIUM_REMOVAL | ack, or no-medium sense |
| `0x23` | READ_FORMAT_CAPACITIES | 12-byte capacity descriptor |
| `0x25` | READ_CAPACITY | 8 bytes: BE uint32 `blocks-1`, then `[0,0,blocksize_hi,0]` (`0x08` for CD = 2048, `0x02` for floppy = 512). Reply with `deviceFlags`, not `dev` |
| `0x28` | READ_10 | lba = BE uint32 at `cdb[2]`, len = BE uint16 at `cdb[7]` |
| `0x2A` | WRITE_10 | **write path** |
| `0x2E` | WRITE_AND_VERIFY | **write path** |
| `0x43` | READ_TOC | CD only; canned responses per format 0/1, msf flag |
| `0x46` | GET_CONFIGURATION | feature descriptors; see §4.6 |
| `0x4A` | GET_EVENT_STATUS_NOTIFICATION | 4 bytes `[0, present, 0x80, 0]`, `present = 0x02` when medium loaded |
| `0x51` | READ_DISC_INFO | sense `0x05`/`0x20` (not implemented) is accepted by BIOSes |
| `0x55` | MODE_SELECT_10 | sense `0x05`/`0x20` |
| `0x5A` | MODE_SENSE_10 | canned page arrays per page code and device |
| `0xAC` | GET_PERFORMANCE | canned 8-byte reply |
| default | — | sense `0x05`, asc `0x20` (invalid command) |

Canned MODE_SENSE / GET_CONFIGURATION byte arrays: copy verbatim from
`amt-ider-module.js` (Apache-2.0). They encode drive geometry the BIOS expects.
Floppy vs LS-120 page selection is by `sectorCount <= 0xB40`.

### 4.6 Read path and backpressure

`readbfr` from OPEN_SESSION_REPLY caps a single `0x54`. A large READ_10 must be
split into successive `0x54` frames, with `completed` set only on the last.
Only one read may be in flight; queue further reads. On RESET_OCCURRED mid-read,
finish the current chunk, then send `0x47` and discard the queue.

This is a state machine, not a loop. Model it explicitly.

---

## 5. Writable media — our extension beyond MeshCentral

MeshCentral's IDE-R is **read-only**. It answers `WRITE_6` with
"no medium" (sense `0x02`, asc `0x3A`), stubs `0x53` DATA_FROM_HOST with a canned
error sense, and hardcodes the MODE_SENSE write-protect bit to `0x80`. This
collection must support writable media, so all three change.

### 5.1 What is genuinely achievable

- **Floppy / USB-R device (`0xA0`) — writable.** 512-byte sectors, `WRITE_6`,
  `WRITE_10`, `WRITE_AND_VERIFY` all map cleanly onto seek-and-write against a raw
  image opened `r+b`. This is the writable path.
- **CD/DVD device (`0xB0`) — read-only, by design.** `GET_CONFIGURATION` advertises
  the CD-ROM profile (`0x0008`). Advertising a writable optical profile would require
  emulating a burner (track/session management, `READ_DISC_INFO`, `RESERVE_TRACK`,
  `CLOSE_TRACK_SESSION`), and BIOSes generally will not boot such a device. Keep the
  ISO slot read-only and say so plainly in module docs.

So "writable media" means: **boot the read-only ISO on `0xB0` while presenting a
writable raw image on `0xA0`**. Both devices can be attached in the same session.
That combination is what makes unattended installs work, because installers look for
answer files on removable media and often want to write results back.

For Proxmox VE specifically this is the mechanism that matters: the automated
installer (`proxmox-auto-install-assistant`) reads `answer.toml` from removable
media, so the writable `0xA0` image carries the answer file and can collect
post-install artifacts.

Do not describe the CD slot as writable anywhere in docs or return values.

### 5.2 Implementation changes

1. **Track pending writes.** `WRITE_6` / `WRITE_10` / `WRITE_AND_VERIFY` must record
   `(device, lba, length)` as pending state, then send `0x52` GET_DATA_FROM_HOST for
   `512 * len` bytes. The existing code discards this context, which is why its
   `0x53` handler can only return a canned error.

2. **Implement `0x53` DATA_FROM_HOST for real.** Payload length is LE uint16 at
   offset `9`; data begins at offset `14`. Seek to `lba << 9` in the writable image,
   write the bytes, `flush()`, then reply `0x51` with success sense
   (`error=False, sense=0x00, asc=0x00, asq=0x00`). Firmware may split one write
   across several `0x53` frames — advance the pending offset per frame and only
   complete when the full expected length has arrived.

3. **Report the medium as writable.** In `MODE_SENSE_6` (`0x1A`) and the
   `MODE_SENSE_10` (`0x5A`) page arrays, the write-protect bit is `0x80`.
   Set it to `0x00` when the image was opened writable. The `0x5A` canned arrays
   are shared constants — copy before mutating, never patch the module-level bytes
   in place.

4. **Fail closed.** If the image was opened read-only (or `writable: false`), keep
   the old behaviour: write-protect bit `0x80`, and answer writes with sense `0x07`
   asc `0x27` (write protected) — not `0x02`/`0x3A` "no medium", which is misleading.

5. **Bounds-check every write** against image size exactly as reads are checked
   (`lba + len > mediaBlocks` → sense `0x05`, asc `0x21`, illegal LBA). A host that
   writes past the end must not extend the file.

6. **Never write to the ISO.** Guard on device code, not on filename.

### 5.3 Safety

Writable IDE-R hands a remote BIOS/OS raw block access to a local file. Therefore:

- `writable: false` is the default. Writability is opt-in per image.
- Refuse to open a writable image that is a symlink, or that resolves outside a
  caller-supplied allowed directory when one is given.
- Never open the ISO read-write.
- Log total bytes written in the operation receipt so callers can detect surprises.

---

## 6. Error classification

Map every failure onto one of these stable classes and never leak secrets:

| Class | Trigger |
|---|---|
| `connection` | TCP/DNS failure, connection refused, port closed |
| `tls_validation` | chain/hostname failure, fingerprint mismatch, insecure transport not acknowledged |
| `authentication` | HTTP 401, digest rejected, redirection auth failure |
| `unsupported_capability` | firmware lacks the feature, boot source absent |
| `invalid_state` | operation illegal from the current power/redirection state |
| `timeout` | operation timeout; must distinguish before-send from after-send |
| `protocol` | malformed SOAP, bad IDE-R framing, out-of-sequence |
| `remote_operation` | valid request, non-zero AMT `ReturnValue` |
| `identity_mismatch` | endpoint evidence disagrees with reviewed inventory binding |

Redaction is mandatory in every path that produces a message: strip passwords,
`Authorization` headers, digest responses, cookies, and cap any SOAP or hex dump
excerpt (2 KB is enough). A timeout *after* sending a mutation must surface as
`indeterminate`, not as a plain failure, so the caller re-probes instead of retrying.

---

## 7. Sources

- MeshCentral (Apache-2.0), Ylian Saint-Hilaire / Intel Corporation —
  `amt/amt-wsman.js`, `amt/amt.js`, `amt/amt-redir-mesh.js`,
  `amt/amt-ider-module.js`, `agents/meshcmd.js`
- `parmstro/intel_amt` (GPL-3.0-or-later) — `plugins/module_utils/wsman.py`,
  the hardware-verified AMT 10.0.56 TLS findings in
  `development/research/AMT_10_TLS_LIMITATION.md`, and the AMT 10.0.56 property
  dumps and verb findings in `development/research/AMT_RESOURCE_DISCOVERY.md` and
  `development/research/AMT_10_CAPABILITIES.md` (§2.7). Their *research notes* are
  the trustworthy artefact; their module code and user documentation are not, and
  no code was taken from them
- Intel AMT Implementation and Reference Guide — power state, boot configuration,
  redirection enablement, manageability ports, security considerations

Attribution for the Apache-2.0 derived work is recorded in `NOTICE`.

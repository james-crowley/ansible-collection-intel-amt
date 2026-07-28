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
| 5 | Power Cycle (soft) | `on` |
| 6 | Off - Hard | `off` |
| 7 | Hibernate | `hibernate` |
| 8 | Off - Soft | `off` |
| 9 | Power Cycle (off-hard) | `off` |
| 13 | Off - Hard Graceful | `off` |

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
   Some AMT versions do not clear it automatically. Pass an empty `Source`.
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
  and the hardware-verified AMT 10.0.56 TLS findings in
  `development/research/AMT_10_TLS_LIMITATION.md`
- Intel AMT Implementation and Reference Guide — power state, boot configuration,
  redirection enablement, manageability ports, security considerations

Attribution for the Apache-2.0 derived work is recorded in `NOTICE`.

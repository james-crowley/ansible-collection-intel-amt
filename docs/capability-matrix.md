<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Capability matrix: what is actually verified

This is a plain accounting of confidence levels in this collection, so a reader does
not have to guess which claims rest on real firmware evidence and which rest on
reading someone else's source code. Four tiers, and nothing here should be read as
implying a higher tier than it earns:

1. **Verified against an authoritative source** — confirmed against a real firmware
   response fixture, a vendor reference implementation, or hardware-verified
   third-party research. This is the strongest claim this document makes, and it is
   still not the same as "tested on our hardware."
2. **Unit/mock tested** — exercised by this collection's own test suite against
   deterministic fixtures/fakes, never against real AMT firmware.
3. **Verified against real firmware** — on two lab endpoints via a self-hosted
   CircleCI runner: all eight qualification stages on machine 1 (Intel AMT
   **16.1.30**, 2026-07-28) and all eight on machine 2 (Intel AMT **19.0.5**,
   2026-07-29). The read-only stages were then re-run against machine 1 on
   2026-07-29, which closed the last difference in coverage between the two runs:
   `amt_info`'s network and system-state facts have now come back populated on
   **both** generations, so this tier no longer has to state that particular
   claim per generation.
4. **Still unproven** — a short, specific list, kept honest.

The collection is no longer "hardware-unverified". Hardware qualification found
**six real defects** that neither the unit tier nor the mock-integration tier
could have found:

| Defect | Why the mocks could not catch it |
|---|---|
| `enum.StrEnum` / `datetime.UTC` on a Python 3.10 controller | mocks run on the same Python as the unit tests |
| `uuid` read from `CIM_ComputerSystem`, which has no such property | the mock served whatever property the code asked for |
| `PlatformGUID` needing SMBIOS little-endian field order | self-consistent either way without a real machine to compare against |
| empty `<Source/>` rejected by the firmware's own schema | the mock's XML parser accepted the empty element happily |
| role always issuing `reset`, which does nothing to a powered-off machine | required actually leaving a machine off, then trying to boot it |
| role connection defaults resolving to `inventory_hostname` | any mock inventory happens to make that resolvable |

That is the argument for the hardware tier existing, stated concretely rather
than in principle.

## Tier 1: Verified against an authoritative source

| Claim | Source | Where used |
|---|---|---|
| `AMT_BootCapabilities` field names — `ForcePXEBoot`, `ForceHardDriveBoot`, `ForceCDorDVDBoot`, `BIOSSetup`, `IDER`, `SOL` | Real firmware response fixture, `device-management-toolkit/go-wsman-messages` (`pkg/wsman/wsmantesting/responses/amt/boot/capabilities/get.xml`), per `docs/protocol-notes.md` §2.5 | `plugins/module_utils/boot.py` (`_CAPABILITY_FIELD_BY_TARGET`), `plugins/module_utils/redirection_service.py` (`RedirectionCapabilities`) |
| The firmware version lives in `CIM_SoftwareIdentity` (`InstanceID == "AMT"`, field `VersionString`), not on `AMT_GeneralSettings` or `AMT_SetupAndConfigurationService` | Class definitions in `device-management-toolkit/go-wsman-messages`; matches how MeshCmd (`agents/meshcmd.js`) reads it | `plugins/module_utils/client.py` (`AmtClient._get_amt_version`) |
| CIM power-state table (2=On, 3/4=Sleep, 6/8/9/13=Off, 7=Hibernate) and `RequestPowerStateChange` action codes (2/3/4/5/7/8/10) | MeshCmd, cross-checked against firmware per `docs/protocol-notes.md` §2.4 ("as used by MeshCmd, verified against firmware") | `plugins/module_utils/client.py`, `plugins/module_utils/models.py` |
| The five-step boot-configuration sequence (clear → mutate → Put → set role → set order) and its field delete-list | MeshCentral (`amt/amt-wsman.js`, `amt/amt.js`), Apache-2.0 | `plugins/module_utils/boot.py` |
| The IDE-R/redirection wire framing (session start, digest auth over the binary protocol, SCSI command set, canned MODE_SENSE/GET_CONFIGURATION byte arrays) | MeshCentral (`amt/amt-redir-mesh.js`, `amt/amt-ider-module.js`), Apache-2.0 | `plugins/module_utils/redirection.py`, `plugins/module_utils/ider.py` |
| AMT provisioned in Small Business Mode never opens port 16993 (no TLS at all) | **Hardware-verified** by `parmstro` on an Intel NUC5i5MYBE, AMT 10.0.56 build 3002 (`parmstro/intel_amt`, GPL-3.0-or-later, `development/research/AMT_10_TLS_LIMITATION.md`) | `plugins/doc_fragments/connection.py`, `plugins/module_utils/tls.py` (`enforce_transport_policy`) — this is *why* the plaintext opt-in exists at all |

Every row above is a claim about the **protocol**, verified against something other
than this collection's own code. None of them is a claim that this collection's
*implementation* of the protocol has been exercised against real firmware — that is
Tier 3.

---

## Tier 2: Unit/mock tested

This is the bulk of the collection's verification effort:

- **761 unit tests** (measured via `pytest --collect-only` against the staged
  collection tree; the number will drift as tests are added, so treat this as a point
  measurement, not a promise) across `tests/unit/plugins/module_utils/` and
  `tests/unit/plugins/modules/`, covering error classification/redaction, TLS trust
  policy, the WS-Man envelope/SOAP layer, the boot five-step sequence, the redirection
  handshake, the IDE-R SCSI state machine, the media-session daemon lifecycle, and
  every module's argument handling, check-mode behaviour, and idempotence logic —
  all against fakes/mocks, never a socket or a real AMT endpoint.
- **5/5 integration targets** (`amt_boot`, `amt_info`, `amt_media`, `amt_power`,
  `amt_redirection` under `tests/integration/targets/`) run end-to-end against local,
  deterministic fixture servers: a mock WS-Man server (HTTP Digest, TLS with a
  generated self-signed certificate, canned per-resource-URI responses, fault
  injection for AMT error codes/malformed SOAP/401/timeouts) and a mock IDE-R server
  (session start, auth-type query, digest challenge, configurable `readbfr`, a write
  path that verifies bytes actually land in the backing image). See
  `docs/testing.md` for how to run these and exactly what they do and do not prove.

### `amt_info`'s network and system-state facts — mock coverage, with hardware now in Tier 3

`amt.network` (`AMT_EthernetPortSettings` instance 0), `amt.system_state`
(`CIM_ComputerSystem`), `amt.bios_version` (`CIM_BIOSElement`) and the six extra
`AMT_GeneralSettings` fields (`domain_name`, `idle_wake_timeout`,
`ping_response_enabled`, `rmcp_ping_response_enabled`, `network_interface_enabled`,
`ddns_update_enabled`) used to be this document's headline Tier 2 entry, on the
argument that no lab machine had ever returned any of them. **That argument expired
on 2026-07-29**, when every one of them came back populated from real AMT 19.0.5
firmware and then, on a re-run of the read-only stages the same day, from real AMT
16.1.30 firmware as well. Both reads are recorded in Tier 3 below.

What stays Tier 2 is the part hardware did not and cannot establish, and it is what
made the hardware result legible the moment it arrived:

- **The parsing and decoding breadth.** Parsing of every property, MAC normalization
  from dash, colon and bare-hex input, `LinkPolicy` decode including the empty and
  absent cases, both candidate `LinkPolicy` wire shapes, every DMTF `EnabledState`
  and `OperationalStatus` value, and graceful `null` degradation when any class
  faults — plus an end-to-end pass of `amt_info` against the mock WS-Man server,
  which serves the MAC dash-separated and requires the exact `Get` selector for
  `AMT_EthernetPortSettings` because that is what real AMT 10 does. Two live
  endpoints exercise whichever paths those two happen to take; the suite exercises
  all of them. Both lab machines returned `link_policy` as a populated integer
  array, for instance, so neither of them exercises the absent or empty cases the
  suite covers.
- **Where the property names came from**, which is not Tier 1. Tier 1 means verified
  against an authoritative source: a vendor reference implementation or a real
  firmware response fixture. These rest on a third party's hardware dump of *one*
  machine (`parmstro`, Intel NUC5i5MYBE, AMT **10.0.56** build 3002,
  `development/research/AMT_RESOURCE_DISCOVERY.md`, GPL-3.0-or-later) — property names
  and observed values, transcribed into `docs/protocol-notes.md` §2.7. That is real
  hardware evidence, but from someone else's lab, on a firmware generation this
  collection has never touched, and the surrounding project's *code* is demonstrably
  unreliable (three of its ten modules report success while doing nothing; its power
  constants map `reset` to CIM code 11, Diagnostic Interrupt/NMI, rather than 10,
  Master Bus Reset). Property names from those notes were used; no code was. What
  confirmed those names resolve on firmware this collection can actually reach is
  the pair of 2026-07-29 reads, on 19.0.5 and on 16.1.30. So these field names now
  rest on **three firmware generations' worth of evidence**: named from a third
  party's 10.0.56 dump, and read back populated by this collection on 16.1.30 and
  19.0.5.
- **The one Tier 1 row here** is the DMTF decoding itself: `EnabledState` and
  `OperationalStatus` come from the DMTF CIM schema, not from anyone's dump. The
  source project's implementation decodes only `OperationalStatus` values 0 and 2 and
  omits `EnabledState` 4 (shutting down) entirely; the full standard tables are
  implemented here instead.
- **`bios_version` was the weakest-evidenced field**, and is much less so now.
  `CIM_BIOSElement` is listed as working in `parmstro`'s notes but no value was ever
  dumped, and the implementation they claim it from swallows failure to `None` — so
  their "pass" was never evidence either way. It is read through the optional path
  with an `Enumerate` fallback. Both lab generations have now returned a value.
  `null` remains a legitimate outcome on firmware that does not expose the class,
  and the optional path stays in place for exactly that reason.

What mock testing genuinely buys: confidence that this collection's own code
correctly implements *its own understanding* of the protocol, consistently, across
every option combination, error path, and check-mode branch this test suite
exercises. What it cannot buy, by construction, is confidence that this collection's
understanding of the protocol matches what a specific piece of real firmware does —
see `docs/testing.md`'s "What CI does not prove" section, which is deliberately blunt
about this.

---

## Tier 3: Verified against real firmware

Two machines have now each completed **all eight** stages, on the lab's self-hosted
CircleCI runner (`crowley/amt-runner`), with TLS pinned to each endpoint's own
reviewed leaf certificate. Three runs contributed, on different dates and in
different runner environments, and each is recorded as itself rather than averaged
into one:

- **`amt-lab-01` (machine 1), AMT 16.1.30** — all eight stages, 2026-07-28, on
  Python 3.10 with ansible-core 2.17.
- **`amt-lab-02` (machine 2), AMT 19.0.5** — all eight stages, 2026-07-29, on
  Python 3.12.13 with ansible-core 2.18.18. That run was deliberately limited to
  machine 2 (`hardware-limit=amt-lab-02`); machine 1 was not touched by it.
- **`amt-lab-01` (machine 1) again, read-only stages only** — stages 1, 3 and 8,
  2026-07-29, limited to machine 1 (`hardware-limit=amt-lab-01`), on the
  ansible-core 2.18.18 lab virtualenv every hardware job now builds. Nothing was
  mutated: this run existed to read machine 1 with the v0.2.0 fact code, which its
  2026-07-28 evidence predated. Machine 1's mutating result stands on the
  2026-07-28 run and was not re-established here.

So power control, IDE-R media, the writable-image path and native one-time PXE are
verified on **two machines across two firmware generations**, not one — and
`amt_info`'s network and system-state facts are now verified on both of those
generations too, which is what the third run added. See the subsection at the end
of this tier.

| Stage | Machines | What real firmware confirmed |
|---|---|---|
| 1 read-only | 1 and 2 | `amt_info` over pinned TLS with HTTP Digest. Firmware version from `CIM_SoftwareIdentity`, all four capability flags, power state `2 -> on`, the platform UUID, and `AMT_RedirectionService.EnabledState` decoded on two different values (`32769` = IDER only on machine 1; `32771` = SOL+IDER on machine 2). Machine 1 was read again on 2026-07-29, which is where its network and system-state facts below come from |
| 2 identity cross-check | 1 and 2 | Each machine returned a **distinct** platform UUID, and both rendered with UUID version nibble `1` after the SMBIOS little-endian field reversal — independent corroboration of the byte-order fix on a second, unrelated GUID. This stage has **no playbook of its own**: it is the review step inside `qualify_readonly.yml`. On 2026-07-29 its comparison **executed for the first time** against a recorded `amt_expected_uuid` for machine 2 and matched; see the note below the table for exactly what a match does and does not prove |
| 3 check mode | 1 and 2 | power and boot plans computed and **nothing mutated** |
| 4 power | 1 and 2 | convergent `on` reported `changed: false` when already on; `off` reported `changed: true`; initial state restored afterwards. Reproduced on machine 2 with the same outcomes |
| 5 IDE-R media | 1 and 2 | the native Python IDE-R engine served a real bootable ISO to real firmware, and the boot was armed and reset issued |
| 6 writable image | 1 and 2 | the device was presented **writable** — MODE_SENSE write-protect bit `0x00`, not `0x80`. On machine 2: `devices.floppy.writable = true`, `bytes_read = 0`, `bytes_written = 0`, `error_class = null` — same shape as machine 1, a writable device with no bytes transferred |
| 7 native PXE | 1 and 2 | one-time PXE armed and read back as armed, reset issued and recovered, `AMT_BootSettingData` stable afterwards. On machine 2 the `before_arm` and `after_reset` snapshots agree, with `UseIDER=false`, `BIOSSetup=false`, `BootMediaIndex=0`. This also settled issue #13: the prefixed-namespace EPR form **is** accepted by real firmware, now on both generations |
| 8 idempotent re-probe | 1 and 2 | repeated reads reported `changed: false` and agreed with each other; no session or state was left drifting behind the stages above |

**What stage 2's match actually proves.** `amt_expected_uuid` is recorded from a
value this collection itself observed on an earlier run, so a match detects **drift**
— a reused DHCP lease, a swapped inventory suffix, a re-racked machine — between the
inventory entry and the endpoint answering on it. It is **not** independent
confirmation of machine identity: that would require comparing against a source
outside this collection's own read path, such as the booted OS's own
`dmidecode -s system-uuid`, which CI has no way to reach. The stage was previously a
documented no-op because nothing ever supplied a value; it is a live comparison now,
with that scope.

Stage 7's evidence file carries the playbook's own caveat verbatim:
`"before_arm/after_reset compare AMT_BootSettingData only -- neither reads the
internal one-shot role bit"`. The stability result is exactly that and no more.

Notably the same firmware **does** enforce its SOAP schema on `ChangeBootOrder` —
it rejected an empty `<Source/>` with HTTP 400 — which is what makes the stage-7
EPR result meaningful rather than merely permissive.

### `amt_info`'s network and system-state facts — Tier 3 on both lab generations

The v0.2.0 facts (`amt.network`, `amt.system_state`, `amt.bios_version` and the six
extra `AMT_GeneralSettings` fields) were argued in Tier 2 above on the grounds that no
lab machine had ever returned them. Both lab machines have now returned **every one of
them, populated — nothing `null`, no class faulted**: machine 2 on its stage-1 read of
2026-07-29, and machine 1 on the read-only re-run the same day.

| Fact | 16.1.30 (machine 1) | 19.0.5 (machine 2) |
|---|---|---|
| `version` | `"16.1.30"` | `"19.0.5"` |
| `network.ip_address`, `subnet_mask`, `default_gateway` | populated | populated |
| `network.primary_dns`, `secondary_dns` | populated | populated |
| `network.mac_address`, `mac_address_raw` | populated | populated |
| `network.dhcp_enabled` | `false` | `false` |
| `network.link_is_up` | `true` | `true` |
| `network.link_policy` | `[1, 14]` | `[1, 14]` |
| `network.link_policy_names` | `["s0_ac", "s0_dc"]` | `["s0_ac", "s0_dc"]` |
| `network.wake_on_lan_capable` | `false` | `false` |
| `network.ip_sync_enabled` | `false` | `false` |
| `system_state.element_name` | `"Managed System"` | `"Managed System"` |
| `system_state.enabled_state` / `enabled_state_text` | `2` / `"enabled"` | `2` / `"enabled"` |
| `system_state.operational_status` / `operational_status_text` | `[0]` / `["unknown"]` | `[0]` / `["unknown"]` |
| `system_state.requested_state` | `12` | populated |
| `bios_version`, `domain_name` | populated | populated |
| `idle_wake_timeout` | `65535` | `65535` |
| `ping_response_enabled`, `rmcp_ping_response_enabled`, `network_interface_enabled` | `true` | `true` |
| `ddns_update_enabled` | `false` | `false` |

Real values are deliberately not transcribed here: the evidence artifacts carry live
lab addressing, and this repository holds no lab identifiers. "populated" means the
field came back non-`null` and its class did not fault, which is the whole of what is
being claimed for it.

`link_policy_names` and `requested_state` are the two fields the machine-1 read added
to the itemised record — both confirmed populated, `requested_state` deliberately left
undecoded by the module. Where a cell above reads "populated" for 19.0.5 rather than
naming a value, that value was not itemised in machine 2's record; it was covered by
that run's "nothing `null`, no class faulted" result, and is reported here at exactly
that strength.

**These fields are now hardware-verified on both lab generations**, so the per-
generation caveat that used to live here is gone. Combined with where the property
names came from (Tier 2 above), they rest on evidence spanning three firmware
generations: named from a third party's AMT **10.0.56** dump, read back populated by
this collection on **16.1.30** and **19.0.5**. Every generation outside those three
remains untouched.

Two protocol details are hardware-confirmed rather than inferred, and on both
generations rather than one:

- **`operational_status` really is an array** (`uint16[]`), not a scalar — live
  firmware returned `[0]` on both machines. A parser that read only element 0 would
  have worked here, but the array shape itself is no longer an assumption.
- **`idle_wake_timeout` came back `65535`** on both machines, the maximum value the
  field can hold. That is reported, not interpreted: nothing available establishes
  what this firmware means by that value, so no behaviour should be inferred from it.
  Two machines agreeing on the maximum is worth noting precisely because it makes an
  unconfigured default the likelier reading than a deliberate setting — but that is a
  guess, and it is not being recorded as a finding.

### Both machines report `wake_on_lan_capable = false`

The single most operationally useful thing the two reads agree on. Both machines
returned `link_policy` `[1, 14]`, which decodes to `s0_ac` and `s0_dc` — S0, meaning
*while the machine is powered on*, on AC power and on battery. The value that would
mean otherwise, **`16` ("network link always on"), is absent on both**, so
`wake_on_lan_capable` is `false` on both.

Read literally, that policy says AMT keeps its network link up only while the host is
already powered on. If that is what it means in practice, then `amt_power state=on`
against a genuinely powered-off endpoint would never reach the management plane at
all, and the failure would surface as `error_class: connection` — indistinguishable
from a wrong address, a dead switch port or a firewall rule. That is exactly the
diagnostic value [`amt_info`'s documentation](amt_info.md) claims for this field, and
it is now measured on real firmware rather than hypothetical.

**What this does not establish.** Nothing in the evidence shows whether these machines
can or cannot be woken from off by AMT. No deliberate power-off-then-power-on test has
been run against either of them. Machine 1's stage 4 did pass on 2026-07-28 including
an `off` transition and a restore, which is hard to square with an endpoint that is
unreachable while off; the most plausible reconciliation is that the machine was
already off when the stage began, making both transitions no-ops, but that is a
reading of the result and not something the result states. So: the policy value that
would *guarantee* link-up-while-off is absent on both machines, that absence is the
first thing to suspect if a remote power-on ever fails, and whether wake-from-off
actually works here is untested — see Tier 4.

## Tier 4: Still unproven

A short list, deliberately.

- **The sleep and hibernate power actions.** `amt_power` accepts `sleep-light`
  (CIM code 3), `sleep-deep` (code 4) and `hibernate` (code 7), and the codes and
  expected-state mappings are unit-tested, but no hardware stage has issued any of
  them. Stage 4 exercised only `on`/`off`. These three also depend on the target
  operating system supporting the corresponding ACPI state, so a failure against
  real hardware would not necessarily indicate a defect in this collection — which
  is exactly why they are listed here rather than claimed.
- **A non-zero IDE-R write.** Stage 6 proves the device is accepted, attached and
  presented writable, and that the session stays healthy. It does **not** prove
  bytes were written, because nothing at the other end issues a SCSI write: a
  BIOS sitting at a boot prompt does not spontaneously write to an attached
  floppy. `bytes_written == 0` is the expected unattended outcome and is reported
  as such — and it is now the observed outcome on **both** machines, across both
  firmware generations, which strengthens that explanation rather than weakening
  it: the zero is a property of the unattended setup, not of one endpoint. Proving
  a real write needs an operating system on the target that writes.
- **That a PXE exchange actually happened.** Stage 7 proves the arming, the reset
  and the recovery. Whether the machine reached a DHCP/TFTP exchange depends on
  boot services this collection cannot observe.
- **That AMT's internal one-shot role bit was consumed.** No module exposes a read
  path for it, so stage 7 asserts `AMT_BootSettingData` stability instead. The
  headline claim that a one-time boot "does not persist" is therefore
  *inferred*, not directly measured.
- **Whether either endpoint answers WS-Man while powered off.** Both machines
  report `wake_on_lan_capable = false` and neither carries `link_policy` value `16`
  (see the subsection at the end of Tier 3), so on a literal reading of the policy
  neither keeps its link up once the host powers down — which would make
  `amt_power state=on` unreachable against a genuinely off machine. **That has not
  been tested.** No stage powers a machine off, confirms it is off, and then tries
  to reach it; stage 4's `off` and restore on machine 1 are consistent with a
  machine that was already off, so they do not settle it either. The specific
  missing test is a deliberate power-off, an independent confirmation that the
  machine is off, and then a WS-Man read — until that runs, this document claims
  neither that wake-from-off works nor that it is broken.
- **Any firmware generation other than 16.1.30 and 19.0.5.** Both lab generations
  have now been mutated through stages 4 to 7 and read with the full v0.2.0 fact
  set, so neither "mutating anything at all" nor "reading the network and
  system-state facts" is a single-generation result any more. Every generation
  outside those two is still untouched, including the Small Business Mode / no-TLS
  path, which is inferred from `parmstro`'s reporting rather than observed here. Two
  generations is repeatability; it is not a compatibility guarantee.

## Known open risks

Each of these is a specific, named gap, not a vague hedge.

### ~~#13 — WS-Addressing EPR byte-form ambiguity~~ (RESOLVED)

Closed by stage 7 on 2026-07-28. `ChangeBootOrder` with a real endpoint
reference naming `Intel(r) AMT: Force PXE Boot` succeeded against AMT 16.1.30,
so the prefixed-namespace form this collection emits is accepted by real
firmware. **Confirmed on a second firmware generation** by stage 7 against AMT
19.0.5 on 2026-07-29 — the same form, accepted again. Kept here rather than
deleted because the reasoning is worth retaining: it could not be settled by
testing, since a conformant XML parser treats both forms as identical.

### Reset-during-write has no IDE-R deferral (reset-during-read does)

`IderEngine._on_reset_occurred()` (`plugins/module_utils/ider.py`) defers its
`RESET_OCCURRED_RESPONSE` reply when a read is in flight (`self._read_state is not
None`) — it finishes draining the current read, then responds and flushes the read
queue, per `docs/protocol-notes.md` §4.6. It has **no equivalent check against
`self._pending_write`**: a `RESET_OCCURRED` that arrives while a write is pending
(between `WRITE_6`/`WRITE_10`/`WRITE_AND_VERIFY` and the `DATA_FROM_HOST` frame(s)
that complete it) is answered immediately, with the pending write left dangling in
`self._pending_write` rather than drained or explicitly aborted first. This is a real
asymmetry in the current implementation, not a documentation gap — the read path was
written with this case in mind; the write path (this collection's own extension
beyond MeshCentral, which never implemented writes) was not.

### AMT in Small Business Mode has no TLS on 16993 at all

Hardware-verified on AMT 10.0.56 (see Tier 1 above) — port 16993 never opens, full
stop, on this provisioning mode. This is the entire reason the explicit plaintext
opt-in (`use_tls: false` **and** `allow_insecure_transport: true`) exists in
`plugins/doc_fragments/connection.py` and is enforced in
`plugins/module_utils/tls.py`. The collection deliberately never auto-probes 16993
and falls back — that would defeat the point of requiring the acknowledgement in the
first place — so a caller managing a Small Business Mode endpoint must set both
options explicitly, every time.

### `amt_media`'s `validate_certs` has no effect, and `ca_path` is rejected

The redirection plane (`plugins/module_utils/redirection.py`,
`RedirectionSession`) implements exactly one trust mode: SHA-256 leaf-certificate
pinning via `tls_fingerprint`, required whenever `use_tls=true`
(`amt_media.enforce_redirection_trust_policy`). `validate_certs` is accepted on
`amt_media` for option-shape parity with the other four modules but does nothing;
`ca_path` is rejected outright with `error_class: tls_validation` rather than
silently ignored, specifically so a caller who sets it does not end up believing the
media session is chain-validated when nothing is checking it. See
[`docs/amt_media.md`](amt_media.md) for the full trust-mode writeup. This is a
deliberate divergence from the WS-Man modules' `ca_path`/`tls_fingerprint`
mutual-exclusion model, not an oversight — the redirection plane has no HTTP layer to
hang chain validation off in the first place.

---

## Return-shape inconsistency across modules (RESOLVED)

Closed by issue #22, the last item before 1.0. **Before** this was fixed, the five
modules disagreed on where the operation receipt lived: `amt_power` nested its
`intel-amt-operation/v1` receipt under an `operation` key, `amt_boot`/`amt_redirection`/
`amt_media` all spread the receipt's fields directly at the top level of the module
result, and `amt_info` used neither shape (it returned a bare `amt` dict with no
receipt at all). That inconsistency was real, not cosmetic: a caller could not write
one helper that reads `error_class` or `tls_peer_fingerprint` from any module in the
collection, and it had already caused a concrete bug (issue #21's README example
referencing `media.operation.session_id`, which never existed).

**Now**, every module returns the receipt nested under an `operation` key —
`amt_power`'s pre-existing shape was the target, and `amt_boot`, `amt_redirection`, and
`amt_media` were changed to match it. `amt_info` gained a receipt for the first time:
read-only, `action: get_facts`, `changed: false` always, and `previous`/`desired`/
`observed` left `null` (a read has no prior/intended/re-observed state distinct from
its own `amt` return key to report — nothing was invented to fill those fields).
Module-specific return values (`amt_power`'s `previous_state`/`desired_state`,
`amt_boot`'s `device`/`boot_config_selector`/`boot_source_selector`,
`amt_redirection`'s `supported`/`enabled`/`transport_reachable`, `amt_media`'s
`session_id`/`session_state`/`devices`/`bytes_read`/`bytes_written`, `amt_info`'s `amt`)
stay exactly where they were — this was a fix to the receipt's location, not a
relocation of everything else.

This is a **breaking change** for anyone reading `amt_boot`/`amt_redirection`/
`amt_media`'s receipt fields (`schema`, `action`, `endpoint`, `previous`, `desired`,
`observed`, `tls_peer_fingerprint`) at the top level — they now live under `operation`.
It does **not** change the shape of a *failed* module's result: `error_class` (and
`endpoint`/`operation`-as-a-string/`indeterminate`/`diagnostic`) still surface at the
top level of `fail_json`, per `errors.py`'s `to_result()`, because that is what Ansible
itself surfaces and what the hardware playbooks' rescue blocks read
(`ansible_failed_result.error_class`). Consult each module's own return-values table
([`amt_info`](amt_info.md), [`amt_power`](amt_power.md), [`amt_boot`](amt_boot.md),
[`amt_redirection`](amt_redirection.md), [`amt_media`](amt_media.md)) for the exact,
now-consistent shape.

---

## Firmware-generation compatibility

**Every row below is inferred from public documentation (Intel's AMT
Implementation and Reference Guide, MeshCentral's generation-conditional logic)
and this collection's own reading of that documentation — not independently tested
against a machine of that generation — except the three rows marked otherwise:**
the TLS-availability finding `parmstro` hardware-verified, and the two lab
generations in Tier 3 above.

| AMT generation | TLS (16993) | IDE-R | SOL | One-time PXE (`ForcePXEBoot`) | Status |
|---|---|---|---|---|---|
| 6.x–9.x | Varies by SKU | Generally present | Generally present | Generally present | **Inferred** — not tested |
| 10.0.56, Small Business Mode | **No** (HTTP 16992 only) | Present | Present | Present | TLS row **hardware-verified** (`parmstro`, NUC5i5MYBE); everything else on this row **inferred** |
| 10.x, Enterprise/other modes | Yes | Present | Present | Present | **Inferred** — not tested |
| 11.x+ Enterprise | Yes | Present | Present | Present | **Inferred** — not tested |
| 12.x+ | Yes, enhanced | Present | Present | Present | **Inferred** — not tested |
| **16.1.30** (machine 1) | Yes, pinned | Verified | Advertised | Verified | **Hardware-verified, all eight stages** (2026-07-28). `amt_info`'s network/system-state facts came back fully populated on a read-only re-run (2026-07-29) |
| **19.0.5** (machine 2) | Yes, pinned | Verified | Advertised | Verified | **Hardware-verified, all eight stages** (2026-07-29). Capability flags were read live and all four came back `true`; the network/system-state facts came back fully populated here too |

"Present" in the IDE-R/SOL/PXE columns means "AMT's published feature set for this
generation includes it," per `docs/protocol-notes.md` §1.1 and Intel's own
documentation — it is not a per-generation claim about the specific
`AMT_BootCapabilities` field values this collection reads, which is exactly what
`amt_info`, `amt_boot`, and `amt_redirection` each discover live from the endpoint
rather than assume from this table. Never use this table as a substitute for a live
`amt_info` capability read.

---

## What would move something from Tier 3 to Tier 1

Per `docs/testing.md`'s qualification order, the eight stages in sequence: a
read-only `amt_info` pass against real hardware (stage 1), a human cross-check of
the reported facts against the physical machine (stage 2, no playbook of its own),
check-mode plans (stage 3), then attended power control (4), IDE-R attach with a
small test ISO (5), the writable-image path (6), one-time PXE (7), and an
idempotent re-probe (8) — one machine all the way through first, a second machine
afterwards to prove repeatability, never both cut over to a new stage at once.

All eight stages have now cleared that bar on two machines of different firmware
generations, machine 1 first and machine 2 afterwards, never both cut over at once,
and the read-only stages have since been re-run against machine 1 so that both
generations have been read with the same fact code. What Tier 4 still lists is
therefore neither "a second machine" nor "a re-run of the first" — it is the
specific things no green run on either machine measures: a real SCSI write, a PXE
exchange, the internal one-shot role bit, the sleep/hibernate actions, and whether
either endpoint answers WS-Man at all while powered off.

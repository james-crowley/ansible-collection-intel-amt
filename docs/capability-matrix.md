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
3. **Verified against real firmware** — as of 2026-07-28, against a lab
   Intel AMT **16.1.30** endpoint via a self-hosted CircleCI runner, through all
   seven qualification stages.
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

- **531 unit tests** (measured via `pytest --collect-only` against the staged
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

What mock testing genuinely buys: confidence that this collection's own code
correctly implements *its own understanding* of the protocol, consistently, across
every option combination, error path, and check-mode branch this test suite
exercises. What it cannot buy, by construction, is confidence that this collection's
understanding of the protocol matches what a specific piece of real firmware does —
see `docs/testing.md`'s "What CI does not prove" section, which is deliberately blunt
about this.

---

## Tier 3: Verified against real firmware

Verified 2026-07-28 against a lab endpoint reporting AMT **16.1.30**, driven from
a self-hosted CircleCI runner (`crowley/amt-runner`, Python 3.10, ansible-core
2.17) with TLS pinned to the endpoint's reviewed leaf certificate.

| Stage | What real firmware confirmed |
|---|---|
| 1-2 read-only | `amt_info` over pinned TLS with HTTP Digest. Firmware version from `CIM_SoftwareIdentity`, all four capability flags, `EnabledState 32771` decoded as SOL+IDER, power state `2 -> on`, and the platform UUID |
| 3 check mode | power and boot plans computed and **nothing mutated** |
| 4 power | convergent `on` reported `changed: false` when already on; `off` reported `changed: true`; initial state restored afterwards |
| 5 IDE-R media | the native Python IDE-R engine served a real bootable ISO to real firmware, and the boot was armed and reset issued |
| 6 writable image | the device was presented **writable** — MODE_SENSE write-protect bit `0x00`, not `0x80` |
| 7 native PXE | one-time PXE armed and read back as armed, reset issued and recovered, `AMT_BootSettingData` stable afterwards. This also settled issue #13: the prefixed-namespace EPR form **is** accepted by real firmware |

Notably the same firmware **does** enforce its SOAP schema on `ChangeBootOrder` —
it rejected an empty `<Source/>` with HTTP 400 — which is what makes the stage-7
EPR result meaningful rather than merely permissive.

## Tier 4: Still unproven

A short list, deliberately.

- **A non-zero IDE-R write.** Stage 6 proves the device is accepted, attached and
  presented writable, and that the session stays healthy. It does **not** prove
  bytes were written, because nothing at the other end issues a SCSI write: a
  BIOS sitting at a boot prompt does not spontaneously write to an attached
  floppy. `bytes_written == 0` is the expected unattended outcome and is reported
  as such. Proving a real write needs an operating system on the target that
  writes.
- **That a PXE exchange actually happened.** Stage 7 proves the arming, the reset
  and the recovery. Whether the machine reached a DHCP/TFTP exchange depends on
  boot services this collection cannot observe.
- **That AMT's internal one-shot role bit was consumed.** No module exposes a read
  path for it, so stage 7 asserts `AMT_BootSettingData` stability instead. The
  headline claim that a one-time boot "does not persist" is therefore
  *inferred*, not directly measured.
- **A second machine.** Everything above is one endpoint, one firmware version.
  Theta is available and would prove repeatability; until it runs, treat AMT
  16.1.30 as the only qualified generation.
- **Any firmware generation other than 16.1.30**, including the Small Business
  Mode / no-TLS path, which is inferred from `parmstro`'s reporting rather than
  observed here.

## Known open risks

Each of these is a specific, named gap, not a vague hedge.

### ~~#13 — WS-Addressing EPR byte-form ambiguity~~ (RESOLVED)

Closed by stage 7 on 2026-07-28. `ChangeBootOrder` with a real endpoint
reference naming `Intel(r) AMT: Force PXE Boot` succeeded against AMT 16.1.30,
so the prefixed-namespace form this collection emits is accepted by real
firmware. Kept here rather than deleted because the reasoning is worth
retaining: it could not be settled by testing, since a conformant XML parser
treats both forms as identical.

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

**Every row below except the TLS-availability one is inferred from public
documentation (Intel's AMT Implementation and Reference Guide, MeshCentral's
generation-conditional logic) and this collection's own reading of that
documentation — not independently tested against a machine of that generation.**
Only the TLS-availability finding is hardware-verified, and only for the one
configuration `parmstro` actually tested.

| AMT generation | TLS (16993) | IDE-R | SOL | One-time PXE (`ForcePXEBoot`) | Status |
|---|---|---|---|---|---|
| 6.x–9.x | Varies by SKU | Generally present | Generally present | Generally present | **Inferred** — not tested |
| 10.0.56, Small Business Mode | **No** (HTTP 16992 only) | Present | Present | Present | TLS row **hardware-verified** (`parmstro`, NUC5i5MYBE); everything else on this row **inferred** |
| 10.x, Enterprise/other modes | Yes | Present | Present | Present | **Inferred** — not tested |
| 11.x+ Enterprise | Yes | Present | Present | Present | **Inferred** — not tested |
| 12.x+ | Yes, enhanced | Present | Present | Present | **Inferred** — not tested |

"Present" in the IDE-R/SOL/PXE columns means "AMT's published feature set for this
generation includes it," per `docs/protocol-notes.md` §1.1 and Intel's own
documentation — it is not a per-generation claim about the specific
`AMT_BootCapabilities` field values this collection reads, which is exactly what
`amt_info`, `amt_boot`, and `amt_redirection` each discover live from the endpoint
rather than assume from this table. Never use this table as a substitute for a live
`amt_info` capability read.

---

## What would move something from Tier 3 to Tier 1

Per `docs/testing.md`'s qualification order: a read-only `amt_info` pass against real
hardware first (cross-checked against an independent power probe and BIOS inventory),
then check-mode plans, then attended power control, then IDE-R attach with a small
test ISO, then the writable-image path, then one-time PXE, then an idempotent
re-probe — one machine first, a second machine to prove repeatability, never both at
once. Until that has actually run and its evidence is recorded here, this document's
Tier 3 section stands as written.

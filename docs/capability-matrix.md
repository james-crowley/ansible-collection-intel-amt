<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Capability matrix: what is actually verified

This is a plain accounting of confidence levels in this collection, so a reader does
not have to guess which claims rest on real firmware evidence and which rest on
reading someone else's source code. Three tiers, and nothing here should be read as
implying a higher tier than it earns:

1. **Verified against an authoritative source** — confirmed against a real firmware
   response fixture, a vendor reference implementation, or hardware-verified
   third-party research. This is the strongest claim this document makes, and it is
   still not the same as "tested on our hardware."
2. **Unit/mock tested** — exercised by this collection's own test suite against
   deterministic fixtures/fakes, never against real AMT firmware.
3. **Not verified against real firmware at all** — currently everything's actual
   end-to-end behaviour against a physical Intel AMT endpoint. No hardware
   qualification has run as of this writing.

If you take one thing from this page: **treat this collection as protocol-complete
and test-covered, but hardware-unverified**, exactly as `README.md` and
`docs/testing.md` already say.

---

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

## Tier 3: Not verified against real firmware at all

**Everything, currently.** No hardware qualification has run. `docs/testing.md`
documents the two-gate opt-in workflow (`run-hardware-tests` pipeline parameter, then
a manual approval) and the qualification order a first run must follow, but as of this
writing that workflow has not executed against a physical Intel AMT endpoint.

Concretely, this means every one of the following is protocol-complete and
mock-tested but has never been confirmed against real firmware:

- Every module's actual power/boot/redirection/media behaviour end-to-end.
- Whether real firmware's `AMT_BootSettingData` actually accepts the `Put` this
  collection sends (the field delete-list in `docs/protocol-notes.md` §2.5 exists
  precisely because *some* firmware rejects echoed read-only fields — no mock server
  can independently confirm this collection got that list right for a given
  generation).
- Whether the `hdd`/`cd`/`bios` capability-field mapping in `boot.py` and the `IDER`/
  `SOL` mapping in `redirection_service.py` — both Tier 1 for the *field names
  existing in the schema* — hold up as the specific gate this collection uses them
  for, on a specific firmware.
- The writable-IDE-R extension (§5 of `docs/protocol-notes.md`) beyond what
  MeshCentral's read-only reference implements.

---

## Known open risks

Each of these is a specific, named gap, not a vague hedge.

### #13 — WS-Addressing EPR byte-form ambiguity

This collection's WS-Man `EndpointReference` builder
(`plugins/module_utils/wsman.py`, `EndpointReference.build_elements`) emits
namespace-*prefixed* XML (`<a:Address>`, `<w:ResourceURI>`, …) for the EPRs it embeds
as method parameters — for example `ChangeBootOrder`'s `Source` parameter in
`amt_boot`. MeshCmd instead emits the equivalent structure using the *default*
namespace (unprefixed elements with an `xmlns=` declaration), not prefixed elements.

The two forms are namespace-equivalent and standards-correct XML — any conformant XML
parser accepts both, because namespace identity is defined by the expanded
`{namespace}localname` pair, not by which prefix happened to be used to spell it. That
is exactly why **no mock server can settle this**: a mock server built on a real XML
parser (as this collection's own mock WS-Man server is) will accept both byte forms
identically, so a passing mock-integration test proves nothing about whether a
specific AMT firmware's WS-Man stack does the same. `ChangeBootOrder` is the
highest-consequence call in this collection — it is the actual boot-order mutation
`amt_boot` exists to make — so this is the single highest-priority item hardware
qualification needs to settle first, deliberately ahead of anything else in the
five-step sequence.

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

## Return-shape inconsistency across modules

Not a firmware-verification gap, but worth recording here because it affects how a
playbook consumes results: `amt_power` nests its `intel-amt-operation/v1` receipt
under an `operation` key (`result_from_receipt()` in `amt_power.py`), while
`amt_boot`, `amt_redirection`, and `amt_media` all spread the receipt's fields
directly at the top level of the module result (`module.exit_json(**receipt.to_dict())`).
`amt_info` does not use the receipt shape at all — it returns a single `amt` dict.
Consult each module's own return-values table
([`amt_info`](amt_info.md), [`amt_power`](amt_power.md), [`amt_boot`](amt_boot.md),
[`amt_redirection`](amt_redirection.md), [`amt_media`](amt_media.md)) rather than
assuming one shape across all five.

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

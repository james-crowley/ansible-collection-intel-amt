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
   claim per generation. A fourth run, 2026-07-30, read **both** machines with the
   0.5.0 hardware-inventory code and moved that inventory's classes and shapes into
   this tier as well. A fifth run, 2026-07-31 (pipeline **208**), put stages 9-12 —
   event log, log clear, sleep/hibernate, and wake-while-off — to real firmware for
   the first time, on **machine 1 only**, and is the first run whose evidence carries
   a per-file SHA-256 digest. All five runs are cited by workflow and job below.
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
| CIM power-state table (2=On, 3/4=Sleep, 6/8/9/13=Off, 7=Hibernate) and `RequestPowerStateChange` action codes (2/3/4/5/7/8/10) | MeshCmd's `DMTFPowerStates`, agreeing with the DMTF ValueMap. **Weaker than the rest of this tier**: the primary source is a third party's constants array, which is the same category of evidence that produced the `LinkPolicy` inversion below. The four codes this collection sends (2/5/8/10) are separately annotated `// Verified Hardware` in `go-wsman-messages`; the rest are not. §2.4 also records an unresolved asymmetry — 5 and 9 are both power cycles yet normalize to `on` and `off` | `plugins/module_utils/client.py`, `plugins/module_utils/models.py` |
| The five-step boot-configuration sequence (clear → mutate → Put → set role → set order) and its field delete-list | MeshCentral (`amt/amt-wsman.js`, `amt/amt.js`), Apache-2.0. **The delete-list specifically is the weakest row in this tier**: "which fields firmware rejects on a Put" is a behavioural claim, and no `Get` fixture can establish it. It is corroborated instead at the integration tier — the mock's `reject_boot_readonly_fields` fault, which two separate mutations confirmed is load-bearing rather than decorative | `plugins/module_utils/boot.py` |
| The IDE-R/redirection wire framing (session start, digest auth over the binary protocol, SCSI command set, canned MODE_SENSE/GET_CONFIGURATION byte arrays) | MeshCentral (`amt/amt-redir-mesh.js`, `amt/amt-ider-module.js`), Apache-2.0 | `plugins/module_utils/redirection.py`, `plugins/module_utils/ider.py` |
| AMT provisioned in Small Business Mode never opens port 16993 (no TLS at all) | **Hardware-verified** by `parmstro` on an Intel NUC5i5MYBE, AMT 10.0.56 build 3002 (`parmstro/intel_amt`, GPL-3.0-or-later, `development/research/AMT_10_TLS_LIMITATION.md`) | `plugins/doc_fragments/connection.py`, `plugins/module_utils/tls.py` (`enforce_transport_policy`) — this is *why* the plaintext opt-in exists at all |
| `AMT_EthernetPortSettings.LinkPolicy` value table: 1 = S0 AC, 14 = Sx AC, 16 = S0 DC, 224 = Sx DC, and no other defined value | `device-management-toolkit/go-wsman-messages` `pkg/wsman/amt/ethernetport` — `decoder.go` named constants (`LinkPolicyS0AC`…`LinkPolicySxDC`), `types.go` schema annotation `ValueMap={1, 14, 16, 224}` / `Values={available on S0 AC, available on Sx AC, available on S0 DC, available on Sx DC}`. Read directly at tag `v2.48.3`, per `docs/protocol-notes.md` §2.7 | `plugins/module_utils/models.py` (`_LINK_POLICY_TABLE`, `wake_on_lan_capable`) |

Every row above is a claim about the **protocol**, verified against something other
than this collection's own code. None of them is a claim that this collection's
*implementation* of the protocol has been exercised against real firmware — that is
Tier 3.

### Correction: the `LinkPolicy` row was previously wrong, and was not Tier 1

The `LinkPolicy` row above is new in 0.3.1. Recorded here rather than silently
substituted, because a matrix that quietly fixes a wrong claim is worth less than one
that says what it got wrong.

Through 0.2.0 and 0.3.0 this collection decoded `LinkPolicy` with a table transcribed
from `parmstro`'s constants file — `1: s0_ac, 2: sx_ac, 14: s0_dc, 15: sx_dc,
16: always_on` — and derived `wake_on_lan_capable` from the presence of `16`. Against
the vendor enum, three of those five entries are wrong: `14` is **Sx AC**, not S0 DC;
`16` is **S0 DC**, not an "always on" bit; `2` and `15` are not defined values at all.
`224` (Sx DC) was missing. The consequence was a boolean that actually asked *"is this
endpoint reachable while running on battery?"* and so returned `false` for every
mains-powered desktop — the inverse of the correct answer.

Two things that document was doing wrong, beyond the table itself:

- **It carried the claim at the wrong tier.** These values sat in Tier 2 on the
  reasoning that the source was "a third party's hardware", with `amt_info.md` adding a
  caveat that the reader should confirm the field in the AMT Web UI. A caveat is not a
  substitute for reading the vendor reference, which was one HTTP request away and
  settles the question outright.
- **It treated a hardware dump as corroborating a *meaning*.** `parmstro`'s machine
  returned `[1, 14, 16]`, which was cited as corroboration. A dump corroborates that a
  value was *returned*; it can never establish what the value *means*. Those are
  different claims and were conflated.

This is the **second** wrong table from that source — their power constants map `reset`
to CIM code 11 (Diagnostic Interrupt / NMI) rather than 10 (Master Bus Reset), noted
below and in `NOTICE`. Their research notes (class names, ResourceURIs, selector
strings, property names, which verb each class accepts) have held up under hardware
testing on two generations. Their *constants and derived meanings* have now been wrong
twice. Any future value table from them belongs in Tier 1 only after being checked
against go-wsman-messages or a real firmware fixture, and nowhere else until then.

### What is actually wrong with `parmstro`'s code

This document previously said that **three of ten** of that project's modules "report
success while doing nothing". On re-verification that count does not hold, so it is
withdrawn. One module fits that description; two others have *different* defects. The
accurate accounting, read from the source at `parmstro/intel_amt`:

- **`amt_tls_config` reports success while doing nothing.** Both mutation paths —
  certificate upload and TLS configuration — are wrapped in `except Exception` handlers
  that append an advisory string to a `messages` list and then fall through to
  `exit_json()`, so *any* failure still exits `ok`. Its `upload_certificate` is a
  self-described placeholder: it base64-encodes the certificate *text*, computes a
  `key_b64` from the private key and then never references it, so the key is silently
  discarded. This is the one module the original claim described.
- **`amt_system_settings_refactored.py` cannot report drift in check mode.** It returns
  `changed: False` and exits on `module.check_mode` before any current state is read or
  compared, so `--check` emits a generic "would configure" message and can never tell a
  caller what would actually change. That is a different defect from reporting success
  while doing nothing: it does nothing *and says so*, but it also computes nothing.
- **`amt_power_policy` does issue writes — with inverted semantics.** It genuinely
  Puts `AMT_EthernetPortSettings`. The defect is in the meaning, not the plumbing, and
  it is the same defect this collection shipped.

**The `LinkPolicy` inversion, stated fairly.** `amt_power_policy` treats
`16 in LinkPolicy` as `always_on` and derives its `wake_on_lan` result from that same
value. But `16` is **"available on S0 DC"** — the link is maintained while the host is
*powered on*, running *on battery*. It says nothing about reachability while the host
is off. So asking that module for `always_on` sets roughly the opposite of
wake-while-off, and its reported `wake_on_lan` inherits the inversion.

**This collection shipped the same bug, from the same table, and fixed it in 0.3.1.**
That is the honest framing and the more useful one. The defect is not carelessness
peculiar to one project; it is what happens when an enumeration's *meaning* is taken
from a transcription instead of from the vendor enum, and it survived review here for
two releases (0.2.0 and 0.3.0) for exactly that reason. The correction above is this
collection's own; the same correction has not been applied upstream. A reader deciding
between the two projects should weigh that this collection found the bug in itself and
documented it, not that it found one in someone else.

Their power constants also map `reset` to CIM code 11 (Diagnostic Interrupt / NMI)
rather than 10 (Master Bus Reset) — a separate transcription error, and the first of
the two wrong tables noted above.

---

## Tier 2: Unit/mock tested

This is the bulk of the collection's verification effort:

- **1869 unit tests** (collected via `pytest` against the staged collection tree on
  2026-07-30; the number drifts as tests are added, so treat it as a point
  measurement, not a promise) across `tests/unit/plugins/module_utils/`, `tests/unit/plugins/modules/`
  and `tests/unit/mock_servers/`, covering error classification/redaction, TLS trust
  policy, the WS-Man envelope/SOAP layer, the boot five-step sequence, the redirection
  handshake, the IDE-R SCSI state machine, the media-session daemon, and every
  module's argument handling, check-mode behaviour, and idempotence logic — all
  against fakes/mocks, never a socket or a real AMT endpoint.

  Branch coverage over `plugins/` is **93%**, measured with
  `coverage run --branch --source=plugins` over that same unit suite — stated because
  a coverage figure whose measurement is not named cannot be checked, and the two
  per-file figures below were taken the same way. The distribution matters more than the
  total, and it used to be inverted against consequence: the two least-covered files
  were the two highest-consequence ones. `media_session.py` (the detached daemon that
  holds credentials across a fork) was **50%** and is now **81%**; `ider.py` (the SCSI
  state machine) was **75%** and is now **92%**.
- **9/9 integration targets** (`amt_baremetal_install_role`, `amt_boot`,
  `amt_event_log`, `amt_info`, `amt_info_hardware`, `amt_log_clear`, `amt_media`,
  `amt_power`, `amt_redirection` under `tests/integration/targets/`) run end-to-end against local,
  deterministic fixture servers: a mock WS-Man server (HTTP Digest, TLS with a
  generated self-signed certificate, canned per-resource-URI responses, fault
  injection for AMT error codes/malformed SOAP/401/timeouts) and a mock IDE-R server
  (session start, auth-type query, digest challenge, configurable `readbfr`, a write
  path that verifies bytes actually land in the backing image). See
  `docs/testing.md` for how to run these and exactly what they do and do not prove.

### What a test count is worth: mutation testing, 2026-07-30

A number of tests is not evidence. This suite was audited by deliberately breaking
the implementation — 21 mutations, the full unit suite run against each — to find
assertions that could not fail. What it found is recorded here rather than quietly
fixed, because the same discipline that makes the tier table useful demands it.

**The worst finding was in the collection's most security-critical invariant.**
Seven tests, one per module, claimed to prove the AMT password never reaches module
output. All seven were vacuous: each file's autouse fixture replaced `exit_json`
with a bare raiser, and the real `exit_json` is the only thing that injects
`invocation.module_args` — the place a password would actually appear. So they
asserted on a dict that structurally could not contain it.

Flipping `no_log: True` to `False` on a password left the unit suite fully green
**and** `ansible-test sanity --test validate-modules` at exit 0. No tier caught it.
Fixed by asserting against Ansible's real serializer, plus a contract test over
every module's argument spec, driven from imported modules so a new module is
covered without anyone remembering to add it.

Three mutations survived everything and were real gaps rather than test defects, and
each turned out to be a live bug:

| Mutation that survived | The bug it revealed |
|---|---|
| Loosening the IDE-R write bound by 512 bytes | The guard's *boundary* was never probed — existing tests used 4096- and 9999-byte overruns against a 512-byte window, so any plausible bound passed |
| — | `engine.feature_toggle_ok` was set and **never read**, so `amt_media` reported `attached` for media firmware had refused to serve |
| Removing `_scsi_read`'s bounds check | `_pump_read` had no zero-length-read guard, so a backing image truncated beneath a live session spun forever |

**Two limits of the tiers themselves, worth stating plainly.** The
`wake_on_lan_capable` inversion that shipped in 0.2.0 and 0.3.0 could not have been
caught by either the mock tier or the hardware tier: the mock is fed from this
collection's own understanding of a value table, so mock and code agreed while both
were wrong, and hardware returned the correct raw values which the code then decoded
confidently and incorrectly. And an integration target whose directory name matches
a role in `roles/` is resolved by `ansible-test` as that role — so a target named
`amt_baremetal_install` ran the role's `validate.yml` and none of its own tasks, a
test that could not fail because it never executed.

### `amt_event_log` and `amt_log_clear` — now Tier 3 on machine 1

**This section used to say these two modules stop at Tier 2 — and only Tier 2 —
because no hardware qualification stage exercised either of them. That is now false
for machine 1.** Stage 9 (`qualify_event_log.yml`, read-only) and stage 10
(`qualify_log_clear.yml`, irreversible) both ran for the first time against
`amt-lab-01`, AMT 16.1.30, and both passed. `amt_event_log` and `amt_log_clear` are
no longer listed again in Tier 4 in their entirety — see the dedicated Tier 3
subsection below for the evidence and citation, and the note there about what is
still missing: machine 2 has never run either stage.

Their wire protocol and record layout still also rest on a captured real-firmware
response fixture set plus MeshCentral, recorded in `docs/protocol-notes.md` §2.8 —
a Tier 1 claim about the *protocol*, unaffected by and independent of this
collection's own hardware run. That is still why `amt_event_log` returns the **raw
bytes** of every record alongside the decoded fields: a decode is not automatically
trustworthy merely because *some* real record decoded cleanly on one machine. See
[`docs/amt_event_log.md`](amt_event_log.md) and
[`docs/amt_log_clear.md`](amt_log_clear.md).

### `amt_info`'s hardware/asset inventory — classes and shape now Tier 3, decoded labels still Tier 1-by-citation

New in 0.5.0: `amt_info`'s `gather_subset` inventory subsets (`system`, `processor`,
`memory`, `storage`) and everything under `amt.hardware`, backed by
`plugins/module_utils/hardware.py`. Six WS-Man classes — `CIM_Chassis`, `CIM_Card`,
`CIM_Processor`, `CIM_Chip`, `CIM_PhysicalMemory`, `CIM_MediaAccessDevice`.

**This section used to say the inventory was "not hardware-verified", that "no lab
machine has ever been asked for any of these classes by this collection", and that "not
one of the values it decodes has been read back from a live endpoint here". All three
were true when written; all three are now false.** Stage 1b of
`tests/hardware/qualify_readonly.yml` asked both lab machines for all six classes and
all six answered. That claim is therefore **Tier 3** and is recorded in that tier below
with the run cited. The former cross-references — "does not appear in Tier 3", "listed
again in Tier 4", "every generation, including the two lab machines, is untested for it"
— are all withdrawn.

**Be precise about what that upgrades.** It establishes that these classes exist on this
firmware, that the verbs and the selector-less `Get` are right, and that this
collection's readers recognise the responses that come back. It establishes **nothing**
about what any decoded label *means*. A dump proves a value was returned; it never
proves what it signifies, and conflating the two is exactly what left
`wake_on_lan_capable` inverted for two releases. The value tables stay sourced by
citation, and the paragraph headed "The value tables are the Tier 1 part of this row"
below is unchanged and is still the reason the labels are trustworthy. This is the same
split already drawn for the network facts in the next subsection; that subsection states
the general principle and is not repeated here.

**Do not overstate it in the other direction either.** Two machines is repeatability,
not a compatibility guarantee, and these two are the same vendor and the same model
family — two SKUs from one vendor, not a survey. The untested-generation entry in Tier 4
applies here exactly as it does elsewhere.

What Tier 2 still buys — and it is what makes the *labels*, rather than the plumbing,
trustworthy:

- **730 unit tests.** **What that number measures**, written out so it cannot quietly
  come to mean something else: `pytest --collect-only` over the four test files this work
  touched — `module_utils/test_hardware.py`, `module_utils/test_client.py`,
  `modules/test_amt_info.py`, `mock_servers/test_wsman_server.py` — **minus their
  pre-0.5.0 baseline of 217**. Those four collect **947** today, and 947 − 217 = 730.

  It is **not** a count of tests that exercise the inventory and nothing else: three of
  those files predate the inventory and keep testing what they always did, and the fourth
  is dedicated to it. It is **not** the whole suite. Anyone updating this figure has to
  re-collect those same four files against the same 217 baseline, or replace the measure
  and say so in the same edit — because the reason the previous number needed
  reconstructing at all is that it stated no measure, which let it drift into meaning
  something its arithmetic never claimed.

  **609**, the number here originally, was defensible on either of the two readings
  available to it. It is the whole-suite delta of the 0.5.0 feature commit — 1078 tests
  before, 1687 after, which is the arithmetic that commit's own message records — **and**
  it is the growth of those same four files, 217 to 826. The two coincided because 0.5.0
  added tests to nothing else, so "609 tests covering the inventory" was not the
  overstatement it looks like from the whole-suite arithmetic alone; the figure had simply
  drifted. It held again for the 57 that followed, all of which landed in these four files
  with `operation.hardware_reads`: 826 → 883 and 1687 → 1744 were the same 57 counted two
  ways.

  **That coincidence has now ended, and this is the more useful thing to record.** Between
  1744 and 1869 the suite grew by 125, of which only 64 landed in these four files
  (883 → 947). The remaining 61 went to `test_redact_evidence.py`, `test_wsman.py`,
  `test_ider_server.py` and the role's integration target — redaction fixes, the
  `EndOfSequence` discriminator, the IDE-R `start_session_status` fault, the 2.17
  connection-guard regressions. So the whole-suite figure and the four-file figure now
  measure genuinely different things, as they always claimed to but never had to
  demonstrate. Anyone tempted to treat one as a proxy for the other should stop here.

  Two narrower counts, for anyone who wants a figure that needs no reconstruction at
  all: `test_hardware.py` — the file dedicated to the decoders and the value tables —
  collects **538** on its own, and the whole unit suite collects **1869**.

  Of these the bulk are per-value assertions over the nine value
  tables — every defined value plus an out-of-table value for each — written against the
  *cited source* rather than against the implementation. Plus multi-instance parsing at
  zero, one, several and paged instance counts; the CIM single-element-array shape; the
  three-state contract per fact group; `gather_subset` resolution across every
  `setup`-compatible case including `!` negation, contradictions and the empty list; and
  per-class graceful degradation.
- **A ninth integration target**, `amt_info_hardware`, driving the real module against
  three separately-configured mock WS-Man endpoints over a real socket: fully populated,
  no inventory classes at all, and one whose singleton `Get`s fault so the `Enumerate`
  fallback is exercised for real.

**Where the protocol claims come from — and this row is stronger than most Tier 2
entries.** Unusually, it does not rest on a third party's prose or a single machine's
dump. `device-management-toolkit/go-wsman-messages` (Intel's own toolkit, Apache-2.0,
read at tag `v2.48.3`) ships **captured real-firmware responses** for all six classes
under `pkg/wsman/wsmantesting/responses/`, and those fixtures are where every property
set came from. The mock server's handlers are derived from those same fixtures, with each
handler citing its fixture path and naming which individual enumeration values were
carried across — a distinction that matters, because a mock fed from this project's own
understanding of a table is exactly how the `LinkPolicy` inversion survived two releases.

**The value tables are the Tier 1 part of this row.** All nine come from
`go-wsman-messages`' `decoder.go` const/map pairs, extracted mechanically rather than
retyped, or from the DMTF CIM schema (`EnabledState`, `OperationalStatus` — the same
single tables this collection already held, imported rather than redeclared). **None
comes from a hardware dump.** Three notes worth recording:

- `go-wsman-messages`' own `cim/processor` `enabledStateMap` **omits values 0, 1 and 2**,
  so its decoder answers "Value not found in map" for its own captured firmware response.
  The full DMTF table is used instead. Its `cim/mediaaccess` copy of the same enumeration
  is complete and agrees with DMTF, which is what identifies the processor one as an
  omission rather than a disagreement.
- Two properties **ship raw and undecoded** because no table could be sourced:
  `CIM_Processor.Family` (no map exists in the library; the DMTF ValueMap has hundreds of
  entries and no offline schema copy was available) and
  `CIM_PhysicalMemory.FormFactor` (no map, **and** two published tables disagree about
  the value real firmware reports — `13` is `SODIMM` under SMBIOS type 17 and `SRIMM`
  under the DMTF ValueMap). `RequestedState` is likewise raw, matching how this module
  already reports it on `CIM_ComputerSystem`. Shipping a raw integer is honest; a guessed
  label is what 0.3.1 was spent undoing.
- Three properties an operator would expect **do not exist** on these classes and are
  therefore not reported: no asset tag anywhere (`AssetTag` does not occur in
  `go-wsman-messages` at all — `Tag` exists, and real firmware populates it with the
  *class name*), no processor core or thread count, and no disk model, vendor or serial.
  See `docs/amt_info.md` and `docs/protocol-notes.md` §2.9.

**What moved this to Tier 3** was exactly what this section used to ask for: one
read-only hardware stage, an `amt_info` call with `gather_subset: [config, hardware]`
against each lab machine, with the resulting fact groups recorded. It ran as stage 1b of
`qualify_readonly.yml`. See "**`amt_info`'s hardware/asset inventory** — Tier 3 on both
lab generations" at the end of Tier 3 for what firmware actually returned.

**One caution carried over from how that stage first reported itself.** The stage's
summary task originally read `amt.hardware.system` and `amt.hardware.processor` — key
names `amt_info` has never emitted, because `system` and `processor` are *`gather_subset`
names* and the *fact groups* they populate are `chassis`+`baseboard` and
`processors`+`chips`. Jinja's `| default(none)` rendered each undefined lookup as a
printed `null`, so the first run reported four of the six groups as unavailable on both
machines while firmware had in fact returned all six. Nothing in the module's output
could contradict it, because a genuinely absent class produces the identical `null`.

That is now guarded three ways, and the middle one is the durable fix: the stage asserts
the six-key set before reporting on it; `amt_info`'s receipt carries
`operation.hardware_reads` giving each class's own read outcome (`read` / `empty` /
`absent`, with the `error_class` when absent); and both the unit and integration tiers
assert that every outcome names a fact group that really exists. **The lesson is a tier
lesson, not a bug report**: a `null` that cannot say *why* it is null is not evidence of
anything, and this document's tiers depend on being able to tell "not asked" from "asked
and refused".

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
  collection has never touched, and the surrounding project's *code* is separately
  assessed as unreliable — see "What is actually wrong with `parmstro`'s code" at the
  end of Tier 1 above for the specific, verified defects. Property names from those
  notes were used; no code was. What
  confirmed those names resolve on firmware this collection can actually reach is
  the pair of 2026-07-29 reads, on 19.0.5 and on 16.1.30. So these field names now
  rest on **three firmware generations' worth of evidence**: named from a third
  party's 10.0.56 dump, and read back populated by this collection on 16.1.30 and
  19.0.5.
- **The Tier 1 rows here** are the value tables, none of which come from anyone's dump.
  `EnabledState` and `OperationalStatus` are the DMTF CIM schema; the source project's
  implementation decodes only `OperationalStatus` values 0 and 2 and omits
  `EnabledState` 4 (shutting down) entirely, so the full standard tables are
  implemented here instead. `LinkPolicy` is go-wsman-messages, as of 0.3.1 — it was
  *not* Tier 1 before that, and it was wrong; see the correction at the end of Tier 1.
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
reviewed leaf certificate. **Five** runs now contribute, on different dates and in
different runner environments, and each is recorded as itself rather than averaged
into one. Every one now carries the identifiers needed to go and look at it — see
"Two limits on how far Tier 3 can be audited" below for what those identifiers do and
do not let a reader check:

> **"All eight stages" is a historical statement, not a current one.** The first four
> runs below predate stages 9-12, which were added 2026-07-31. Eight was the whole
> suite on the dates those four runs measured; it is now eight of twelve. A fifth run,
> the same day, put stages 9-12 to real firmware for the first time — but only on
> machine 1. The dated claims below are left exactly as they were because they were
> true when measured — but "all stages" and "all eight stages" still are not the same
> sentence as "all twelve", and nothing in the first four runs should be read as
> covering event-log, log-clear, sleep/hibernate or wake-from-off. The fifth run below,
> and the dedicated subsections that follow the stage table, are what now covers those
> four stages — on machine 1 only. Machine 2 has never run any of them.

- **`amt-lab-01` (machine 1), AMT 16.1.30** — all eight stages *as they existed then*, 2026-07-28, on
  Python 3.10 (3.10.12) with ansible-core 2.17, against collection 0.1.0.
  `hardware` workflow `6ced8630-58e3-44d0-bfdc-68f8d2f47a7a`; jobs
  `hardware-tests` `e01e14b5-e1ae-4003-919b-e3b99fea3c11` (stages 1, 2, 3, 8),
  `hardware-power` `a01cda9b-565c-424e-b812-0536b0a14194` (4),
  `hardware-media` `a3e56c2c-e301-41ea-b726-2fb304fa1aa9` (5),
  `hardware-writable` `23113b0c-1090-4a9b-9412-9fb74e2bc528` (6),
  `hardware-pxe` `6315a506-db04-4809-807b-1c8c6b32424d` (7), all succeeded. This run
  predates the `hardware-limit` parameter; it reached only machine 1 because the lab
  inventory held one endpoint at the time, which the job's own
  "Credentials present for 1 endpoint(s)" step records.
- **`amt-lab-02` (machine 2), AMT 19.0.5** — all eight stages *as they existed then*, 2026-07-29, on
  Python 3.12.13 with ansible-core 2.18.18. That run was deliberately limited to
  machine 2 (`hardware-limit=amt-lab-02`); machine 1 was not touched by it.
  CircleCI **pipeline #93**, `hardware` workflow
  `6b0b30d8-0956-4017-9b37-b8dd4d62db63`; jobs `hardware-tests`
  `97cf1c8d-8615-46bf-b33e-b1c3f91d54d3` (stages 1, 2, 3, 8), `hardware-power`
  `5767a536-5ed3-46cd-aa82-993972fe53f0` (4), `hardware-media`
  `8c4e4a51-2082-489a-843d-fa32bfc9a13e` (5), `hardware-writable`
  `988a4327-10ca-4252-8c38-9ff5d9b7d281` (6), `hardware-pxe`
  `310385c9-0916-4863-947f-52428ec895a5` (7), all succeeded.
- **`amt-lab-01` (machine 1) again, read-only stages only** — stages 1, 3 and 8,
  2026-07-29, limited to machine 1 (`hardware-limit=amt-lab-01`), on the
  ansible-core 2.18.18 lab virtualenv every hardware job now builds. Nothing was
  mutated: this run existed to read machine 1 with the v0.2.0 fact code, which its
  2026-07-28 evidence predated. Machine 1's mutating result stands on the
  2026-07-28 run and was not re-established here. `hardware` workflow
  `3756bbcd-3867-458a-83a2-648ee03bffdf`, job `hardware-tests`
  `7a33fe92-99d8-44c0-bcd5-53248f409df4`, succeeded. **That workflow is still on
  hold** at `hardware-power-approval` and so reports as unfinished; the read-only job
  it is cited for completed and its artifacts were uploaded.
- **Both machines, read-only stages only** — stages 1, 1b, 3 and 8, 2026-07-30,
  against collection 0.5.0, on the ansible-core 2.18.18 lab virtualenv. Nothing was
  mutated. This run existed to read both machines with the 0.5.0 hardware-inventory
  code, which every earlier run predated, and it is the sole evidence for the
  inventory subsection at the end of this tier. CircleCI **pipeline 167**, `hardware`
  workflow `aa1af1c2-6069-47bc-b5f6-de4a9c273399`, job `hardware-tests`
  `65ddc061-b273-4777-8c51-174a48e74402`, succeeded. **That workflow's overall
  outcome reads `canceled`**, because the four mutating approvals were never given and
  were cancelled hours later; the read-only job cited here succeeded, and no mutating
  job in it ever started. A reader checking the citation will see the cancelled
  workflow first, which is why it is stated here rather than left to surprise them.
- **`amt-lab-01` (machine 1), AMT 16.1.30 — stages 9, 10, 11 and 12**, 2026-07-31, the
  first time any of the four newest qualification stages ran against real firmware.
  All four succeeded. Limited to machine 1 only, by virtue of every one of these four
  jobs' own approval gate being exercised only once, against one endpoint; machine 2
  has never been asked. CircleCI **pipeline 208**, workflow
  `282b6692-94a2-481b-aacf-32c2cb1b2dfe`; jobs `hardware-tests` (job **2568**, stage 9),
  `hardware-log-clear` (job **2574**, stage 10), `hardware-sleep-hibernate` (job
  **2576**, stage 11), `hardware-wake-from-off` (job **2578**, stage 12), all
  succeeded. **This is the first Tier 3 run whose evidence is digest-pinned**: every
  one of these four jobs emits a `hardware-evidence/SHA256SUMS` manifest, so a reader
  can re-hash the published artifact and check it against the run's own record. The
  four runs above this one remain permanently digest-less — see "Two limits on how far
  Tier 3 can be audited" below.

So power control, IDE-R media, the writable-image path and native one-time PXE are
verified on **two machines across two firmware generations**, not one — and
`amt_info`'s network and system-state facts are now verified on both of those
generations too, which is what the third run added. The fourth run added the
hardware/asset inventory on both. The fifth run added stages 9-12 — event log,
log clear, sleep/hibernate, and wake-while-off — but on **machine 1 only**. See the
subsections at the end of this tier.

| Stage | Machines | What real firmware confirmed |
|---|---|---|
| 1 read-only | 1 and 2 | `amt_info` over pinned TLS with HTTP Digest. Firmware version from `CIM_SoftwareIdentity`, all four capability flags, power state `2 -> on`, the platform UUID, and `AMT_RedirectionService.EnabledState` decoded on two different values (`32769` = IDER only on machine 1; `32771` = SOL+IDER on machine 2). Machine 1 was read again on 2026-07-29, which is where its network and system-state facts below come from |
| 1b inventory (read-only) | 1 and 2 | All six hardware/asset inventory classes answered on both machines, 2026-07-30: `CIM_Chassis` and `CIM_Card` on a bare selector-less `Get`, `CIM_Processor`, `CIM_Chip`, `CIM_PhysicalMemory` and `CIM_MediaAccessDevice` on `Enumerate`/`Pull`. One property-level gap — `CIM_Card.SerialNumber` is empty on both. See the subsection at the end of this tier |
| 2 identity cross-check | 1 and 2 | Each machine returned a **distinct** platform UUID, and both rendered with UUID version nibble `1` after the SMBIOS little-endian field reversal — independent corroboration of the byte-order fix on a second, unrelated GUID. This stage has **no playbook of its own**: it is the review step inside `qualify_readonly.yml`. On 2026-07-29 its comparison **executed for the first time** against a recorded `amt_expected_uuid` for machine 2 and matched; see the note below the table for exactly what a match does and does not prove |
| 3 check mode | 1 and 2 | power and boot plans computed and **nothing mutated** |
| 4 power | 1 and 2 | convergent `on` reported `changed: false` when already on; `off` reported `changed: true`; initial state restored afterwards. Reproduced on machine 2 with the same outcomes |
| 5 IDE-R media | 1 and 2 | the native Python IDE-R engine served a real bootable ISO to real firmware, and the boot was armed and reset issued. **Read the caveat below this table before citing this row** — it is the one stage that records no evidence file |
| 6 writable image | 1 and 2 | the device was presented **writable** — MODE_SENSE write-protect bit `0x00`, not `0x80`. On machine 2: `devices.floppy.writable = true`, `bytes_read = 0`, `bytes_written = 0`, `error_class = null` — same shape as machine 1, a writable device with no bytes transferred |
| 7 native PXE | 1 and 2 | one-time PXE armed and read back as armed, reset issued and recovered, `AMT_BootSettingData` stable afterwards. On machine 2 the `before_arm` and `after_reset` snapshots agree, with `UseIDER=false`, `BIOSSetup=false`, `BootMediaIndex=0`. This also settled issue #13: the prefixed-namespace EPR form **is** accepted by real firmware, now on both generations |
| 8 idempotent re-probe | 1 and 2 | repeated reads reported `changed: false` and agreed with each other; no session or state was left drifting behind the stages above |
| 9 event log (read-only) | 1 only | a single `GetRecords` batch read the log to completion: `total_records: 205`, `records_read: 205`, `batches: 1`, `stop_reason: no_more_records`, `complete: true`, `truncated: false`, `filtered_out: 0`, every record decoding with `decode_error: null`. Log metadata decoded coherently alongside: `max_record_size: 21`, `current_number_of_records: 205`, `max_number_of_records: 390`, `overwrite_policy: 2`, `is_frozen: false`, `log_state: 4`. See the subsection below the table |
| 10 log clear (irreversible) | 1 only | the same 205 records were archived to disk (`complete: true`) *before* the clear; `ClearLog` then reported `records_before: 205`, `records_after: 0`, `cleared: true`, `changed: true`, `return_value: 0`; a separate, independent re-read afterwards confirmed empty (`total_records: 0`, `records: []`, `stop_reason: "no_record_exists"`, `complete: true`). See the subsection below the table |
| 11 sleep/hibernate | 1 only | all three actions — `sleep-light`, `sleep-deep`, `hibernate` — came back `outcome: "firmware_refused"`, `error_class: "remote_operation"`. AMT rejected every request itself, before it reached the platform; the machine was reported `on` throughout and was left `on`. See the dedicated subsection at the end of this tier — this is a **negative** result, and a consequential one |
| 12 wake-while-off | 1 only | AMT answered WS-Man **3 for 3** while reporting itself powered off (`off_confirmed_by_amt`), accepted a wake request (`wake_request_accepted: true`), and the machine came back `on` (`restored_to`). `operator_attestation` is `null` — unattended CI has no way to supply it. See the dedicated subsection at the end of this tier for exactly what this does and does not establish |

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
| `network.link_policy_names` | `["s0_ac", "sx_ac"]` | `["s0_ac", "sx_ac"]` |
| `network.wake_on_lan_capable` | `true` | `true` |
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

The `link_policy_names` and `wake_on_lan_capable` cells above are stated **as 0.3.1
decodes them**. The runs themselves, on 0.3.0, emitted `["s0_ac", "s0_dc"]` and `false`
for these machines, because the value table was wrong — see the correction at the end of
Tier 1. What the firmware reported and what those runs measured is the raw
`link_policy` `[1, 14]`; the row is re-decoded, not re-measured, and nothing else in this
table is affected.

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

### `amt_info`'s hardware/asset inventory — Tier 3 on both lab generations

The 0.5.0 inventory subsets were argued in Tier 2 above on the grounds that no lab
machine had ever been asked for these classes. Both have now been asked, and **all six
fact groups came back populated on both machines**.

**Evidence.** Stage 1b of `tests/hardware/qualify_readonly.yml` — a second, read-only
`amt_info` call with `gather_subset: [config, hardware]`. CircleCI **pipeline 167,
`hardware` workflow, job `hardware-tests`** (job UUID
`65ddc061-b273-4777-8c51-174a48e74402`), artifacts
`hardware-evidence/amt-lab-01-qualify_hardware_inventory.json` and
`hardware-evidence/amt-lab-02-qualify_hardware_inventory.json`. Both post-redaction, per
`tests/hardware/redact-evidence.py`. This row was the first in this tier to cite its
run, added because Tier 3 rows citing no run ID were a tracked shortcoming and adding
another would have made it worse. The other three runs have since been recovered and are
cited in the run list at the top of this tier; this row keeps its own citation because it
is the only claim in the document resting on a single run.

| Fact group | Class | Verb | 16.1.30 (machine 1) | 19.0.5 (machine 2) |
|---|---|---|---|---|
| `chassis` | `CIM_Chassis` | bare `Get` | populated: serial, model, manufacturer, `version` | same |
| `baseboard` | `CIM_Card` | bare `Get` | populated **except `serial_number`, which is `null`** | same |
| `processors` | `CIM_Processor` | `Enumerate` | 1 instance | 1 instance |
| `chips` | `CIM_Chip` | `Enumerate` | 2 instances | 3 instances |
| `memory` | `CIM_PhysicalMemory` | `Enumerate` | 1 DIMM | 2 DIMMs |
| `storage` | `CIM_MediaAccessDevice` | `Enumerate` | 1 device | 1 device |

Identifying values are deliberately not transcribed: this repository holds no lab
serials, model numbers or part numbers. "Populated" means the field came back non-`null`
and its class did not fault, which is the whole of what is claimed.

What this settles, and only this:

- **The classes exist and the verbs are right.** All six answered on both generations.
  The two single-instance classes answered the **bare, selector-less `Get`** — the
  `Enumerate` fallback never had to run, so the `system` subset cost the documented two
  requests, not six. Both reference implementations send exactly that form
  (`go-wsman-messages` v2.48.3's shared `base.WSManService.Get()` calls
  `getBySelector(nil)` and emits no `<w:SelectorSet>` at all; MeshCentral's `obj.Get`
  has no selectors parameter to pass one with), and firmware agrees with both.
- **`CIM_Chip` really does return memory chips alongside the processor chip**, which
  Tier 2 predicted from the class hierarchy and left unfiltered on that basis. Confirmed:
  one `"Managed System Processor Chip"` plus one `"Managed System Memory Chip"` per DIMM
  on each machine — hence 2 chips against 1 DIMM, and 3 against 2. Filtering to "just the
  CPUs" would have been wrong, and `element_name` is what tells them apart.
- **`Tag` is not an asset tag**, as Tier 2 said. Real firmware returns the literal class
  names `"CIM_Chassis"` and `"CIM_Card"` in it on both machines. There is still no asset
  tag anywhere in AMT's implementation of these classes.
- **`operational_status` is `[0]` — `"unknown"` — everywhere it appears**, matching what
  `CIM_ComputerSystem` already reports on these machines. It is **absent entirely**
  (`null`) on `CIM_PhysicalMemory` and on the memory-chip `CIM_Chip` instances. Neither is
  a defect; both are reported as received.

What it does **not** settle is any decoded label's meaning — see the Tier 2 subsection.
One reading is worth calling out precisely because it shows that boundary working:

- **`CIM_Processor.UpgradeMethod` came back `85` on 19.0.5**, and
  `UPGRADE_METHOD_TABLE` is a faithful transcription of `go-wsman-messages` v2.48.3,
  which defines 85 values, `0`-`84`. So real firmware reported a socket **one past the
  end of the vendor's own table**, and the collection renders it `unknown(85)` while
  keeping the raw `85`. That is the `unknown(<raw>)` convention earning its keep: a bare
  `unknown` would have been indistinguishable from this table's *defined* value `1`.
  Machine 1 reported `64`, which is in the table. **No entry for `85` should be invented**
  — no source names it, and inferring a socket name from one machine's dump is the exact
  move that inverted `wake_on_lan_capable`.
- **`Family` came back `198` on machine 1 and `774` on machine 2**, both shipped raw and
  undecoded as documented. Two different values across two generations is a reason to keep
  it undecoded, not a reason to start guessing.

#### The one observed gap: `baseboard.serial_number` is `null` on both machines

`CIM_Card` is plainly readable — `manufacturer`, `model`, `version`, `can_be_frued` and
`package_type` all come back on both machines — but `SerialNumber` yields nothing, on
both, while `CIM_Chassis.SerialNumber` populates on both. Consistent across the two
generations, so it is a property-level gap and not a class-level one.

**This document cannot say which of four things is happening, and the next hardware run
will.** The distinction matters, and the list is longer than it first looked:

1. firmware omits the `SerialNumber` element from the response entirely;
2. firmware returns the element present but empty;
3. firmware returns it carrying child elements; or
4. firmware returns it more than once.

`models.optional_str()` maps all four to `None` by design (it refuses a mapping and a
list, and `text.strip() or None` handles the rest), and the evidence artifacts are the
module's already-parsed output — taken *after* that collapse. **1 and 2 are firmware
limitations; 3 and 4 would be defects in this collection**, a value arriving and being
dropped, which is why ruling them out is not academic.

This section previously recorded that settling it needed a raw SOAP body from stage 1b.
**That was wrong, and the correction is worth keeping rather than quietly editing out.**
The distinction survives the parser intact — `wsman._element_to_value()` gives an omitted
element no key at all and an empty one a key holding `""` — and is destroyed one call
later by the coercion. 0.7.0 therefore censuses each property of `CIM_Chassis` and
`CIM_Card` by *shape* before the coercion runs, publishing property names and one of five
fixed labels and **no value whatsoever**, and stage 1b both prints and asserts it.

So the next stage 1b run can state, per machine, which of the four applies —
`operation.hardware_reads['CIM_Card'].property_shapes['SerialNumber']`, in an artifact
that is redacted and digest-manifested like every other. Until that run happens this
stays **#84** and stays a gap this document cannot close: the mechanism to answer it is
Tier 1 (mock-exercised, both firmware shapes served over a real socket), the answer itself
is not yet Tier 3.

The practical consequence is worth stating rather than leaving implicit: `system` was
documented as letting an operator tell a board swap from a re-rack, and that inference
needs *both* serials. On this firmware only the chassis serial is available, so it cannot.
`docs/amt_info.md` says so.

### Both machines report `wake_on_lan_capable = true`

Both machines returned `link_policy` `[1, 14]`. Against the vendor enum that is `s0_ac`
plus `sx_ac`: the link is maintained while the host is powered on **and** while it is
asleep, hibernating or off, in both cases on mains. `14` is an **Sx** value, so
`wake_on_lan_capable` is `true` on both.

This reverses what 0.2.0 and 0.3.0 reported for these same readings. The raw `[1, 14]`
is unchanged and measured; the decoding of it was wrong, keyed off a transcribed table
in which `14` was labelled `s0_dc` and `16` was labelled an "always on" bit that Intel's
enum does not contain. See the correction at the end of Tier 1 for the full accounting.

**Firmware configuration corroborates the corrected table.** The MEBx screen on one of
these machines was photographed after the fact: `ME ON in Host Sleep States` reads
*"Desktop: ON in S0, ME Wake in S3, S4-5"* — the wake-capable option — and `Idle Timeout`
reads `65535`, matching the `idle_wake_timeout` `amt_info` already reports for it. So the
firmware's own configuration screen and the vendor value table agree with each other, and
the collection's old derivation disagreed with both. That is two independent sources
against one transcription. (These are related fields, not the same field: `LinkPolicy`
governs whether the network **link** is maintained, the MEBx setting governs whether the
**ME itself** is powered, and this collection reads only the former.)

**It also resolves a result previously recorded here as not adding up.** Machine 1's
stage 4 passed on 2026-07-28 including an `off` transition and then a successful restore,
which this document called "hard to square with an endpoint that is unreachable while
off" and explained away as the machine most likely having been off already. With `14` =
Sx AC there is nothing to explain away: the endpoint is configured to stay reachable
while off, on AC, which is exactly what that stage's behaviour implies. The awkward
reading was an artefact of the wrong table.

**What this still does not establish.** No deliberate power-off, independent
confirmation, then WS-Man read had been run against either machine as of the evidence
above — that gap is what stage 12 (below) was built to close, on machine 1.

### `amt_event_log` and `amt_log_clear` — Tier 3 on machine 1, stages 9 and 10

**Evidence.** CircleCI pipeline **208**, workflow `282b6692-94a2-481b-aacf-32c2cb1b2dfe`,
against `amt-lab-01`, AMT 16.1.30, 2026-07-31. Stage 9 (`qualify_event_log.yml`) ran as
job **2568**; stage 10 (`qualify_log_clear.yml`) ran as job **2574**. Both are the first
run of either module against real firmware — no earlier stage ever reached them, per the
Tier 2 subsection above (now retitled to match).

**Stage 9, read-only.** A single `GetRecords` batch read the log to completion:
`total_records: 205`, `records_read: 205`, `batches: 1`, `stop_reason:
"no_more_records"`, `complete: true`, `truncated: false`, `filtered_out: 0`, and every
one of the 205 records decoded with `decode_error: null`. The log's own metadata decoded
coherently alongside the records — `max_record_size: 21` (confirming the 21-byte record
layout this collection has assumed since it was written), `current_number_of_records:
205`, `max_number_of_records: 390`, `overwrite_policy: 2`, `is_frozen: false`,
`log_state: 4` — and individual record content was itself coherent, e.g.
`description: "Starting operating system boot process"`, `entity_text: "BIOS"`,
`entity: 34`, `device_address: 255`. This is what settles the three things the Tier 2
subsection listed as specifically unproven: that real firmware accepts this collection's
`GetRecords` iteration as issued, that the 21-byte record layout decodes, and that the
fields inside those records decode against records a real ME actually wrote.

**Stage 10, irreversible.** Two artifacts. The archive
(`amt-lab-01-qualify_log_clear-archive.json`) captured the same **205 records**,
`complete: true`, *before* the clear ran — so the read that validates stage 9's decoder
survived the clear that then destroyed those records on the endpoint. `ClearLog` itself
then reported `records_before: 205`, `records_after: 0`, `cleared: true`, `changed:
true`, `return_value: 0`. The stage does not stop at trusting that return value: a
second, independent `amt_event_log` read afterwards returned
`current_number_of_records: 0`, `records_read: 0`, `total_records: 0`, `records: []`,
`stop_reason: "no_record_exists"`, `complete: true`. So `ClearLog` does what its name
says on real firmware, confirmed by a separate read rather than by the method's own
say-so.

**What this settles, and what it does not.** Both stages prove this collection's
*implementation* of the wire protocol against real firmware for the first time — the
iteration loop, the 21-byte decode, the archive-before-clear sequencing, and the
clear-then-reread confirmation. It does **not** independently verify what any individual
event-code label *means*: stage 9 shows the layout decodes structurally and that the
sampled records' fields are plausible, not that every event-code name this collection
has ever assigned is correct. That claim stays exactly where it already was — Tier 1 by
citation, `docs/protocol-notes.md` §2.8 — for the same existence-vs-meaning reason drawn
throughout this document. And both stages ran on **one machine, one firmware version**:
machine 2, AMT 19.0.5, has never run either. See Tier 4.

### Sleep and hibernate: firmware refuses all three, on machine 1

**Evidence.** Stage 11 (`qualify_sleep_hibernate.yml`), CircleCI pipeline **208**,
workflow `282b6692-94a2-481b-aacf-32c2cb1b2dfe`, job `hardware-sleep-hibernate`
(**2576**), against `amt-lab-01`, AMT 16.1.30, 2026-07-31. This is the first time any
hardware stage issued `sleep-light`, `sleep-deep` or `hibernate` — stage 4 exercised
only `on`/`off`.

**The result is negative, and it is the most consequential one in this run.** All three
requested actions came back `outcome: "firmware_refused"`, `error_class:
"remote_operation"`:

| requested `state` | `expected_normalized` | outcome |
|---|---|---|
| `sleep-light` | `sleep` | `firmware_refused` |
| `sleep-deep` | `sleep` | `firmware_refused` |
| `hibernate` | `hibernate` | `firmware_refused` |

Every attempt: `before: {normalized: "on", raw: 2}`, `restored_to: {normalized: "on",
raw: 2}`, `probe_final: null`. The machine was healthy throughout and was left exactly
as it started. The stage's own evidence is explicit that AMT itself rejected the
request, before it ever reached the platform — this is `firmware_refused`, not
`os_did_not_transition`, so it is not "the target OS doesn't support S3"; AMT declined
the request itself.

**This settles the request-path half of what Tier 4 used to list as spanning a split.**
Whether real firmware accepts CIM codes 3, 4 and 7 as this collection issues them is now
answered, on this machine: no, it does not. The codes themselves are correct — per the
DMTF/`go-wsman-messages` mapping already established in Tier 1 — and this result is
about firmware's willingness to act on them, not about this collection's encoding of
them. The second half of that old entry — whether the machine actually *enters* S3, S4
or S5 — remains as out of reach as ever, and is now additionally moot on this specific
machine: firmware never lets the request reach a platform that could honour it.

**Scope, stated precisely.** This is one machine, one firmware version: AMT 16.1.30 on
`amt-lab-01`. Machine 2 (AMT 19.0.5) has never been asked to sleep or hibernate. Nothing
here should be read as "AMT does not support sleep" — only that this specific firmware,
on the one machine that has ever been asked, refuses all three actions this module
advertises. See `plugins/modules/amt_power.py` and
[`docs/amt_power.md`](amt_power.md), both updated to carry this finding where an
operator reading the option list will see it before trying one of these three states.

### Wake-while-powered-off: reachable and wakeable on machine 1, per AMT's own report

**Evidence.** Stage 12 (`qualify_wake_from_off.yml`), CircleCI pipeline **208**,
workflow `282b6692-94a2-481b-aacf-32c2cb1b2dfe`, job `hardware-wake-from-off`
(**2578**), against `amt-lab-01`, AMT 16.1.30, 2026-07-31 — the last stage in the chain,
and the first time any stage powered a machine off and then tried to reach it.

- `before: {normalized: "on", raw: 2}`
- `off_confirmed_by_amt: {normalized: "off", raw: 8}`
- `reachability_probes_while_off`: **3 probes**, `reachability_probe_failures`: **0**
- `wake_request_accepted: true`
- `restored_to: {normalized: "on", raw: 2}`
- `operator_attestation: null`

So AMT answered WS-Man **three times out of three** while reporting itself powered off,
accepted a wake request, and the machine came back on. This is materially stronger than
the position this document held before this run ("configuration says it should work,
nothing has measured it") — the subsection above already established both machines
report `wake_on_lan_capable: true` from `link_policy` `14` (Sx AC), and this stage is
the first time that configuration was actually exercised by powering a machine off and
trying to reach it.

**It is not the full claim, and the gap is preserved deliberately.**
`off_confirmed_by_amt` is AMT's own self-report of its own power state, not independent
confirmation of genuine physical power-off — the same distinction stage 2's note draws
for machine identity. `operator_attestation` is `null` on this run, and will be `null`
on every unattended CI run, because nothing reachable from CI can supply it; only an
attended run, with a human physically present or a switched outlet the runner can
query, can. So what this stage measured is: WS-Man kept answering, and a wake request
worked, while AMT itself reported the machine off. What it did not measure is whether
the machine was genuinely, physically off at the time. The Tier 4 entry for this claim
shrinks to exactly that remaining gap — see Tier 4 below.

### Two limits on how far Tier 3 can be audited

**Stage 5 writes no evidence file.** `qualify_media_attach.yml` is the only one of the
seven qualification playbooks with no `copy` task; it ends by asking a human to
visually confirm the boot hand-off. So the collection's flagship hardware claim — that
the native Python IDE-R engine served a real bootable ISO to real firmware — rests on
an operator's word, with nothing recorded that a third party could inspect. Every
other stage emits a JSON artifact. Stage 3's evidence gap was found and fixed
(`check_mode: false`, since the playbook runs under `--check` by design); stage 5's is
still open, and is tracked in Tier 4.

**Every Tier 3 row now cites a run, but not to the same depth.** This entry used to
read "no Tier 3 row cites a specific run" — accurate when written, and the reason it
was written is that dates and machine names alone leave a reader nothing to go and
check. What is recorded now, and what still is not:

- **Every stage row is citeable**, but through the run list at the top of this tier
  rather than in the row itself. The stage table names machines and outcomes; the run
  list names the workflow and the individual job each stage ran as, so "stage 6 on
  machine 2" resolves to one job UUID. The rows are not repeated with their own
  citations because a stage row that named its own job would have to name two — one
  per machine — and the run list already distinguishes them by date.
- **Pipeline numbers exist for three of the five runs**, #93, 167 and 208. For machine
  1's 2026-07-28 qualification and its 2026-07-29 read-only re-run, the workflow and job
  UUIDs were recovered and are recorded above, but the pipeline number was not: the
  API surface used to recover them returns run, workflow and job UUIDs and does not
  expose the pipeline number, and no commit message recorded it at the time. Those two
  runs are therefore cited by UUID and date only. **No pipeline number has been
  inferred from ordering** — sequence would make one easy to guess and a guessed
  identifier is worse than an absent one in a document whose purpose is this.
- **Runs from now on carry a digest; the first four do not, permanently.** This used to
  read "no artifact digest is recorded anywhere" (issue #90). Every hardware job now
  emits `hardware-evidence/SHA256SUMS` — a SHA-256 per published evidence file,
  computed by the job itself immediately after `tests/hardware/redact-evidence.py` runs
  and before `store_artifacts` publishes, so the digest covers exactly the bytes a
  reader can fetch. A reader who downloads a future run's evidence can re-hash it and
  check the result against that run's cited manifest, which closes the original
  complaint for every run from here on. **Pipeline 208 (stages 9-12, machine 1,
  2026-07-31) is the first run this applies to**, so it is also the first Tier 3 run
  in this document whose citation includes a manifest a reader can actually check
  against. **The four runs before it cannot be given one retroactively, and are
  explicitly digest-less rather than silently left without one**: their artifacts can
  still be hashed *as served today*, but that would only prove what CircleCI is
  serving now, not what this document's authors actually read at the time — the one
  thing a digest is for. That gap is permanent for those four, the same way the two
  limits above it are not fixable after the fact.

## Tier 4: Still unproven

A short list, deliberately — and split, because it was previously one list holding two
different kinds of thing. Some entries are work that is planned and closeable in this
lab; the rest are limits of what an unattended two-machine lab can observe at all. A
reader deciding whether to wait for something needs to know which is which, and the
undivided list did not say.

No entry has been added to or dropped by the split, and no caveat trimmed. Two entries
gained a paragraph, because filing an entry under a heading forced a question the
undivided list let it leave open: *which part* of the claim is backlog and which part is
out of reach. Both are marked **spans the split** below.

### Not yet done — closeable with planned lab work

These are a backlog. Each names a specific test or artifact that does not exist yet,
each would move a claim up a tier when it runs, and none needs a *different* lab — at
most an attended run or a small addition to the one that exists, said where it applies.

- **That stage 5 served media, in any form a third party can check.** ~~The stage emits
  no evidence file.~~ **Partly closed**: stage 5 now writes a durable evidence artifact
  (added 2026-07-31), so the claim no longer rests on an operator's visual confirmation
  alone. What is still unproven is narrower and unchanged — that bytes were *served* —
  because nothing at the other end issues a SCSI read during an unattended run. The
  artifact records what the engine did, not what a BIOS consumed.
- **`amt_event_log` and `amt_log_clear` on machine 2.** Both modules are now Tier 3 on
  machine 1 (stages 9 and 10, pipeline 208, 2026-07-31 — see the dedicated Tier 3
  subsection). Machine 2 (AMT 19.0.5) has never run either stage. Closeable the
  ordinary way: run stages 9 and 10 against machine 2, the same repeatability step
  every other mutating stage has already had. Until then this is one machine, one
  firmware version, not the two-generation coverage the rest of Tier 3 has.
- **Sleep and hibernate on machine 2.** Stage 11 has run once, against machine 1, and
  the answer there was a clean, negative one — see the dedicated Tier 3 subsection.
  Whether AMT 19.0.5 answers the same three requests the same way is unmeasured;
  refusal on one firmware version is not evidence about another. Closeable by running
  stage 11 against machine 2.
- **Wake-from-off's independent confirmation step.** Stage 12 has run once, against
  machine 1, and measured that WS-Man kept answering and a wake request was accepted
  while AMT self-reported the machine off — see the dedicated Tier 3 subsection for the
  full result. What remains unproven, and is now the *entire* content of this entry, is
  narrower than it used to be: **independent** confirmation that the machine was
  genuinely, physically off during those probes, not merely reported off by the same
  firmware being asked to answer them. `operator_attestation` is `null` on this run and
  will be `null` on every unattended CI run, because nothing reachable from CI can
  supply it.

  **This entry spans the split, at the confirmation step.** Running stage 12 again — on
  machine 2, or attended on either machine — is an ordinary extension of what already
  exists and belongs in this backlog. Supplying *independent* confirmation is not:
  independent means outside this collection's own read path, the same thing stage 2's
  note says CI cannot reach for machine identity. That needs something the lab does not
  have yet — a switched outlet the runner can query, or a human at the machine typing
  an attestation — so it closes with an attended run or a small addition to the lab, not
  by adding a task to an existing stage. Nothing about the claim changes because of
  that: physical power-off is still **not independently confirmed**, on either machine.

### Permanently unproven — documented as out of reach, and accepted

**What "accepted" means here.** These are out of reach without changing what the lab
*is* — an unattended pair of machines with no operating system on the target and no
visibility into the boot services around it. They are recorded rather than dropped
because a claim this document does not make is exactly as much a part of the accounting
as one it does, and because each explains why a result a reader might expect to see is
absent. **Accepted is not forgotten, and it is not pending work**: nothing below is
waiting on anyone, none of it is a defect, and no reader should treat this subsection as
a gap that a future release is expected to close. If any of it ever does become
reachable — an attended run with an OS on the target, an instrumented boot network, a
third firmware generation — the entry moves up to the backlog above and says so.

- **A non-zero IDE-R write.** Stage 6 proves the device is accepted, attached and
  presented writable, and that the session stays healthy. It does **not** prove
  bytes were written, because nothing at the other end issues a SCSI write: a
  BIOS sitting at a boot prompt does not spontaneously write to an attached
  floppy. `bytes_written == 0` is the expected unattended outcome and is reported
  as such — and it is now the observed outcome on **both** machines, across both
  firmware generations, which strengthens that explanation rather than weakening
  it: the zero is a property of the unattended setup, not of one endpoint. Proving
  a real write needs an operating system on the target that writes.
- **That a target operating system actually enters S1/S3/S4/S5.** Proving a real
  transition needs an OS on the target to honour the ACPI request, which this lab does
  not have — the same limit as the IDE-R write above. On machine 1, AMT 16.1.30, this
  is now additionally moot rather than merely out of reach: stage 11 measured that
  firmware refuses `sleep-light`, `sleep-deep` and `hibernate` itself, before any
  request reaches a platform that could act on it, so there is currently nothing for an
  OS on that machine to honour. That is a statement about this one firmware version;
  it says nothing about machine 2 or any other generation, which is why the machine-2
  repeatability question stays in the backlog above rather than moving here.
- **That a PXE exchange actually happened.** Stage 7 proves the arming, the reset
  and the recovery. Whether the machine reached a DHCP/TFTP exchange depends on
  boot services this collection cannot observe.
- **That AMT's internal one-shot role bit was consumed.** No module exposes a read
  path for it, so stage 7 asserts `AMT_BootSettingData` stability instead. The
  headline claim that a one-time boot "does not persist" is therefore
  *inferred*, not directly measured. Accepted rather than queued because the claim
  this document can make is about **this collection's** read paths: no module has one,
  and nothing consulted here establishes that AMT exposes one to be implemented
  against. That is a narrower statement than "AMT offers no read path", and the
  narrower one is what the evidence supports — so this entry is not a request for a
  module nobody has written, and should not be read as one.
- **Any firmware generation other than 16.1.30 and 19.0.5.** Both lab generations
  have now been mutated through stages 4 to 7, read with the full v0.2.0 fact set, and
  read with the 0.5.0 hardware/asset inventory — so none of "mutating anything at all",
  "reading the network and system-state facts" and "reading the inventory classes" is a
  single-generation result any more. Every generation outside those two is still
  untouched, including the Small Business Mode / no-TLS path, which is inferred from
  `parmstro`'s reporting rather than observed here. Two generations is repeatability; it
  is not a compatibility guarantee. Accepted rather than queued because what is missing
  is a machine the lab does not have, not a test nobody has written: no amount of work
  on this collection closes it, and the Small Business Mode / no-TLS path needs a
  differently *provisioned* endpoint on top of that.

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
modules that existed at the time disagreed on where the operation receipt lived
(`amt_event_log` and `amt_log_clear` were added afterwards and were built to the
settled shape from the start): `amt_power` nested its
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
`session_id`/`session_state`/`devices`/`bytes_read`/`bytes_written`, `amt_info`'s `amt`,
`amt_event_log`'s `records`/`total_records`/`records_read`/`log`, `amt_log_clear`'s
`records_before`/`records_after`/`cleared`/`return_value`/`log`)
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
[`amt_redirection`](amt_redirection.md), [`amt_media`](amt_media.md),
[`amt_event_log`](amt_event_log.md), [`amt_log_clear`](amt_log_clear.md)) for the exact,
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
| **16.1.30** (machine 1) | Yes, pinned | Verified | Advertised | Verified | **Hardware-verified, all eight stages as they existed then** (2026-07-28). `amt_info`'s network/system-state facts came back fully populated on a read-only re-run (2026-07-29). Stages 9-12 then ran here for the first time (2026-07-31, pipeline 208): `amt_event_log`/`amt_log_clear` passed; `sleep-light`/`sleep-deep`/`hibernate` were all refused by firmware; wake-while-off answered WS-Man 3/3 and accepted a wake request |
| **19.0.5** (machine 2) | Yes, pinned | Verified | Advertised | Verified | **Hardware-verified, all eight stages as they existed then** (2026-07-29). Capability flags were read live and all four came back `true`; the network/system-state facts came back fully populated here too |

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
and the read-only stages have since been re-run against both machines so that both
generations have been read with the same fact code, inventory included. What Tier 4
still lists is therefore neither "a second machine" nor "a re-run of the first" — it is
the specific things no green run on either machine measures — a list now split by
whether running something would close it:

- **Backlog** — that bytes were genuinely served during stage 5, `amt_event_log` and
  `amt_log_clear` against real firmware on machine 2, the sleep/hibernate request path
  on machine 2, and independent confirmation of physical power-off for stage 12.
  Stages 9, 10, 11 and 12 have each now run once, against machine 1 only (pipeline
  208, 2026-07-31) — see the dedicated Tier 3 subsections — so what is left in this
  half of Tier 4 for those four stages is machine-2 repeatability and, for stage 12
  specifically, the independent-confirmation step no CI run can supply.
- **Accepted as out of reach** — a real SCSI write, a PXE exchange, the internal
  one-shot role bit, that a target OS genuinely enters S1/S3/S4/S5, and any third
  firmware generation. These are not waiting on anyone; they are what an unattended
  lab with no OS on the target cannot see.

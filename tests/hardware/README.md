<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Hardware-in-the-loop qualification

These playbooks power-cycle, attach boot media to, and can reimage **real**
Intel AMT machines. Nothing here runs against a mock server. See
[`docs/testing.md`](../../docs/testing.md) for how this fits into the
collection's three testing tiers.

## Gating

Every hardware job sits behind at least two independent gates, neither of
which fires on an ordinary push:

1. **Pipeline parameter.** The `hardware` CircleCI workflow only exists when
   the pipeline is triggered with `run-hardware-tests=true`
   (`.circleci/config.yml`). A normal push cannot reach it.
2. **Manual approval.** Even then, a human must approve a `type: approval`
   job in the CircleCI UI before the corresponding hardware job runs.

`hardware-tests` runs on a self-hosted machine runner inside the lab network
(`resource_class: crowley/amt-runner`), behind `hardware-approval`, and
invokes the four **non-mutating** stages below:

```yaml
- run:
    name: "Stage 1: read-only AMT qualification"
    command: ansible-playbook tests/hardware/qualify_readonly.yml -i tests/hardware/inventory.yml -v
- run:
    name: "Stage 3: check-mode power and boot plans (no mutation)"
    command: ansible-playbook tests/hardware/qualify_checkmode.yml -i tests/hardware/inventory.yml --check -v
- run:
    name: "Stage 8: idempotent re-probe"
    command: ansible-playbook tests/hardware/qualify_idempotent_reprobe.yml -i tests/hardware/inventory.yml -v
- run:
    name: "Stage 9: read-only amt_event_log"
    command: ansible-playbook tests/hardware/qualify_event_log.yml -i tests/hardware/inventory.yml -v
```

Stages 4-7 -- the mutating ones -- are wired into CI too, as four separate
jobs (`hardware-power`, `hardware-media`, `hardware-writable`, `hardware-pxe`),
each **escalating past the last and each behind its own separate approval
job** (`hardware-power-approval`, `hardware-media-approval`,
`hardware-writable-approval`, `hardware-pxe-approval`). One approval does not
cover all four: a human confirms every escalation independently, from
"power-cycle" through "arm a native PXE boot," rather than one click
green-lighting everything. Each of these jobs runs the corresponding
playbook with `-e amt_qualify_attended=false`, which skips the playbook's own
interactive `ansible.builtin.pause` prompts -- those block on stdin, which the
CircleCI machine executor cannot supply, so the approval job itself is CI's
human checkpoint. **The approver is expected to already have the KVM/console
open before clicking approve**, exactly as an attended manual run asks a human
to do by hand. Stage 7's job additionally reads the `pxe-prereqs-confirmed`
pipeline parameter (default `false`) into `amt_pxe_prereqs_confirmed`, so that
attestation has to be set deliberately on the pipeline trigger, not assumed.

The same escalating, own-gate-per-stage pattern continues past stage 7:
`hardware-log-clear` (stage 10), `hardware-sleep-hibernate` (stage 11), and
`hardware-wake-from-off` (stage 12, last in the chain) each sit behind their
own approval job, downstream of the one before. **Read
[`PREFLIGHT.md`](PREFLIGHT.md) before approving any of these three** -- stage
10 is irreversible, and stages 11-12 can leave a machine needing a physical
hand to bring back. Stage 9 has no approval of its own; it runs as a fourth
step inside `hardware-tests` above, for the same reason stages 1/3/8 do -- a
read is not a mutation.

Stages 5 and 6 need small local media files that must never be committed
(`.gitignore` blocks `*.iso`/`*.img`); their jobs run
[`make-test-media.sh`](make-test-media.sh) first to provision a small
genuinely-bootable ISO (iPXE's own `ipxe.iso`) and a zero-filled writable
image, entirely inside the workspace. Run it yourself for a manual run too:

```bash
./tests/hardware/make-test-media.sh
# prints AMT_TEST_ISO_PATH= / AMT_TEST_IMAGE_PATH= for tests/hardware/render-inventory.sh
# to pick up, or pass them directly with -e amt_test_iso_path=... / -e amt_test_image_path=...
```

None of this weakens what stages 4-7 -- or 10-12 -- running unattended in CI
can actually prove -- see each job's own comment in `.circleci/config.yml`,
each playbook's own header comment, and (for 10-12) `PREFLIGHT.md` for the
exact, honest scope of what a green run does and does not establish. In
particular: stage 6 (`hardware-writable`)
will always observe `bytes_written=0` when run unattended, because nothing is
booted on the target to issue a write -- that is documented as a legitimate
outcome, not a failure. Stage 7 (`hardware-pxe`) cannot verify netboot itself
succeeds, since that depends on DHCP/boot-service infrastructure this
collection has no way to observe.

## Inventory and credentials

`tests/hardware/inventory.yml` is **gitignored** (see the repository
`.gitignore`). Commit only [`inventory.yml.example`](inventory.yml.example),
which uses obviously fake hostnames (`.invalid` TLD) and addresses
(`203.0.113.0/24`, the RFC 5737 documentation range).

Real hostnames, AMT credentials, and TLS fingerprints come from the
self-hosted runner's environment (`AMT_USERNAME`, `AMT_PASSWORD`,
`AMT_TLS_FINGERPRINT`, looked up via `lookup('ansible.builtin.env', ...)` in
the example inventory) -- never from a file in this repository.

Evidence this stage produces is written to `tests/hardware/output/`, which is
also gitignored; the CircleCI job stores it as build artifacts instead
(`store_artifacts: path: tests/hardware/output`). Everything in that directory
is redacted first -- see below.

## Evidence redaction

Every stage playbook now has a task that writes JSON evidence into
`tests/hardware/output/` -- stage 5 and stages 9-12 are the additions that made this
universal; see "Verified on real evidence" below for a historical run from before that
was true. CI publishes the whole directory as the `hardware-evidence` artifact. Those
values come from firmware, so they describe a real machine on a real network.

[`redact-evidence.py`](redact-evidence.py) rewrites every `.json` file in that
directory in place, and every `hardware-*` job runs it via the shared
`redact-hardware-evidence` command **immediately before `store_artifacts`**,
with `when: always` so evidence written before a failing stage is covered too.

### Why it exists

**CircleCI masks context values in log output only. It does not mask
`store_artifacts` content.** Holding `AMT_HOST` and friends in the restricted
`amt-lab-runner` context therefore never censored the evidence files, and
artifact visibility follows the project's "Free and Open Source" flag -- which
made the published evidence world-readable. That flag is a checkbox, so the
artifact has to be safe on its own rather than safe because of how the project
happens to be configured today. A previous history rewrite deliberately removed
exactly this class of data from the repository; leaking it through CI artifacts
would defeat that work.

It runs at the CI layer, once, rather than inside each playbook. Eleven write sites
are eleven chances to forget, and a twelfth playbook added later would leak by
default. The right place to fix it is where the data leaves the machine.

### What is redacted

| Category | Examples |
| --- | --- |
| IPv4 and IPv6 addresses | `ip_address`, `default_gateway`, `subnet_mask`, `primary_dns`, `secondary_dns`, the address inside `operation.endpoint` |
| MAC addresses | `mac_address` and `mac_address_raw`, colon- or dash-separated, any case |
| UUIDs / platform GUIDs | `uuid`, dashed and 32-character compact forms |
| SHA-256 fingerprints and digests | `operation.tls_peer_fingerprint`, bare 64-hex digests |
| DNS names / FQDNs | `domain_name`, and any `label.label...tld` inside a message |
| The AMT hostname | `hostname` -- a bare label matches no pattern, so the key is what identifies it |

Strings are walked wherever they occur, including inside lists, nested
dictionaries, and strings that merely *contain* an address rather than being one
(`"WS-Man Get against 192.0.2.10:16993 failed"`). Keys are never rewritten.

Each distinct value maps to a stable pseudonym for the whole run
(`<redacted-ipv4-1>`, `<redacted-mac-1>`, ...), so an address appearing in three
files is still recognisably one machine. Tokens are assigned in order of first
appearance and are deliberately **not** derived from the value: a hash of an
IPv4 address on a known /24 is a reversible oracle -- 254 guesses -- and a MAC on
a known OUI is not much better.

### What is deliberately preserved, and why

Over-redaction is its own failure. The point of keeping these artifacts is that
a reviewer can tell what the firmware actually did, and evidence scrubbed into
uselessness is evidence that gets dropped a release later. So the following stay
exactly as the firmware reported them:

- Firmware `version` (`19.0.5`) and `bios_version`. Both are dotted and
  TLD-shaped; the FQDN rule requires the label before the last one to contain a
  letter, which is what keeps `EXAMPLE10H.86A.0000.2026.0101.0000` out of it.
- Capability flags, `power_state`, `enabled_state`, `operational_status`,
  `requested_state`, `link_policy` integers, `wake_on_lan_capable`.
- `bytes_read` / `bytes_written`, `writable`, `session_id`, `error_class`,
  `AMT_BootSettingData` fields, and every boolean.
- Repository paths in the prose `note` and `diagnostic` fields
  (`tests/hardware/README.md#...`): `md` and `yml` are TLD-shaped labels, and
  redacting them would delete the pointer a reviewer is meant to follow.
- Public standards domains inside WS-Man resource URIs (`intel.com`,
  `schemas.dmtf.org`, `schemas.xmlsoap.org`, `w3.org`, `oasis-open.org`). Those
  are protocol constants, not lab data.
- The JSON structure itself: same keys, same nesting, same types.
- **`amt_info`'s per-property shape census**, new in 0.7.0:
  `operation.hardware_reads.<class>.property_shapes`. This one needs its own rule
  and is the most interesting entry in this list, because the general rules
  actively get it wrong.

  The census is keyed by CIM property name with a shape label as the value --
  `{"SerialNumber": "absent", "Model": "text"}` -- which is what makes issue #84
  answerable: whether firmware sent `CIM_Card.SerialNumber` at all, and if it did,
  whether it was empty. But that puts the literal string `SerialNumber` in **key**
  position, and `serialnumber` is in the identifying-key table that catches real
  serial numbers. Unmodified, the script rewrote the *shape* `"absent"` to
  `<redacted-serial-1>`: the third instance of over-redaction in this file, and the
  worst-behaved, since a reader would see a plausible token and never know a
  diagnostic had been destroyed.

  The exemption is scoped two ways so it cannot become a hole -- to the census
  **container**, and to the **closed vocabulary** of five shapes `amt_info` can
  emit. Anything else in census position is redacted exactly as it would be
  anywhere else, which is asserted with a real serial (caught by key) and an IPv4
  address (caught by pattern).

  What this does **not** do, stated plainly: census keys come from firmware, and
  this script never rewrites keys. Safety there comes from the generator, which
  publishes a name only if it matches the CIM property-name grammar -- a letter,
  then letters, digits and underscores, 64 max -- and counts anything else in
  `property_names_dropped` instead. Every category above needs a character that
  grammar forbids, or is longer than it allows. A non-zero
  `property_names_dropped` in an artifact means a firmware sent a name nobody has
  seen; look at it interactively rather than reasoning from the artifact.

Redacting twice is a no-op, so a re-run cannot renumber the tokens.

### Verified on real evidence, not only on unit tests

The redactor shipped with unit tests and no live exercise. On **2026-07-29** it ran
for the first time against real hardware evidence, on the read-only re-run of
machine 1, and it worked:

```
redact-evidence: 2 JSON file(s) rewritten, 21 value(s) redacted
  ipv4: 11 occurrence(s), 3 distinct value(s)
  mac: 4 occurrence(s), 2 distinct value(s)
  uuid: 2 occurrence(s), 1 distinct value(s)
  fqdn: 2 occurrence(s), 1 distinct value(s)
  hostname: 2 occurrence(s), 1 distinct value(s)
```

Three things that run established, which unit tests could not:

- **The published artifact is clean.** The `hardware-evidence` artifact from that run
  was independently swept for IPv4, MAC and UUID patterns afterwards: **zero hits**.
  That is the check that matters, because it tests the artifact a stranger can
  download rather than the script's own report of itself.
- **The diagnostic substance survived.** Firmware version, BIOS version, the
  `link_policy` integers, the enabled/operational/requested states and the byte
  counters all came through intact, which is the over-redaction failure mode this
  section's preservation rules exist to prevent. The evidence was still readable as
  evidence.
- **Stable pseudonyms do what they are for.** `primary_dns` and `secondary_dns` both
  mapped to the *same* token, correctly preserving the fact that this machine points
  at one DNS server twice without disclosing which server. A per-occurrence random
  token would have hidden that; a hash of the value would have disclosed it.

Two files rather than three, for a three-stage run, is expected and is worth knowing
about: `qualify_checkmode.yml`'s evidence-writing `ansible.builtin.copy` carries no
`check_mode: false`, and stage 3 runs under `--check`, so stage 3 writes no evidence
file at all. Only stages 1 and 8 produced one. Nothing leaked as a result — a file
that does not exist cannot be published — but do not read a stage-3 evidence file's
absence from an artifact as a redaction failure.

### Running and testing it by hand

```bash
python3 tests/hardware/redact-evidence.py tests/hardware/output
```

Stdlib only, and invoked with the system `python3` rather than the lab venv on
purpose: the step runs even on the paths where `.venv` was never built. It never
exits non-zero, including when the directory does not exist -- it must not turn a
red job into a differently red one. It prints a per-category count of what it
redacted, which is the line in the job log that tells a reviewer it actually ran.

Unit tests live in
[`tests/unit/hardware/test_redact_evidence.py`](../unit/hardware/test_redact_evidence.py),
and they remain the only place the behaviour is exercised deterministically — the
live run above confirms it, but a hardware run is not a regression test.
Every fixture there uses obviously fake values -- RFC 5737 TEST-NET-1, RFC 3849
documentation IPv6, the RFC 7042 documentation MAC block, `.invalid` domains.
**Never put a real lab value in a fixture**; a committed fixture is exactly the
leak this script exists to prevent.

## The staged plan, and why it never runs in parallel

**The `amt_event_log`/`amt_log_clear` gap is closed, for real, on machine 1.** Stages
1-8 predate both event-log modules, and until stage 9 was added neither had ever run
against real firmware. Stage 9 (`qualify_event_log.yml`) is the read-only half, wired
into the existing `hardware-tests` job precisely because a read is non-destructive
exactly like `amt_info`'s. Stage 10 (`qualify_log_clear.yml`) is the destructive half,
behind its own approval gate downstream of every prior mutating stage, and performs its
own read-archive-verify sequence immediately before the irreversible call rather than
trusting an earlier stage's run to still be current. **Both stages ran against real
firmware for the first time on 2026-07-31** (CircleCI pipeline 208), against
`amt-lab-01` only, and both passed -- see [`PREFLIGHT.md`](PREFLIGHT.md) for what was
read before approving stage 10, and
[`docs/capability-matrix.md`](../../docs/capability-matrix.md) Tier 3 for the full
result. Both modules are now hardware-qualified **on one machine**; `amt-lab-02` has
never run either stage.

Stages 11 and 12 close two further gaps the original eight stages never reached:
`amt_power`'s sleep-light/sleep-deep/hibernate states (stage 4 covers only on/off), and
whether the endpoint can actually be reached and woken over WS-Man while genuinely
powered off (no earlier stage ever tried). Both also ran for the first time on
2026-07-31, against `amt-lab-01` only. Stage 11's result is a clean negative: AMT
refused all three sleep/hibernate requests outright, before they reached the platform.
Stage 12 measured that WS-Man kept answering, and a wake request landed, while AMT
self-reported the machine off -- with the caveat that AMT's own self-report is not
independent confirmation of genuine physical power-off. See the subsections in
[`docs/capability-matrix.md`](../../docs/capability-matrix.md) Tier 3 for both.

There are **twelve numbered stages** and **eleven playbooks**: stage 2 has no
playbook of its own, because it is a human cross-check performed on stage 1's
output rather than anything Ansible can assert unaided. Each stage is a gate on
the next. They run in this order, and **never in parallel** -- a failure at stage
N must stop everything after it, not race ahead on the assumption stage N was
cosmetic:

| Stage | Playbook | Mutates? | What it catches |
|---|---|---|---|
| 1 | `qualify_readonly.yml` | No | Endpoint unreachable, firmware read failures. Stage 1b within it reads the hardware/asset inventory and, since 0.7.0, records the per-property **shape census** of `CIM_Chassis` and `CIM_Card` -- which is what settles issue #84 (see [What is deliberately preserved](#what-is-deliberately-preserved-and-why)) |
| 2 | *(none -- human review of stage 1's output)* | No | **Inventory/reality mismatch** -- firmware-reported UUID vs. reviewed `amt_expected_uuid` |
| 3 | `qualify_checkmode.yml` (`--check`) | No | Module check-mode paths that unit/mock tests cannot fully exercise against real firmware quirks |
| 4 | `qualify_power.yml` | Yes | Real `RequestPowerStateChange` behaviour, attended |
| 5 | `qualify_media_attach.yml` | Yes | IDE-R attach and boot hand-off against real firmware |
| 6 | `qualify_writable_image.yml` | Yes | The device is accepted, attached, and presented writable; a non-zero `bytes_written` (needs something booted on the target to write) is cross-checked against the on-disk checksum. `bytes_written=0` is expected without that and is **not** a failure -- see the playbook header |
| 7 | `qualify_pxe.yml` | Yes | One-time PXE arms and reads back armed; the reset is issued and the endpoint recovers; `AMT_BootSettingData` is not left drifted by the reset. Does **not** verify netboot itself succeeds (depends on DHCP/boot-service infrastructure) or read back AMT's internal one-shot role bit -- see the playbook header |
| 8 | `qualify_idempotent_reprobe.yml` | No | No session or state was left quietly drifting after everything above |
| 9 | `qualify_event_log.yml` | No | Whether real firmware accepts this collection's `GetRecords` iteration as issued, and whether the 21-byte record layout and little-endian timestamp decode correctly against records a real ME actually wrote |
| 10 | `qualify_log_clear.yml` | Yes -- **irreversible** | Whether `ClearLog` is accepted and the log reads back empty by two independent reads, after archiving whatever it held to disk first. See [`PREFLIGHT.md`](PREFLIGHT.md) |
| 11 | `qualify_sleep_hibernate.yml` | Yes | Whether AMT accepts and can act on sleep-light/sleep-deep/hibernate, with the outcome classified so an unsupporting OS is never conflated with a defect here. See [`PREFLIGHT.md`](PREFLIGHT.md) |
| 12 | `qualify_wake_from_off.yml` | Yes | Whether WS-Man stays reachable, and a power-on request lands, while the endpoint reports itself off. See [`PREFLIGHT.md`](PREFLIGHT.md) for exactly what this does and does not establish about the host being *genuinely* off |

**Stage 2 is the one that matters most and is easiest to skip.** It is not
testing AMT or this collection -- it is testing whether `inventory.yml` and
the physical machine in front of you still agree with each other. Inventory
drifts: a machine gets re-racked, a DHCP lease changes, someone repurposes a
lab box. `qualify_readonly.yml` records the firmware-reported UUID on first
run and, once a human has reviewed it and filled in `amt_expected_uuid`,
cross-checks it on every subsequent run. Skipping this is how you reset the
wrong machine.

Stage 3 gates on `ansible_check_mode` itself (see the assertion in
`qualify_checkmode.yml`) precisely so that forgetting `--check` on the
command line turns into an immediate, loud failure instead of a real power
action landing where a preview was expected.

Stages 4 through 7 are progressively more disruptive and are marked
"attended" in their own file headers: a human should be watching the machine
(console or KVM) while each one runs, not just watching the Ansible output.
For a manual run this means answering the `ansible.builtin.pause` prompts;
in CI it means the approver watching the console before approving that
stage's job (see Gating above -- `amt_qualify_attended=false` skips the
prompts themselves in CI, but the human checkpoint they exist for is still
there, just moved to the approval). Stage 7 additionally requires
`-e amt_pxe_prereqs_confirmed=true` (or, in CI, the `pxe-prereqs-confirmed`
pipeline parameter set `true`), because nothing in this collection can verify
a PXE/DHCP boot service actually exists on the target's network -- that has
to be proven independently first, or stage 7 just strands the machine at a
PXE ROM prompt.

Stage 9 is read-only and shares stage 1/3/8's `hardware-tests` gate rather than
earning its own. Stages 10 through 12 are, like 4-7, progressively more
disruptive, attended in the same sense, and each behind its own approval gate
-- but unlike 4-7, **read
[`PREFLIGHT.md`](PREFLIGHT.md) before approving any of the three**: stage 10
is irreversible, and stages 11-12 can leave a machine needing a physical hand
to bring back. PREFLIGHT.md is written specifically for the moment right
before you click approve, not as background reading.

## Qualify one machine first

Qualify exactly one machine through all twelve stages before running any
stage against a second. A second machine then proves **repeatability** --
that the first machine's success was not a fluke of that specific firmware
build or lab-network quirk. Never cut both machines over to a new stage at
once: if a firmware quirk bricks a boot configuration, you want a known-good
machine to compare against while recovering the other.

### Where the lab actually stands

Stated precisely, because which run established what still matters:

| Machine | Firmware | Stages completed | Run date |
|---|---|---|---|
| `amt-lab-01` | AMT 16.1.30 | **All eight** (1, 2, 3, 4, 5, 6, 7, 8) | 2026-07-28 |
| `amt-lab-02` | AMT 19.0.5 | **All eight** (1, 2, 3, 4, 5, 6, 7, 8) | 2026-07-29 |
| `amt-lab-01` | AMT 16.1.30 | Read-only re-run (1, 3, 8), nothing mutated | 2026-07-29 |
| `amt-lab-01` | AMT 16.1.30 | **9, 10, 11, 12** -- all four, first real-firmware run of any of them | 2026-07-31 |

**"All eight" in the first two rows means all eight that existed at the time.**
Stages 9-12 were added after both of those runs. They have now run once each, on
machine 1 only (pipeline 208) -- see the previous section for the result of each and
[`PREFLIGHT.md`](PREFLIGHT.md) before approving 10-12 on machine 2, which has not
run any of them.

Machine 2 cleared its four mutating approvals on 2026-07-29, so power control,
IDE-R media, the writable-image path and native PXE are reproduced on a second
machine of a *different* firmware generation -- which is worth more than a
second machine of the same one. That run was limited to machine 2 alone
(`hardware-limit=amt-lab-02`), so machine 1 was untouched by it, exactly as the
"never cut both machines over at once" rule above asks.

**Coverage is now the same on both generations.** It was not: `amt_info`'s network
and system-state facts (added in v0.2.0) had come back populated from 19.0.5 only,
because machine 1's evidence predated the code that reads them. The 2026-07-29
read-only re-run of machine 1 (`hardware-limit=amt-lab-01`, `hardware-tests` only,
no mutating approval requested) closed that: **every one of those fields came back
populated on 16.1.30 too**. Machine 1's mutating result still rests on its
2026-07-28 run -- the re-run did not, and was not meant to, re-establish it. See
[`docs/capability-matrix.md`](../../docs/capability-matrix.md) Tier 3.

One result from that re-run is worth reading before you trust a remote power-on:
**both** machines report `link_policy` `[1, 14]`, which is `s0_ac` plus `sx_ac` --
`14` is "available on Sx AC", so both report `wake_on_lan_capable: true`. That is a
correction: through 0.3.0 this collection decoded `14` as `s0_dc` and reported
`false` here, from a value table that was wrong (see
[`docs/capability-matrix.md`](../../docs/capability-matrix.md) Tier 1). Stage 12
(`qualify_wake_from_off.yml`) has now made that measurement for real, against
`amt-lab-01`, on 2026-07-31: WS-Man answered 3 reachability probes out of 3 while AMT
self-reported the machine off, a wake request was accepted, and the machine came back
on. `amt-lab-02` has not run stage 12. Read the playbook's own header and
[`PREFLIGHT.md`](PREFLIGHT.md) for the honest limit on what even this passing run
establishes from CI: "AMT self-reports off" is not the same as "the host is genuinely,
physically off", and only an attended run with a human watching the machine, or a
switched outlet the runner can query, supplies the latter --
`operator_attestation` was `null` on this run and will be on every unattended one. See
Tier 3 and Tier 4 in [`docs/capability-matrix.md`](../../docs/capability-matrix.md).

Stage 2's automatic comparison is also live now: `amt_expected_uuid` is recorded
for machine 2, and the 2026-07-29 run matched it. Recorded from a value this
collection itself observed, that match detects **drift** in the
inventory-to-endpoint binding -- a reused DHCP lease, a swapped inventory suffix
-- and is not independent proof of machine identity, which needs a source outside
this collection's own read path such as the booted OS's `dmidecode -s
system-uuid`.

Real hostnames, addresses and fingerprints are deliberately absent from this
repository; `amt-lab-01`/`amt-lab-02` are the neutral names
[`render-inventory.sh`](render-inventory.sh) emits.

## If a machine ends up in a bad boot state

One-shot boot is single-use, so a plain power cycle usually clears it. If the
machine is stuck:

1. **KVM console.** [MeshCentral](https://github.com/Ylianst/MeshCentral) (or
   any AMT-aware KVM tool) can show you what the machine is actually doing,
   which is the first thing to check -- a "stuck" machine is often just
   sitting at a BIOS/PXE prompt waiting for input.
2. **MEBx.** Enter the Intel Management Engine BIOS Extension (usually
   `Ctrl+P` at boot) and reset the boot configuration from there if AMT's own
   `AMT_BootSettingData` state looks wrong or the machine will not leave a
   forced boot source.
3. As an absolute last resort, a full AMT unprovision/reprovision cycle
   clears everything, including the admin credential -- treat that as
   destroying the endpoint's identity, not a qualification step.

**Set this path up and confirm it actually works before running stage 5 for
the first time on any new machine.** Discovering you cannot reach the KVM
console *after* a boot configuration has gone wrong is the failure mode this
note exists to prevent.

## What this does not prove

Same caveat as [`docs/testing.md`](../../docs/testing.md): qualifying one or
two lab machines does not prove every AMT generation or SKU behaves
identically. Anything version-dependent is unverified until a stage has
actually run against that specific firmware.

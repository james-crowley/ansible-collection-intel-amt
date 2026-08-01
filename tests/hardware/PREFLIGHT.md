<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Pre-flight briefs: stages 10-12, plus one proposed stage that does not exist

Read the relevant section below **before clicking approve** on
`hardware-log-clear-approval`, `hardware-sleep-hibernate-approval`, or
`hardware-wake-from-off-approval` in the CircleCI UI. This document is written
for the person about to touch real hardware, not for a code reviewer: it says
what can go wrong and what to do about it, not why the code is structured the
way it is (see the corresponding playbook's own header comment for that, and
[`README.md`](README.md) for the staged plan as a whole).

If you are running one of these three playbooks by hand instead of through
CI, everything below still applies -- "the approver" just means you.

**The last section is different in kind from the other three.** `amt_network`
has **no playbook, no stage, and no approval job**. Its brief is here so that a
human has what they need in order to decide whether one should ever exist --
which is a decision this collection has deliberately not made on their behalf.
Nothing in `.circleci/config.yml` refers to it. Read that section as a
proposal, not as instructions for a run you are about to approve.

---

## `amt_log_clear` (stage 10, `qualify_log_clear.yml`)

### What it does

In order, against one machine:

1. Reads the entire event log (`amt_event_log`, the same call stage 9 makes).
2. Writes that read to disk as
   `{{ hostname }}-qualify_log_clear-archive.json`, **before anything else
   happens**.
3. Re-checks that the archive file actually exists on disk and is non-empty.
   Refuses to continue if it does not.
4. **Calls `amt_log_clear` with `confirm_destructive: true`.** This is the
   irreversible step.
5. Reads `records_after` from the clear call's own response.
6. Independently re-reads the log a second time via `amt_event_log` (a
   different WS-Man call than step 5) and confirms it also reports empty.
7. Writes a second evidence file recording the clear and the re-read.

### What it is looking for

Whether real Intel AMT firmware actually accepts and executes `ClearLog` the
way this collection expects, and whether the log genuinely comes back empty
by two independent reads -- not just one call's self-report. Neither
`amt_event_log` nor `amt_log_clear` had ever touched real firmware before
this branch of work; this is the first data point for the destructive half
of that pair.

### Expected outcome on a healthy machine

All steps `ok`. The archive file contains whatever records existed (which may
legitimately be zero). The clear reports `records_after: 0`, or reports the
log was already empty and skipped sending anything (`records_before: 0` --
also a pass, not a failure; see the module's own "convergent on an
already-empty log" behaviour). The independent re-read agrees.

### Failure modes

| Failure | Where it happens | Machine left in |
|---|---|---|
| The pre-clear archive read fails or comes back incomplete | Step 1-3 | **Untouched.** Nothing was cleared. The play stops before `amt_log_clear` is ever called. |
| The archive file cannot be confirmed on disk | Step 3 | **Untouched.** Same as above -- this is the one check standing between "irreversible" and "irreversible and unrecorded", and it is checked before the clear, not after. |
| `amt_log_clear` itself fails (auth, TLS, connection, or a firmware-level refusal) | Step 4 | **Ambiguous -- read this carefully.** A non-zero `ReturnValue` from firmware raises before this collection would ever report `changed: true`, so ordinarily nothing was cleared. But a *timeout or connection failure sent while waiting for the response* is genuinely indeterminate: the request may have reached firmware and been acted on even though the client never saw a reply. Do not assume either way -- go straight to a manual read (see Recovery). |
| The clear reports acceptance but `records_after` (or the independent re-read) is not 0 | Step 5-6 | **Log not actually cleared, or cleared and something new landed immediately after** (e.g. a boot event fired in the gap between the two reads). Treat the firmware's `ClearLog` semantics on this generation as unproven until this is investigated -- do not trust `ReturnValue == 0` alone on this firmware again. |

### Recovery

There is no "recovery" that restores cleared records -- see Blast radius.
What you can recover is *certainty about what state the log is in*:

1. Run `qualify_event_log.yml` (stage 9) by hand against the same machine.
   Its evidence file tells you, independently of this stage's own claims,
   exactly what the log currently holds.
2. If step 4 above failed with a connection/timeout error (the indeterminate
   case), do the read in step 1 anyway before touching anything else -- it
   costs nothing and tells you whether the clear actually landed.
3. This stage never power-cycles, resets, or touches boot configuration. If
   the machine seems unresponsive afterwards, that is not this stage's doing
   -- treat it as a separate incident and use the KVM/MEBx recovery path in
   [`README.md`](README.md#if-a-machine-ends-up-in-a-bad-boot-state).

### Blast radius

**Firmware event history, gone permanently, with no undo and no
firmware-side archive.** This is the entire point of `ClearLog` and the
entire reason this stage exists behind its own gate. The only copy that
survives a clear is the archive file this stage writes to
`tests/hardware/output/` *before* calling `amt_log_clear` -- if that file is
lost (not published as a CI artifact, or deleted before anyone looks at it),
whatever was in the log at clear time is gone with no way to reconstruct it.
Nothing else on the machine is touched: power state, boot configuration, and
every other module's state are unaffected.

---

## Sleep-light / sleep-deep / hibernate (stage 11, `qualify_sleep_hibernate.yml`)

### What it does

For each of three ACPI states in turn (sleep-light, sleep-deep, hibernate),
against one machine that must already be reporting `on`:

1. Queries the current power state and confirms it is `on`; refuses to
   continue otherwise.
2. Pauses for the operator to confirm they are watching the machine
   (skipped in CI -- see each playbook's header for what that means for the
   approval gate).
3. Issues the ACPI transition via `amt_power`.
4. If AMT itself rejected the request, records `firmware_refused` and skips
   straight to step 6.
5. If AMT accepted it, polls (bounded: 5 retries / 10s delay by default)
   for the machine to actually report the expected state, and records either
   `confirmed_transition` or `os_did_not_transition`.
6. **Unconditionally** issues `amt_power state=on` and polls until the
   machine reports `on` again, regardless of what happened above.
7. Moves to the next state. After all three, writes one evidence file with
   every state's result.

### What it is looking for

Whether AMT actually accepts and can act on `RequestPowerStateChange` codes
3, 4, and 7 (sleep-light, sleep-deep, hibernate) against real firmware.
These codes are unit-tested but no hardware stage before this one had ever
issued any of them.

**Read this before judging any single result:** `os_did_not_transition` is
an *expected, legitimate* outcome, not a failure of this collection or of
AMT. AMT can only ask the platform's ACPI subsystem to transition; whether
the target operating system actually supports and enables sleep-light,
sleep-deep, or hibernate at all is entirely outside AMT's control and
outside this collection's ability to observe independently. A machine
running an OS/BIOS combination that does not support S3, for example, will
legitimately show `os_did_not_transition` for `sleep-deep` forever, on every
run, and that is not something to "fix".

### Expected outcome on a healthy machine

Any mix of `confirmed_transition` and `os_did_not_transition` across the
three states is a **pass**. The one thing that must hold for every state,
unconditionally, is that the machine is back to `on` and independently
confirmed as such by the time the stage moves to the next state (or
finishes). `firmware_refused` is also informative rather than fatal on its
own, but is worth a closer look (see the table below).

### Failure modes

| Failure | What it means | Machine left in |
|---|---|---|
| A state comes back `firmware_refused` with `error_class=unsupported_capability` | This AMT generation/SKU does not implement that CIM code at all. Expected on some hardware; not a defect. | On (restore already ran). |
| A state comes back `firmware_refused` with `error_class=remote_operation` or `invalid_state` | AMT rejected the request outright -- worth investigating (e.g. a config, licensing, or MEBx restriction), but not this collection's bug by itself. | On (restore already ran). |
| A state comes back `os_did_not_transition` | Expected outcome; see above. Not a failure. | On (restore already ran). |
| The task fails with an error class **outside** [`remote_operation`, `invalid_state`, `unsupported_capability`] (e.g. `connection`, `tls_validation`, `timeout`) | The run itself is broken -- credentials, network, or a TLS pin mismatch -- and has nothing to do with sleep/hibernate support. This re-raises immediately rather than being classified. | **Depends on when it happened.** If it happened before the transition was requested, the machine never left `on`. If it happened after the transition request but the restore-to-`on` step never got to run, **the machine may still be in the requested sleep/hibernate state.** Check the CI job log for which task failed. |
| **The restore-to-`on` step itself fails, or the independent confirmation never observes `on`** | This is the one outcome this stage always treats as fatal, by design. | **The machine may be stranded in sleep or hibernate.** This is the actual risk this stage carries. |

### Recovery

If the machine is stranded asleep or hibernating (the last row above):

1. **Try the obvious first: a physical power button press or keyboard/mouse
   input**, if you are at the machine -- most sleep states wake on exactly
   that, independent of AMT.
2. **KVM console** (MeshCentral or similar): check whether it can even see
   the machine's current state. A machine in S3 sleep will typically show a
   blank/dark session; hibernation looks like a machine that is fully off
   from the KVM's perspective.
3. **Re-run `amt_power` by hand** (`state: "on"`) against the same host --
   the automated restore may simply have hit a transient network blip.
   `amt_power` is convergent for `on`, so re-running it is always safe.
4. **Physical reset** (power button held, or unplug/replug) as the last
   resort if none of the above brings the machine back. This is a known,
   accepted possibility of running this stage -- the owner has explicitly
   accepted the risk of needing to do this by hand.

### Blast radius

Nothing is destroyed. The risk here is entirely **availability**, not data:
a machine that ends up stuck asleep, deep-asleep, or hibernating until
someone (or something) wakes it. No firmware state, boot configuration, or
stored data is at risk. Compare this directly against stage 10 and stage 12,
where the risk is either permanent data loss or a machine that needs a
physical hand on it.

---

## Wake-while-powered-off (stage 12, `qualify_wake_from_off.yml`, last in the chain)

### What it does

Against one machine that must already be reporting `on`:

1. Queries the power state and confirms it is `on`; refuses otherwise.
2. Pauses for the operator to prepare an independent, physical/KVM
   confirmation of "off" -- **this pause is the only point in the entire
   stage where an independent confirmation is even possible**; it is
   skipped in CI. Read "What it is looking for" below before treating a CI
   run's result as more than it is.
3. Issues `amt_power state=off`.
4. Polls (bounded) for AMT to self-report `off`. Refuses to continue if it
   never does, but still attempts the restore in step 8.
5. A second pause, where an attended operator can type `confirmed-off` to
   record an explicit attestation that they personally, independently
   observed the machine genuinely powered down. Skipped in CI; recorded as
   `null` when skipped.
6. Issues 3 (configurable) **fresh, independent** WS-Man queries against the
   endpoint, several seconds apart, while it reports `off`, recording
   whether each one answers.
7. Issues `amt_power state=on` -- the actual "wake" -- while the machine
   still reports `off`.
8. Polls (bounded) for the machine to come back to `on`, and treats failure
   to do so as fatal.
9. Writes one evidence file with every step's result, plus an explicit note
   about what was and was not independently confirmed on this run.

### What it is looking for

Whether Intel AMT stays reachable over WS-Man, and can actually issue a
working power-on command, while the host reports itself off. **No stage
before this one had ever powered a machine off and then tried to reach
it** -- stage 4 issues `off` immediately followed by a restore, with no
attempt to talk to the endpoint in between, so it never actually tested
this. Both lab machines report `link_policy` 14 (available on Sx AC) and
`wake_on_lan_capable: true`, and one has MEBx configured "ON in S0, ME Wake
in S3, S4-5" -- but that is all *configuration*. This stage is the first
attempt at an actual *measurement*.

**Read this before trusting any CI run of this stage as strong evidence:**
there is no channel available to this playbook, running unattended in CI,
that independently confirms the host is genuinely, physically powered off.
"AMT reports off" is AMT's own self-report -- the very state machine this
stage exists to test -- not an outside observation. The only independent
signal this stage can ever obtain is a human physically watching the
machine or its KVM console during an attended run (the pauses in steps 2
and 5). A CI run (`amt_qualify_attended=false`) skips both pauses, and its
evidence file's `operator_attestation` field will read `null` every time. A
green CI run of this stage establishes "AMT self-reports off, and WS-Man
answered anyway" -- a real, useful data point -- and nothing stronger.
Do not read it as proof the host was ever actually dark.

### Expected outcome on a healthy machine

AMT self-reports `off` within the poll window. All (or most) reachability
probes answer while it reports `off` -- consistent with the lab's
`wake_on_lan_capable: true` configuration actually doing something real.
The power-on request issued while `off` is accepted, and the machine comes
back to `on`, independently confirmed.

### Failure modes

| Failure | What it means | Machine left in |
|---|---|---|
| AMT never self-reports `off` after the off request | Either the off request didn't take, or something is already wrong before this stage's real measurement even begins. | Uncertain -- likely still on, but not confirmed. The play stops here (after attempting the restore below). |
| One or more reachability probes fail to connect while the machine reports off | **This is itself a real, notable finding, not necessarily a problem.** It would mean the WS-Man plane actually went dark along with the host, contradicting what the `link_policy`/`wake_on_lan_capable` configuration implies. Recorded in `reachability_probe_failures`, does not by itself fail the stage. | Off, and this stage still attempts to wake it in the next step regardless. |
| The power-on request issued while off fails outright | Unlike sleep/hibernate, `on` is a base capability already exercised by stage 4 -- a failure here on a machine confirmed off is a real regression to investigate, not an ambiguous OS-support question. | **The machine is off and the wake attempt itself did not go through.** This is the actual stranding risk. |
| The independent post-wake confirmation never observes `on` | The wake request was sent, but the machine did not come back (or came back and then dropped again). | **The machine may be stranded off.** Explicitly accepted as a possible outcome of running this stage -- see Recovery. |

### Recovery

If the machine does not come back on:

1. **Physical power button.** The most direct recovery, and the one to try
   first if you are at the machine.
2. **KVM console.** Check whether it shows anything at all -- a machine
   genuinely at S5 will typically show no KVM session; one that is merely
   slow to respond over WS-Man (network hiccup, not actually off) may still
   show a live console.
3. **Re-issue `amt_power state=on` by hand.** If AMT itself is still
   reachable (check with `amt_power state=query`), a fresh `on` request
   costs nothing to try again -- this is exactly what stage 4 already does
   routinely.
4. **MEBx.** If the machine seems to be cycling power oddly or not
   responding to AMT at all afterwards, check the ME's own state via MEBx
   (`Ctrl+P` at boot) once you can get a boot to happen at all.
5. **Physical power cycle / unplug-and-replug AC** as the last resort. The
   owner has explicitly accepted this as a known, acceptable outcome of
   running this stage -- it is not a sign this stage should not have been
   approved.

### Blast radius

Nothing is destroyed and no data is lost. As with stage 11, the risk here is
entirely **availability**: a machine that ends up powered off and requiring
a physical hand to bring back, because the one thing this stage cannot
verify from inside CI -- that the host was ever genuinely, physically off in
the first place -- is also the one thing that makes "did the wake actually
work" a real question rather than a foregone conclusion. This is the last
stage in the chain specifically because it carries this stage's own,
previously-untested risk on top of everything proven by stages 1-11.

---

## `amt_network` — **PROPOSED, NOT IMPLEMENTED** (no stage, no playbook, no approval job)

**There is nothing to approve here.** No `qualify_network.yml` exists, no
`hardware-network-approval` job exists, and `amt_network` is not reachable from
any hardware stage. This brief exists so that whoever eventually considers
adding one has the risk written down in the same shape as the three real briefs
above, rather than having to reconstruct it.

`amt_network` is currently **mock-tested only** (Tier 2 in
[`../../docs/capability-matrix.md`](../../docs/capability-matrix.md) terms). Its
own documentation says so, and says why: see
[`../../docs/amt_network.md`](../../docs/amt_network.md).

### Why this one was held back when stages 10-12 were not

Every existing stage's worst case is recoverable **at the machine**, with a
power button, a KVM console, or in the worst case an AC unplug. Stage 12's brief
says exactly that: "the risk here is entirely availability: a machine that ends
up powered off and requiring a physical hand to bring it back."

A bad network write is not that. If the AMT management interface ends up with an
address, mask, gateway or link policy that does not work on the lab network,
**AMT is no longer reachable at all, and nothing you can do over the network
fixes it.** Recovery requires MEBx -- `Ctrl+P` at boot, on a keyboard and a
monitor physically attached to that machine -- and MEBx requires the MEBx
password, which is a separate credential from the AMT admin password these
playbooks use. That is a materially higher bar than "walk over and press the
power button", and it is the reason this is a proposal rather than a stage.

The wake-capability case is worse still in one specific way: a `LinkPolicy` with
no Sx value leaves the endpoint reachable **right now** and unreachable the next
time the host sleeps or powers down. So a stage could pass, be signed off, and
strand the machine hours later.

### What a stage would do

Sketched, not written. Against one machine that must already be reporting `on`
and reachable:

1. Read the full current state (`amt_info`), and **write it to disk before
   anything else happens** -- the same archive-first discipline stage 10 uses
   for the event log. This file is the only record of what to restore to, and
   unlike an event log it cannot be re-read afterwards if the write goes wrong.
2. Assert the recorded state is complete: `amt.network.ip_address`,
   `subnet_mask`, `default_gateway`, `dhcp_enabled` and `link_policy` all
   non-null. Refuse to continue otherwise. A restore built from a partial
   reading is worse than no restore.
3. Run the **ungated** changes only: `ping_response_enabled`,
   `rmcp_ping_response_enabled`, `hostname`, `domain_name`. None of these can
   affect reachability. Confirm each, then restore each.
4. Run a **check-mode** addressing plan (`allow_self_disconnect: true`,
   `check_mode: true`) and record the exact `Put` body it would send. This is
   the highest-value, zero-risk observation available: it proves the
   read-modify-write body this collection builds is the shape real firmware
   returned, without writing anything.
5. Optionally, and behind its own separate approval: a `link_policy` write that
   **adds** `sx_dc` while keeping `sx_ac`, then restores. Additive and
   wake-preserving, so it cannot lose reachability in any host power state.
6. **Stop there.** An actual addressing write (steps that set `ip_address` or
   `dhcp_enabled`) should be a separate stage again, approved separately, on a
   machine someone is physically sitting at.

Steps 1-4 are worth doing and carry roughly the risk of stage 1. Step 5 is a
real but bounded risk. Step 6 is the one this brief exists to make someone think
twice about.

### What it is looking for

Three things, none of which any mock can settle:

- **Does firmware accept the `Put` body this collection builds?** The read-only
  properties it strips (`MACAddress`, `LinkControl`, `SharedDynamicIP`,
  `WLANLinkProtectionLevel`) come from the vendor's *request struct*, which says
  those properties are not settable and says nothing about what firmware does if
  you send them anyway. MeshCentral sends `AMT_GeneralSettings`' read-only
  properties back and apparently succeeds. So "does a stripped body work, and
  does an unstripped one fail" is genuinely open, and the mock models the
  rejection behind a default-off knob for exactly that reason.
- **Does `PingResponseEnabled: false` take?** The vendor library marks that
  property `omitempty`, so it cannot write `false` through its own request
  struct at all. This collection emits the boolean explicitly. Whether firmware
  honours it is unmeasured.
- **Is a `LinkPolicy` write honoured at all, and does the `Get` afterwards
  report what was written?** Both lab machines report `[1, 14]`. Nothing has
  ever attempted to change it.

### Expected outcome on a healthy machine

Steps 1-4 complete with `changed: true` for each ungated write, `changed: false`
on an immediate repeat (idempotence), and a check-mode plan whose
`operation.desired.AMT_EthernetPortSettings` contains `DHCPEnabled` and none of
`MACAddress`/`LinkControl`/`SharedDynamicIP`/`WLANLinkProtectionLevel`. Step 5
reports `wake_capability_loss: false` and a `link_policy` of `[1, 14, 224]`,
then restores to `[1, 14]`.

### Failure modes

| Failure | What it means | Machine left in |
|---|---|---|
| The pre-write state read is incomplete (step 2 refuses) | Nothing has been written and nothing is at risk. Investigate the read before considering a write. | Untouched. |
| A `Put` is refused with `error_class=protocol` and a SOAP fault | Firmware rejected the body. **A real and useful finding** -- it means the delete list is wrong for this generation, in one direction or the other. The fault reason arrives in `diagnostic`. | Untouched: the refused property was not applied. |
| `error_class=unsupported_capability` after a `Put` | Firmware answered HTTP 200 and did not honour the property. Also a real finding, and the reason the confirming re-read exists. | Untouched in effect, though firmware accepted the request. |
| An ungated write applies and the restore then fails | Ping response or the hostname is left at a test value. Cosmetic and remotely fixable -- rerun the restore. | Reachable. Low consequence. |
| `indeterminate: true` on an **ungated** write | Should not happen: nothing in steps 3-5 changes addressing. If it does, something else took the connection down and the state of that write is unknown. | Unknown. Re-probe with `amt_info` at the same address before doing anything else. |
| `indeterminate: true` on a step-6 addressing write | The endpoint stopped answering at the old address. **This is what a successful address change looks like** -- and also what a failed one looks like. The two are indistinguishable from here. | **Reachable at the new address, or not reachable at all.** See Recovery. |
| A `link_policy` write lands with no Sx value | The endpoint answers now and will stop answering the next time the host leaves S0. `amt_network` refuses this without `allow_wake_capability_loss: true`, so reaching it requires having asked for it. | Reachable while on; **unreachable once asleep or off, permanently, until MEBx**. |

### Recovery

In escalating order of how much it costs:

1. **`amt_info` at the address you expected.** For an `indeterminate` addressing
   write this is the first and usually the only step needed:
   `amt_network`'s failure message names it. Retry with `until`/`retries` --
   firmware can take several seconds to answer on a new address.
2. **`amt_info` at the *old* address.** If the write did not take, the endpoint
   is still there. This is the other half of the "indistinguishable" problem
   above, and checking both is how you tell them apart.
3. **Scan the subnet for the AMT MAC.** The MAC does not change when the address
   does -- it is read-only and this module cannot write it -- so `arp`/`nmap`
   against the management VLAN will find the endpoint even if it landed on a
   DHCP address nobody predicted. Both lab machines' MACs are in the inventory.
4. **Restore from the step-1 archive.** Once the endpoint is reachable at *any*
   address, run `amt_network` with the recorded values and
   `allow_self_disconnect: true`. Expect another `indeterminate` on the way
   back.
5. **MEBx.** `Ctrl+P` at boot, on a keyboard and monitor physically attached.
   This needs the **MEBx password**, not the AMT admin password. Confirm you
   have it *before* approving any stage that could get you here. Under
   `Intel(R) AMT Configuration` -> `Network Setup` -> `TCP/IP Settings` ->
   `Wired LAN IPV4 Configuration` you can set DHCP or a static address by hand.
   `ME ON in Host Sleep States` under `Power Control` is the adjacent setting
   for the wake case -- note it governs whether the **ME** is powered, which is
   related to but not the same field as `LinkPolicy`, so it may not by itself
   undo a bad link policy.
6. **Full unprovision and re-provision.** If MEBx cannot be reached or the
   password is unknown, the endpoint has to be unprovisioned and set up again,
   which means re-recording its TLS fingerprint and updating the inventory --
   this collection pins per machine, so an unprovision invalidates the pin.

### Blast radius

Nothing is destroyed and no data is lost -- the same as stages 11 and 12. The
difference is **what recovery costs**, and it is the whole reason this section
is a proposal:

- Stage 11 and 12's worst case is a machine that needs someone to press a power
  button.
- This one's worst case is a machine that needs someone at a keyboard, in MEBx,
  with a credential the playbooks do not use, potentially followed by a full
  re-provision and a new TLS fingerprint in the inventory.

The host operating system, its disks and its data are not touched in any
scenario. Only the manageability plane is at risk -- but the manageability plane
is the thing every other stage depends on, so stranding it takes the entire
hardware qualification chain with it until someone visits the machine.

**One further consideration for whoever decides.** Both lab machines are on the
same management network and are reached by address from
`tests/hardware/inventory.yml`. A stage that changed an address would have to
update that inventory, or every subsequent stage in the same pipeline would
target an endpoint that no longer exists. That is not a hazard to the hardware,
but it is a good reason for any addressing stage to be the **last** thing in a
pipeline, the way stage 12 already is, and to run against one machine at a time.

<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Pre-flight briefs: stages 10-12

Read the relevant section below **before clicking approve** on
`hardware-log-clear-approval`, `hardware-sleep-hibernate-approval`, or
`hardware-wake-from-off-approval` in the CircleCI UI. This document is written
for the person about to touch real hardware, not for a code reviewer: it says
what can go wrong and what to do about it, not why the code is structured the
way it is (see the corresponding playbook's own header comment for that, and
[`README.md`](README.md) for the staged plan as a whole).

If you are running one of these three playbooks by hand instead of through
CI, everything below still applies -- "the approver" just means you.

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

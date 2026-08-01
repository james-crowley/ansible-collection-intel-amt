<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_alarm`

Schedule Intel AMT to wake a machine at a wall-clock time, and converge on that schedule
as desired state.

> **This module has never touched real AMT firmware.** There is no hardware
> qualification stage for it, and — unusually — there deliberately is not going to be one
> in its current form; see [Why there is no hardware stage](#why-there-is-no-hardware-stage).
> The wire protocol is decoded from the sources recorded in
> [`protocol-notes.md`](protocol-notes.md) §2.10, and the module is exercised end to end
> against the local mock WS-Man server, including the idempotence case. Neither of those
> is evidence that firmware behaves as documented. See
> [`capability-matrix.md`](capability-matrix.md).

## Purpose

AMT's alarm clock powers the machine on by itself at a time you set, with nothing
installed on the target and no agent running. That composes with the rest of this
collection into a maintenance window driven entirely from the controller: wake at 03:00,
confirm with [`amt_power`](amt_power.md), patch, shut down again.

Unlike every other mutating module here, an alarm is **state rather than an action**.
"This machine wakes at 03:00 daily" is a desired-state assertion, so `amt_alarm`
converges on it and reports `changed=false` on a second run.

Two firmware classes are involved (`protocol-notes.md` §2.10):

| Class | Role |
|---|---|
| `AMT_AlarmClockService` | The service singleton. Owns the `AddAlarm` method |
| `IPS_AlarmClockOccurrence` | One instance per configured alarm |

## Quick reference

```yaml
# Read-only: report every configured alarm and firmware's clock.
- james_crowley.intel_amt.amt_alarm:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt_alarms

# Wake for patching at 03:00 UTC every day.
- james_crowley.intel_amt.amt_alarm:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    state: present
    name: nightly-patch-window
    start_time: "2026-08-02T03:00:00Z"
    interval_minutes: 1440
    delete_on_completion: false
  delegate_to: localhost
  no_log: true
```

| Option | Default | Notes |
|---|---|---|
| `state` | `query` | `query` reads only. `present` converges. `absent` removes |
| `name` | — | Required for `present`/`absent`. Becomes the firmware instance key |
| `start_time` | — | Required for `present`. ISO-8601, **timezone mandatory** |
| `interval_minutes` | `0` | `0` = one-shot. `1440` = daily. `10080` = weekly |
| `delete_on_completion` | `true` | Whether firmware removes the alarm after it fires |
| `allow_past_start_time` | `false` | Send an already-passed time anyway. See below |

## `start_time` must carry a timezone, and that is not pedantry

`start_time: "2026-08-02T03:00:00"` is **rejected** with
`error_class: invalid_state`. Append `Z` for UTC, or an explicit offset:

```yaml
start_time: "2026-08-02T03:00:00Z"        # 03:00 UTC
start_time: "2026-08-02T03:00:00-04:00"   # 03:00 US Eastern DST = 07:00 UTC
```

The reason is that **the two existing implementations of this firmware class disagree
about what an unqualified wall-clock time means**, and the module cannot pick one without
being wrong for half its users:

- `go-wsman-messages` (Intel's own library, and this project's cited authority) converts
  the caller's time to UTC before putting it on the wire.
- MeshCentral's `meshcmd` builds the string from **local** date components and appends a
  literal `Z`. It sends local time mislabelled as UTC.

A module that guessed would silently wake one population's machines wrong by exactly the
controller's UTC offset — the single most likely defect in a feature like this, and one
that would show up as "the patch window ran at the wrong hour" rather than as an error.
So the caller says which they mean, once, in the playbook.

This collection sends **true UTC**, following `go-wsman-messages`. See
`protocol-notes.md` §2.10.5 for the citations.

### Seconds are truncated to `:00`

`03:00:47Z` is sent as `03:00:00Z`. MeshCentral's own code carries the note *"seconds
must be 00"* against its construction of this value — an undocumented firmware
constraint reported by prior art, honoured here because the cost of honouring it is a
truncated seconds field and the cost of ignoring it is an alarm firmware may refuse. The
value actually sent is in `operation.desired.start_time`, so the truncation is visible.

## Firmware has its own clock, and it may not agree with yours

AMT keeps a real-time clock independent of the host OS and of your controller. Every run
reports what it reads:

```yaml
firmware_clock:
  epoch_seconds: 1785597731
  utc: "2026-08-01T15:22:11Z"
  skew_seconds: 0                     # firmware minus controller; positive = ahead
  time_source: 0
  time_source_name: bios_rtc
  local_time_sync_enabled: 0
  local_time_sync_enabled_name: default_true
```

Read from `AMT_TimeSynchronizationService.GetLowAccuracyTimeSynch`, whose `Ta0` is Unix
epoch seconds — the same units and epoch [`amt_event_log`](amt_event_log.md) already
decodes for firmware event timestamps.

**`time_source` is the field that matters, and `0` is the interesting value.**
`go-wsman-messages` documents the property as *"Determines if RTC was set to UTC by any
configuration SW"*:

| Value | Name | What it means for you |
|---|---|---|
| `0` | `bios_rtc` | Firmware is reading the platform RTC. On a machine whose BIOS keeps **local** time, firmware's clock is **not UTC** |
| `1` | `configured` | Management software set the clock, and per that property's own description, set it to UTC |

So "AMT keeps UTC" is not a fact about AMT — it is a fact about how a particular machine
was set up. A large `skew_seconds` on a `bios_rtc` machine, close to a whole number of
hours, is the signature of exactly that: firmware holding local time while the wire
format says UTC.

**Nothing here writes firmware's clock.** `SetHighAccuracyTimeSynch` exists, writes to
flash, and has a flash-write-limit return code; and an alarm whose time had been silently
adjusted for skew would be impossible to reason about. The skew is reported so you can
act on it, never corrected for.

`local_time_sync_enabled` reports whether a local caller may move firmware's clock, i.e.
whether the host OS can shift the clock out from under a scheduled alarm. Note `0` and
`1` **both mean enabled** and differ only in default-versus-configured; that is the
vendor's own encoding and it is transcribed rather than collapsed to a boolean.

`firmware_clock` is `null` on firmware that does not implement the service. That degrades
the past-date check (below) rather than failing the run.

## Idempotence, and the identity it rests on

Deciding an alarm "already exists" needs a stable key, and this class has a good one:
**`InstanceID` is supplied by the caller**, not assigned by firmware.
`go-wsman-messages` types it as "the instance key, set by the caller of
`AMT_AlarmClockService.AddAlarm`", and both other implementations go further and make one
caller-supplied name serve as *both* `InstanceID` and the friendly `ElementName` — Intel's
own Console assigns one from the other outright.

`amt_alarm` does the same. Your `name` becomes both fields, and convergence matches on
`InstanceID` and nothing else.

> **Why not match on the friendly name.** MeshCentral does, and gets away with it only
> because it sets the two equal: its code scans `ElementName` to decide whether an alarm
> exists, then issues the delete with an `InstanceID` selector. An alarm whose two fields
> differed would be found by that code and then not removed. Keying on the actual key
> avoids creating that resource at all.

### What is compared

Three fields, all of them:

| Field | Why it is compared |
|---|---|
| `start_time` | The obvious one |
| `interval_minutes` | Comparing time alone would silently leave a one-shot alarm where a daily one was asked for |
| `delete_on_completion` | A mismatch leaves an occurrence behind after it fires, counting against the five-alarm limit |

If all three already match, `changed=false` and **nothing is sent** — not even a delete.

### Changing an alarm deletes and re-adds it

`operation.alarm_operation` reports `replace`, and the module issues `Delete` then
`AddAlarm`, in that order. **There is no update operation on this firmware class** — no
`Put` is implemented or evidenced by any source — and `AddAlarm` for an `InstanceID` that
already exists cannot succeed, since that property *is* the key. So the key has to be
freed before it can be reclaimed.

There is a consequence worth knowing: between the delete and the add, the machine has no
alarm. The window is one WS-Man round trip, and this module cannot make it zero.

### The known way idempotence could still fail

Start times are compared as **wire strings**, not as parsed instants. The module knows
exactly what text it would send, and firmware's reported text is returned verbatim.

If some firmware generation normalises what it was given into a different spelling of the
same instant — a different offset, a different precision — this module will report
`changed` on every run and re-write the alarm each time. That is deliberate: a loud wrong
answer rather than a quiet one. Nobody has run this against firmware, so if you see
perpetual `changed=true` with an unchanged playbook, compare
`operation.desired.start_time` against `operation.observed.start_time` and open an issue
with both.

## Past-dated alarms are refused, and the refusal is ours

Setting `start_time` to a time that has already passed fails with
`error_class: invalid_state`. Set `allow_past_start_time: true` to send it anyway.

**No source available to this project establishes what firmware actually does with a
past-dated alarm.** The three candidates are:

- **fires immediately** — an unscheduled reboot, from a stale playbook variable
- **rejected** — harmless
- **sits forever** — harmless but confusing

All three are consistent with everything known. MeshCentral prints *"Verify the alarm is
for a future time"* when `AddAlarm` fails, which is a hint in an error message rather
than a specification; `go-wsman-messages` defines exactly one return value for the method
(`0: Success`) so it cannot say either; no captured firmware response shows a rejection;
and Intel's Console performs no client-side check at all.

Since one of the three is a surprise reboot, the module refuses rather than finding out on
your hardware. **The refusal is this collection's judgement, not a firmware state
report** — the message says so, because otherwise an operator would go looking for a
firmware setting to change.

**The comparison is against firmware's clock, not yours.** The machine that decides
whether a time has passed is the machine holding the alarm, so a controller that thinks
the time is an hour away and firmware whose clock runs two hours fast must produce a
refusal. Where firmware will not report its clock, the controller's is used and the
message says explicitly that the comparison may be wrong by the RTC's drift.

An alarm that **already matches** desired state is never refused for being past — a
recurring alarm whose last `StartTime` has gone by still satisfies the assertion, so
re-running the play reports `ok` rather than failing.

## Firmware holds at most five alarms

`AddAlarm` is documented to fail once five `IPS_AlarmClockOccurrence` instances exist.
`amt_alarm` checks the count first and refuses with `error_class: invalid_state`, naming
the limit, its source, and the alarms already present.

The pre-check exists because a `ReturnValue` past that limit would have **no name in any
source** — `go-wsman-messages` defines only `0: Success` for this method — so an opaque
number from firmware is worse than a client-side refusal that can explain itself. If a
firmware generation turns out to allow more than five, this refuses a legal operation;
that is why the message lists what it counted.

Replacing an alarm at the limit is allowed: a replace frees the key before claiming it,
so it cannot exceed the cap.

## Reading configured alarms, and why this is not an `amt_info` subset

`state: query` — the default — is the read path. It reports every configured alarm,
firmware's clock, and the service instance, and always reports `changed=false`.

This is deliberately **not** a new `gather_subset` value on
[`amt_info`](amt_info.md), for two reasons:

1. **It would change existing plays.** `amt_info`'s subset resolution adds *every* valid
   subset when a caller supplies no positive entry (see `resolve_subsets` rule 6 in
   `plugins/module_utils/hardware.py`), so `gather_subset: ['all']` or
   `gather_subset: ['!memory']` in a play written today would silently start reading
   `IPS_AlarmClockOccurrence` and paying the round trips for it. The default,
   `['config']`, would be unaffected — but the two forms above are the ones people
   actually write.
2. **An alarm is configuration this collection writes, not inventory.** Every existing
   subset reads a `CIM_` physical-asset class that describes the machine. An alarm
   describes what somebody asked the machine to do. And `amt_alarm` already has to read
   the alarm list in order to converge, so the read path exists in the module that owns
   the identity semantics — which is where a caller comparing `instance_id` values wants
   it.

## `service` is reported and deliberately not trusted

```yaml
service:
  element_name: "Intel(r) AMT Alarm Clock Service"
  next_alarm_time: null
  alarm_interval: null
```

`next_alarm_time` and `alarm_interval` come from `AMT_AlarmClockService`'s
`NextAMTAlarmTime` and `AMTAlarmClockInterval`. **Both are absent from the only captured
firmware response for this class**, even though `go-wsman-messages`' own struct declares
them — so they may not exist on your firmware either, and `null` here means "firmware did
not report it", not "no alarm is set".

`alarms` is the authoritative reading. It comes from enumerating the occurrence class,
which is evidenced.

## Check mode

Fully supported, and the same planner decides both the preview and the real run — so a
check-mode `changed` and a real `changed` cannot disagree.

All **reads** still happen in check mode, including firmware's clock. That means the
past-date refusal and the occurrence-limit refusal **fire in check mode too**, which is
the point: `--check` is for previewing a correct play, not for discovering the play is
wrong only once it runs for real. (Same reasoning [`amt_log_clear`](amt_log_clear.md)
applies to its confirmation gate.)

No `AddAlarm` and no `Delete` is sent.

## Error classes

| `error_class` | When |
|---|---|
| `invalid_state` | `start_time` has no timezone, is unparseable, is past-dated without `allow_past_start_time`, or the five-occurrence limit is reached |
| `unsupported_capability` | Firmware does not implement `IPS_AlarmClockOccurrence` |
| `remote_operation` | `AddAlarm` returned a non-zero `ReturnValue`. The raw integer is reported and **not named** — no source names any value but `0` |
| `protocol` | A `Delete` for an alarm that does not exist, malformed SOAP, and the usual transport-level faults |
| `connection`, `tls_validation`, `authentication`, `timeout` | As every other module in this collection |

Note that `start_time` parsing happens **before the first WS-Man request**, so the most
likely mistake a caller can make costs no round trips and does not even authenticate.

## Why there is no hardware stage

Two reasons, and the first is not solved by waiting longer:

1. **Proving an alarm fires requires wall-clock time to pass.** The shortest honest test
   is "set an alarm two minutes out, then poll" — the slowest stage in the suite by a wide
   margin, and one whose failure mode ("it has not fired *yet*") is indistinguishable from
   a real failure without waiting longer still.
2. **It only means anything with the machine powered off**, since a running machine cannot
   tell "fired immediately" from "sat forever". That needs AMT to answer WS-Man while
   reporting itself off, which hardware stage 12 established on **`amt-lab-01` only**. A
   stage built on that could only ever run on one machine, and a green result there would
   say nothing about the other.

What does exist:

- **Mock coverage driven through the real client**, over a real TCP socket:
  `tests/unit/mock_servers/test_wsman_server.py`'s `TestRealClientAlarmClock` and
  `TestRealClientFirmwareClock`, including an assertion on the **outgoing element tags**,
  because the `AddAlarm` body spans three namespaces and a client that flattened them
  would still satisfy a fake shaped to its own output.
- **An integration target**, `tests/integration/targets/amt_alarm`, driving the real
  module against the mock — including setting the same alarm twice and asserting the
  second run reports `changed=false`.

**None of that is evidence about firmware.** It is evidence that this collection sends
what its sources say to send, and reads back what it sent.

## See also

- [`protocol-notes.md`](protocol-notes.md) §2.10 — the wire format, every value table,
  and the citations for all of the above
- [`amt_power`](amt_power.md) — confirming the machine actually came up
- [`amt_event_log`](amt_event_log.md) — the same firmware epoch, decoded for events
- [`capability-matrix.md`](capability-matrix.md) — what has and has not touched hardware

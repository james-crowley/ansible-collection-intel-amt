<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_event_log`

Read the Intel AMT event log.

> **Exercised against real firmware for the first time on 2026-07-31, on one machine.**
> Hardware qualification stage 9 (`qualify_event_log.yml`) read `amt-lab-01`, AMT
> 16.1.30 (CircleCI pipeline 208, job `hardware-tests` 2568), and passed: all 205
> records read to completion, zero decode errors, the 21-byte record layout confirmed.
> `amt-lab-02` (AMT 19.0.5) has never run this stage — see
> [`capability-matrix.md`](capability-matrix.md) Tier 3 for the full result and Tier 4
> for what a second machine would still add. The wire protocol and the record layout
> were, and still are, also decoded per the sources recorded in
> [`protocol-notes.md`](protocol-notes.md) §2.8 — a captured real-firmware response
> fixture set and MeshCentral. Every record is returned with its **raw bytes** alongside
> the decoded fields regardless: a decode is not automatically trustworthy everywhere
> merely because it decoded cleanly on one machine.

## Purpose

This is the only place that records **why** an unattended bare-metal install failed when
the failure happened outside the host operating system. Boot failures, agent-watchdog
expiry, and power events the OS never saw — because it was not running when they
happened — are recorded here and nowhere else this collection can reach.

Reads `AMT_MessageLog` over WS-Man: `PositionToFirstRecord` to establish an iteration,
then `GetRecords` repeatedly, feeding each response's `IterationIdentifier` into the next
request, until firmware sets `NoMoreRecords` or `max_records` is reached.

Strictly read-only. `changed` is always `false`.

### The iteration is followed to completion

One `GetRecords` call is not the log. Firmware may return fewer records than asked for,
which is what `NoMoreRecords` exists to disambiguate, so a client that fetches one batch
and stops silently returns a prefix. This module follows the iteration until firmware says
it is finished, and when it stops for any other reason it says so:

| `stop_reason` | Meaning | `complete` | `truncated` |
|---|---|---|---|
| `no_more_records` | Firmware set `NoMoreRecords`. This is the whole log. | `true` | `false` |
| `no_record_exists` | `PositionToFirstRecord` reported an empty log. | `true` | `false` |
| `no_record_exists_in_log` | `GetRecords` reported an empty log, or the end of one. | `true` | `false` |
| `max_records` | The `max_records` bound was hit while records remained. | `false` | **`true`** |
| `invalid_record_pointed` | Firmware rejected the iteration identifier mid-read. | `false` | `false` |
| `no_iteration_identifier` | Firmware returned no identifier to continue from. | `false` | `false` |
| `iteration_stalled` | The identifier stopped advancing while more records were claimed. | `false` | `false` |

The last three end the read abnormally. Records already collected are still returned, but
`complete` is `false` so a caller is never told a partial read was the whole log. The
`iteration_stalled` case exists so a firmware that keeps handing back the same position
cannot spin a play forever.

**Truncation is never silent.** Compare `records_read` against `total_records` (which comes
from `CurrentNumberOfRecords` on the log itself, not from counting what arrived) to tell a
bounded read from a short log.

### Raw bytes are always returned

Every record carries `raw_base64`, `raw_hex` and `raw_length` next to the decoded fields —
including records that could not be decoded at all. The decode is derived from two
third-party sources rather than from firmware this collection has talked to, so if it is
wrong on some generation the raw bytes are the only thing that makes that diagnosable
rather than merely wrong.

A record shorter than the documented 21 bytes yields a `decode_error` and **no** decoded
fields. A partial struct read at the wrong offsets produces values that look real, which is
worse than no decode.

### What is decoded, and what is deliberately not

`EventSeverity` and `Entity` are named, from tables both sources carry identically.
Descriptions are derived for `EventSensorType` 6, 15, 18, 30, 32, 35 and 37.

`EventType`, `EventOffset`, `EventSourceType`, `DeviceAddress` and `SensorNumber` are
returned as **raw integers only**. No value table for any of them is established by any
source available here. MeshCentral does carry a 12-entry event-trap source list, but real
firmware records show `EventSourceType == 104`, far outside it, so that list plainly does
not describe this field and is not applied.

`description` is `null` when this collection has no sourced way to name the event —
including for `EventSensorType == 15` at a non-zero `EventOffset` with the `0xAA` marker,
the one place the two sources actively contradict each other. `null` reads unambiguously
as "this collection cannot name this event"; a placeholder string would invite an operator
to read it as a firmware statement. See [`protocol-notes.md`](protocol-notes.md) §2.8,
"Deliberately not decoded".

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `max_records` | `int` | `390` | no | — |
| `severity` | `list` of `str` | — | no | `unspecified`, `monitor`, `information`, `ok`, `non_critical`, `critical`, `non_recoverable` |
| `host` | `str` | — | yes | — |
| `port` | `int` | (16993 if `use_tls` else 16992) | no | — |
| `username` | `str` | `admin` | no | — |
| `password` | `str` (`no_log`) | — | yes | — |
| `use_tls` | `bool` | `true` | no | — |
| `allow_insecure_transport` | `bool` | `false` | no | — |
| `validate_certs` | `bool` | `true` | no | — |
| `ca_path` | `path` | — | no | — |
| `tls_fingerprint` | `str` | — | no | — |
| `timeout` | `int` | `30` | no | — |
| `connect_timeout` | `int` | `10` | no | — |

Verified against `argument_spec()` in `plugins/modules/amt_event_log.py` and the rendered
`ansible-doc` output.

### `max_records`

The default `390` is **one whole log** on the firmware generation the protocol fixtures
came from — that firmware reports `MaxNumberOfRecords` as `390` — so the default does not
truncate there. It is also the per-call cap both sources use for `MaxReadRecords`. It exists
so a generation with a larger log cannot hang a play.

### `severity` filters by name, not by threshold

The firmware severity values are a **sparse lookup**, not an ordered scale:

| 0 | 1 | 2 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|
| `unspecified` | `monitor` | `information` | `ok` | `non_critical` | `critical` | `non_recoverable` |

`ok` (4) is numerically greater than `information` (2) without being worse, so "severity at
or above X" is not a meaningful operation on them and is not offered.

**A filter drops records it cannot classify.** A record whose severity byte is outside the
table (rendered `unknown(<raw>)`) or which failed to decode at all does not match any
filter name, so it is removed. `filtered_out` reports how many records the filter removed,
so that loss is visible rather than vanishing. If you are diagnosing a failure, prefer
reading unfiltered and filtering in Jinja, where the dropped records are still in hand.

## Return values

| Key | Type | Meaning |
|---|---|---|
| `records` | `list` of `dict` | The decoded records, in firmware's order. AMT normally stores the log **newest first**, so `records[0]` is usually the most recent event — compare `timestamp` rather than relying on position. |
| `total_records` | `int` | `CurrentNumberOfRecords` from the log. `null` if firmware did not report it. |
| `records_read` | `int` | How many records were read from firmware, before `severity` was applied. |
| `filtered_out` | `int` | How many read records the `severity` filter removed. |
| `truncated` | `bool` | `true` when `max_records` stopped the read while records remained. |
| `complete` | `bool` | `true` when the iteration ended the way firmware said it should. |
| `stop_reason` | `str` | See the table above. |
| `batches` | `int` | How many `GetRecords` calls were issued. |
| `log` | `dict` | The `AMT_MessageLog` container properties — capacity, record size, overwrite policy, capabilities. |
| `operation` | `dict` | The `intel-amt-operation/v1` receipt. `changed` is always `false`; `previous` and `desired` are always `null`; `observed` carries the container properties. |

### Per-record fields

| Field | Type | Notes |
|---|---|---|
| `raw_base64` | `str` | Exactly as firmware sent it. **Always present**, even when decoding failed. |
| `raw_hex` | `str` | The decoded bytes as lowercase hex. `null` only when the base64 itself was invalid. |
| `raw_length` | `int` | Normally `21`. |
| `decode_error` | `str` | `null` on a clean decode. When set, every field below is `null`. |
| `timestamp` | `int` | Raw `UINT32`, always reported alongside the rendered form. |
| `timestamp_utc` | `str` | ISO-8601 UTC, interpreting `timestamp` as Unix epoch seconds. `null` for the sentinels `0` and `4294967295`, neither of which is a real time. |
| `event_severity` / `event_severity_text` | `int` / `str` | Raw byte and its name, or `unknown(<raw>)`. |
| `entity` / `entity_text` | `int` / `str` | Raw byte and its name, e.g. `BIOS`, `Intel(r) ME`, or `unknown(<raw>)`. |
| `entity_instance` | `int` | Raw byte. |
| `event_sensor_type` | `int` | Raw byte. Selects how `description` is derived. |
| `event_type`, `event_offset`, `event_source_type`, `device_address`, `sensor_number` | `int` | **Raw only** — no value table is established for these. |
| `event_data` | `list` of `int` | The eight trailing `EventData` bytes. |
| `description` | `str` | Human-readable, or `null` where unsourced. |

**Timestamps are Unix epoch seconds in UTC.** MeshCentral instead adds the *management
station's* local timezone offset before rendering, which makes the displayed instant depend
on where the reader is sitting; that is a property of the reader, not the event, and is not
reproduced here. `timestamp` is always returned raw so a caller who disagrees still has the
number.

## Check mode

**Fully supported.** A read is a read: check mode runs the identical code path and returns
the identical result. Nothing is skipped and nothing is stubbed.

## Failure modes

| `error_class` | Meaning here |
|---|---|
| `connection` | TCP/DNS failure. |
| `tls_validation` | Certificate/fingerprint problem, or plaintext without acknowledgement. |
| `authentication` | Digest credentials rejected. |
| `unsupported_capability` | `AMT_MessageLog` is absent (neither `Get` nor `Enumerate` returned it), or `PositionToFirstRecord` reported `ReturnValue=1` (Not Supported). This firmware has no reachable event log. |
| `timeout` | Read timed out. |
| `protocol` | Malformed SOAP or unexpected response shape. |
| `remote_operation` | `GetRecords` returned a `ReturnValue` that is not an ordinary outcome — e.g. `1` (Not Supported). |

**An empty log is a success, not a failure.** Firmware signals it with a non-zero
`ReturnValue` (`2` from `PositionToFirstRecord`, `3` from `GetRecords`), and both are
treated as ordinary outcomes: the module returns `records: []`, `total_records: 0`,
`complete: true`. "The class is absent" (`unsupported_capability`) and "the log is empty"
(success) are different findings and stay distinguishable — one is a firmware capability
gap, the other is just a quiet machine.

A record that fails to decode never fails the read. It comes back with `decode_error` set
and its raw bytes attached, so one unreadable record does not cost you the other 389.

## Limitations

- **Verified against real firmware on one machine, one generation.** Stage 9
  (2026-07-31, `amt-lab-01`, AMT 16.1.30) passed; `amt-lab-02` (AMT 19.0.5) has never
  run this stage. See [`capability-matrix.md`](capability-matrix.md) Tier 3.
- The record layout, the method names, the `ReturnValue` maps and every value table are
  third-party-sourced. Each fact names its source in
  [`protocol-notes.md`](protocol-notes.md) §2.8, and anything still inferred says so — in
  particular, **the returned `IterationIdentifier`'s arithmetic is not established** and is
  treated as an opaque token fed back verbatim.
- Five byte fields (`event_type`, `event_offset`, `event_source_type`, `device_address`,
  `sensor_number`) are reported raw with no interpretation, because no source establishes
  one.
- `description` is `null` for sensor types this collection cannot name from a source,
  including every case where its two sources disagree. Absence of a description is not
  absence of an event — the raw bytes are always there.
- Only `GetRecords` (plural) is used. `GetRecord` (singular) and `PositionAtRecord` exist on
  the class and are not implemented; neither adds anything for a full read.
- Reading is not atomic. A log that firmware is actively writing to may shift between
  batches, and nothing in the protocol offers a snapshot. `FreezeLog` exists on the class
  and is deliberately **not** used — it could leave an endpoint refusing log writes.
- `delegate_to: localhost` does not protect against inventory fan-out. This module is
  read-only, so a fan-out costs round trips rather than damage, but constrain the **play**
  with `serial: 1` if that matters — `serial` cannot be set on a task.

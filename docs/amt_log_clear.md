<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_log_clear`

Clear the Intel AMT event log.

> **Exercised against real firmware on both lab generations.** Hardware qualification
> stage 10 (`qualify_log_clear.yml`) first ran, irreversibly, against `amt-lab-01`, AMT
> 16.1.30 (CircleCI pipeline 208, job `hardware-log-clear` 2574, 2026-07-31), and
> passed: 205 records archived to disk first, `ClearLog` reported `records_before: 205`
> / `records_after: 0`, and an independent re-read afterwards confirmed the log empty
> rather than trusting `ClearLog`'s own return value. Stage 10 has since also run
> against `amt-lab-02`, AMT 19.0.5 (CircleCI workflow
> `b7865873-40b2-43b5-825f-be5ebba704fc`), and reproduced the identical sequence on its
> own 110 records: `records_before: 110` / `records_after: 0`, with an independent
> re-read confirming empty. That second run's independent `amt_event_log` re-read,
> taken *immediately* after the clear, reported `empty_slots: 0` — see "A read after a
> clear is trustworthy" below for what that does and does not say about padding. See
> [`capability-matrix.md`](capability-matrix.md)
> Tier 3 for the full result. The wire protocol is, and was, also decoded per the
> sources recorded in [`protocol-notes.md`](protocol-notes.md) §2.8 — a captured
> real-firmware response fixture set and MeshCentral.

## Purpose

Invokes `AMT_MessageLog.ClearLog` over WS-Man. The method takes no parameters.

**This is irreversible.** The records are gone; there is no undo and no firmware-side
archive.

### What the risk actually is

Clearing a log **cannot strand the management path** — reachability is unaffected, and
nothing about power, boot or redirection changes. So unlike the other mutating modules in
this collection, the danger here is not lost access. It is **destroyed forensic evidence**.

The AMT event log is the only record of why an unattended install failed when the failure
happened outside the host operating system. Clearing it before reading it discards the one
artefact that explains the failure, and no amount of retrying the install brings it back.
Read with [`amt_event_log`](amt_event_log.md) first — the `EXAMPLES` in
`plugins/modules/amt_log_clear.py` show the archive-then-clear sequence.

## The confirmation gate

The module refuses to do anything at all unless `confirm_destructive: true` is set
explicitly. This mirrors `amt_baremetal_install_confirm_destructive` in the
`amt_baremetal_install` role (`roles/amt_baremetal_install/tasks/validate.yml`).

An unconfirmed invocation **does not touch the endpoint**. The gate is checked before the
first WS-Man request, so nothing is read, nothing is authenticated, and no connection is
opened. It fails with `error_class=invalid_state`.

**The gate refuses in check mode too.** `--check` is for previewing a correctly-configured
play, not for discovering that the confirmation is missing only once the play runs for
real. To preview safely, set `confirm_destructive: true` **and** run with `--check`: that
reads the record count and reports what would be cleared, sending nothing.

Set the option at the point of use — for example
`-e amt_confirm_clear=true` fed into `confirm_destructive` — rather than in a checked-in
defaults file, so the confirmation stays a deliberate act rather than a value someone
committed once.

### A note on `error_class=invalid_state`

This is a **client-side refusal, not a firmware state report**. Everything user-visible in
this collection carries one of the nine stable classes in
`plugins/module_utils/errors.py`, and `invalid_state` ("the operation is not legal from the
current state") is the closest of them to "this invocation is not legal as configured".
A caller branching on `error_class` should read `invalid_state` from this module as either
the confirmation gate or a genuine firmware state refusal, and distinguish them by whether
the message mentions `confirm_destructive` — it always does for the gate.

## Convergence

Clearing an already-empty log is a **no-op**: if `CurrentNumberOfRecords` reads `0`
beforehand, nothing is sent and `changed` is `false`. There is nothing to destroy, and
reporting a change for a no-op would be wrong.

If firmware does not report the count at all (`null`, as opposed to `0`), the clear **is**
attempted. "Firmware did not say" is not "already clean", and treating the two the same way
would silently skip a real clear on a generation that omits the property.

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `confirm_destructive` | `bool` | `false` | no (but must be `true` to do anything) | — |
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

Verified against `argument_spec()` in `plugins/modules/amt_log_clear.py` and the rendered
`ansible-doc` output.

## Return values

| Key | Type | Meaning |
|---|---|---|
| `records_before` | `int` | `CurrentNumberOfRecords` read **before** anything was sent — how many records were about to be destroyed. `null` if firmware did not report it. |
| `records_after` | `int` | `CurrentNumberOfRecords` re-read **after** `ClearLog` returned. Expected `0`. `null` in check mode and when no clear was sent. |
| `cleared` | `bool` | `true` only when `ClearLog` was actually invoked and accepted. |
| `return_value` | `int` | AMT's `ReturnValue` from `ClearLog`. Only present when a request was sent, and then always `0` — a non-zero value raises `remote_operation` instead. |
| `log` | `dict` | The `AMT_MessageLog` container properties as read before the clear. `capabilities` containing `6` (`ClearLogSupported`) is firmware stating this method is implemented. |
| `operation` | `dict` | The `intel-amt-operation/v1` receipt: `previous` and `observed` carry `current_number_of_records`, `desired` is always `0`. |

### The "after" count is observed, not assumed

`ReturnValue == 0` means AMT **accepted** the request, not that the log is empty. So
`records_after` comes from a fresh `Get AMT_MessageLog` issued after the method returned,
not from assuming the mutation did what it said. If a firmware ever accepts `ClearLog` and
leaves records behind, `records_after` is where that shows up.

### A read after a clear is trustworthy — this was tested, not assumed

**Post-clear reads are reliable, and this module carries no warning to the contrary
because there is nothing to warn about.** It is worth stating positively, because the
opposite was suspected: after the first hardware clear, a subsequent
[`amt_event_log`](amt_event_log.md) read on the same machine returned far more entries
than firmware's own record count, and the leading explanation was that `GetRecords` was
serving records `ClearLog` had deleted.

**It was measured, and it is false.** Not one of the records archived before the clear
appeared anywhere in the read that followed it. The extra entries were **all-zero
padding** — firmware returning a zero-filled 21-byte entry for each record slot the clear
had freed, carrying no timestamp, no entity and no event data, and nothing whatsoever
that was in the log before the clear. Nothing deleted is being served. The over-count was
a defect in `amt_event_log`, which counted those empty slots as records; it is fixed in
0.7.1 and reported there as `empty_slots`. The full accounting, and why the arithmetic
made the wrong explanation look convincing, is in
[`capability-matrix.md`](capability-matrix.md) under "The hypothesis that `GetRecords`
serves records `ClearLog` deleted — tested and refuted".

Two practical consequences:

- **`records_after` was never exposed to that defect.** It is read from
  `CurrentNumberOfRecords` on the log container, not by counting returned records, and
  firmware's counter was correct throughout — it reported `18` while the read returned
  `223` entries. The verification this module performs is the one that was right.
- **A non-zero `empty_slots` on the next `amt_event_log` read is expected, not a
  failure.** A clear that frees 205 slots can leave 205 slots to pad with. It means the
  slots are empty, which is what a clear is for.

## Check mode

**Fully supported, and it really reads.** `CurrentNumberOfRecords` is fetched so the preview
reports how many records *would* be destroyed, and `ClearLog` is never invoked.

A check-mode run that reported `changed` without reading anything would make check mode
useless for exactly the decision it is needed for — "how much evidence am I about to
throw away?". The `amt_log_clear` integration target asserts both halves: that the count is
real, and that the records survive the preview.

Note the gate still applies: `--check` without `confirm_destructive: true` fails rather than
previewing.

## Failure modes

| `error_class` | Meaning here |
|---|---|
| `connection` | TCP/DNS failure. |
| `tls_validation` | Certificate/fingerprint problem, or plaintext without acknowledgement. |
| `authentication` | Digest credentials rejected. |
| `invalid_state` | **The confirmation gate refused** (message mentions `confirm_destructive`), or firmware refused the operation from its current state. |
| `unsupported_capability` | `AMT_MessageLog` is absent — neither `Get` nor `Enumerate` returned it. This firmware has no reachable event log to clear. |
| `timeout` | If raised *after* `ClearLog` was transmitted, carries `indeterminate: true` — the clear may have applied. Re-read with `amt_event_log` rather than retrying. |
| `protocol` | Malformed SOAP or unexpected response shape. |
| `remote_operation` | **AMT returned a non-zero `ReturnValue` from `ClearLog`.** |

### A non-zero `ReturnValue` is a failure, never a warning

If AMT accepts the request but reports a non-zero `ReturnValue`, this module fails with
`error_class=remote_operation` and the value in `return_value`. It is not demoted to a
warning and the task does not report success.

This matters more than it looks. An operator told "cleared" about a log that was not
cleared will either go looking for evidence they think is gone, or stop looking for
evidence that is still there. Both are wrong, and both are worse than a loud failure. The
prior art (`parmstro/intel_amt`) demotes exactly this case to a warning and returns
success; that is the specific behaviour this module exists not to repeat.

## Limitations

- **Verified against real firmware on both lab generations.** Stage 10 passed against
  `amt-lab-01` (AMT 16.1.30, 2026-07-31, pipeline 208) and again against `amt-lab-02`
  (AMT 19.0.5, workflow `b7865873-40b2-43b5-825f-be5ebba704fc`), including the
  independent re-read that confirmed the log empty on each. Any generation outside
  these two remains untested — two generations is repeatability, not a compatibility
  guarantee. See [`capability-matrix.md`](capability-matrix.md) Tier 3.
- The method name, its empty parameter list, and the container properties the receipt is
  built from are third-party-sourced. Each fact names its source in
  [`protocol-notes.md`](protocol-notes.md) §2.8. Firmware's own `Capabilities` array
  advertising `6` (`ClearLogSupported`) is the strongest available evidence that the method
  exists, and it is reported in `log.capabilities` so an operator can check it before
  clearing.
- **`IPS_ProvisioningRecordLog.ClearLog` is deliberately not implemented.** It was
  investigated. MeshCentral wraps it, but with a `_method_dummy` parameter whose type,
  permitted values and purpose no available source explains; there is no response fixture
  for the class anywhere in the captures this collection relies on; and
  `go-wsman-messages` does not implement it at all. Whether it exists on modern firmware
  is therefore unestablished, and its single parameter cannot be filled in without
  guessing. It is also a *different* log — provisioning/audit history, not platform events
  — so it is not a substitute for `AMT_MessageLog.ClearLog` and its absence costs the
  motivating use case nothing. `AMT_AuditLog.ClearLog` and `CIM_RecordLog.ClearLog` are out
  of scope for the same reasons.
- There is no partial clear and no per-record delete. `ClearLog` empties the log or does
  nothing; `Capabilities` advertising `3` (`DeleteRecordSupported`) is reported raw but no
  delete path is implemented.
- The clear is not transactional with a read. A record written between the archive read and
  the clear is destroyed unread. Nothing in the protocol offers a snapshot, and `FreezeLog`
  — which exists on the class — is deliberately not used, since it could leave an endpoint
  refusing log writes.
- `delegate_to: localhost` does not protect against inventory fan-out: a play over ten
  hosts clears ten event logs. Constrain the **play** with `serial: 1` and an explicit
  single-target selection — `serial` cannot be set on a task.

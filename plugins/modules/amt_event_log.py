#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_event_log
short_description: Read the Intel AMT event log
description:
  - >-
    Reads the Intel AMT event log over WS-Man, via C(AMT_MessageLog) --
    C(PositionToFirstRecord) to establish an iteration, then C(GetRecords)
    repeatedly until firmware reports no more records.
  - >-
    This is the only place that records B(why) an unattended bare-metal install
    failed when the failure happened outside the host operating system: boot
    failures, agent-watchdog expiry, and power events the OS never saw because it
    was not running.
  - >-
    Strictly read-only. C(changed) is always V(false) and check mode performs the
    identical read -- a read is a read.
  - >-
    Records arrive as base64-encoded 21-byte binary structs. This module returns
    B(both) the decoded fields and the raw bytes (RV(records[].raw_base64) and
    RV(records[].raw_hex)) for every record, including records it could not
    decode. The decode is derived from third-party sources rather than from
    firmware this collection has talked to, so the raw bytes are what make a
    wrong decode diagnosable.
  - >-
    B(Neither this module nor M(james_crowley.intel_amt.amt_log_clear) has been
    exercised against real firmware.) No hardware qualification stage covers
    them. The wire protocol and the record layout are decoded per the sources
    recorded in C(docs/protocol-notes.md) §2.8 -- a real-firmware response fixture
    set and MeshCentral -- and not per any endpoint this collection has read.
version_added: 0.3.0
author:
  - Jim Crowley (@james-crowley)
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
options:
  max_records:
    description:
      - >-
        Upper bound on how many records to read in total, across every
        C(GetRecords) batch. Exists so a large log cannot hang a play.
      - >-
        The default is V(390), which is one whole log on the firmware generation
        the protocol fixtures came from (that firmware reports
        C(MaxNumberOfRecords) as V(390)), so the default does not truncate there.
      - >-
        When the bound is hit while records remain, RV(truncated) is V(true) and
        RV(stop_reason) is V(max_records). Truncation is never silent.
    type: int
    default: 390
  severity:
    description:
      - >-
        Keep only records whose decoded severity is in this list. Omit to return
        every record.
      - >-
        Filtering is by B(name), not by numeric threshold. The firmware severity
        values are a sparse lookup (0, 1, 2, 4, 8, 16, 32), not an ordered scale
        -- V(ok) is numerically greater than V(information) without being worse --
        so "severity at or above X" is not a meaningful operation on them.
      - >-
        A record whose severity byte is outside the known table, or which failed
        to decode at all, is B(dropped) by any filter. RV(filtered_out) reports
        how many records the filter removed so that loss is visible.
    type: list
    elements: str
    choices:
      - unspecified
      - monitor
      - information
      - ok
      - non_critical
      - critical
      - non_recoverable
seealso:
  - module: james_crowley.intel_amt.amt_log_clear
  - module: james_crowley.intel_amt.amt_info
attributes:
  check_mode:
    description: >-
      Fully supported. The module only reads, so check mode runs the identical
      code path and returns the identical result.
    support: full
    details:
      - >-
        Fully supported. The module only reads, so check mode runs the identical
        code path and returns the identical result.
  diff_mode:
    description: Not supported. There is nothing to diff -- this module never changes anything.
    support: none
    details:
      - Not supported. There is nothing to diff -- this module never changes anything.
"""

EXAMPLES = r"""
- name: Read the whole AMT event log
  james_crowley.intel_amt.amt_event_log:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: event_log

- name: Show why the unattended install failed, newest first
  ansible.builtin.debug:
    msg: "{{ event_log.records | map(attribute='description') | select('string') | list }}"

- name: Read only the records that indicate something went wrong
  james_crowley.intel_amt.amt_event_log:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    severity:
      - non_critical
      - critical
      - non_recoverable
    max_records: 50
  delegate_to: localhost
  no_log: true
  register: event_log_bad

- name: Fail the play if the log was truncated before the interesting records
  ansible.builtin.assert:
    that:
      - not event_log_bad.truncated
    fail_msg: >-
      Only {{ event_log_bad.records_read }} of {{ event_log_bad.total_records }} records were
      read; raise max_records before drawing conclusions from this log.
"""

RETURN = r"""
records:
  description:
    - >-
      The decoded records, in the order firmware returned them. Note that AMT
      normally stores the event log B(newest first), so RV(records[0]) is usually the
      most recent event -- compare RV(records[].timestamp) rather than relying on
      position.
    - >-
      Zero-filled empty record slots are excluded and counted in RV(empty_slots)
      instead. A record whose timestamp is V(0) but whose other fields are populated
      is B(not) a slot and is returned -- a zero clock on a real event is a firmware
      RTC fault worth seeing, and it renders RV(records[].timestamp_utc) as V(null)
      rather than being discarded.
  type: list
  elements: dict
  returned: always
  contains:
    raw_base64:
      description: The record exactly as firmware sent it, base64. Always present, even when decoding failed.
      type: str
    raw_hex:
      description: The decoded record bytes as lowercase hex. V(null) only when the base64 itself was invalid.
      type: str
    raw_length:
      description: Length of the raw record in bytes. Normally V(21).
      type: int
    decode_error:
      description: >-
        V(null) on a clean decode. Otherwise a description of why this record could not
        be decoded, in which case every decoded field below is V(null) -- a partial
        struct read at wrong offsets produces values that look real.
      type: str
    timestamp:
      description: Raw C(UINT32) timestamp from the record, always reported alongside the rendered form.
      type: int
    timestamp_utc:
      description: >-
        RV(records[].timestamp) rendered as an ISO-8601 UTC instant, interpreting it as
        Unix epoch seconds. V(null) when the raw value is V(0) or V(4294967295), neither
        of which is a real time.
      type: str
    device_address:
      description: Raw C(DeviceAddress) byte. Reported raw -- no value table for it is established.
      type: int
    event_sensor_type:
      description: Raw C(EventSensorType) byte. Selects how RV(records[].description) is derived.
      type: int
    event_type:
      description: Raw C(EventType) byte. Reported raw -- no value table for it is established.
      type: int
    event_offset:
      description: Raw C(EventOffset) byte. Reported raw; it selects a sub-table for sensor type V(15).
      type: int
    event_source_type:
      description: >-
        Raw C(EventSourceType) byte. Reported raw. MeshCentral carries a 12-entry
        event-trap source list, but real firmware records show V(104) here, well outside
        it, so that list is B(not) applied.
      type: int
    event_severity:
      description: Raw C(EventSeverity) byte.
      type: int
    event_severity_text:
      description: >-
        One of V(unspecified), V(monitor), V(information), V(ok), V(non_critical),
        V(critical), V(non_recoverable), or V(unknown(<raw>)) for a value outside the table.
      type: str
    sensor_number:
      description: Raw C(SensorNumber) byte. Reported raw -- no value table for it is established.
      type: int
    entity:
      description: Raw C(Entity) byte -- the system entity that raised the event.
      type: int
    entity_text:
      description: RV(records[].entity) named, e.g. V(BIOS) or V(Intel(r) ME). V(unknown(<raw>)) outside the table.
      type: str
    entity_instance:
      description: Raw C(EntityInstance) byte.
      type: int
    event_data:
      description: The eight trailing C(EventData) bytes, as integers.
      type: list
      elements: int
    description:
      description: >-
        A human-readable description, or V(null) when this collection has no sourced way
        to describe the event. V(null) is deliberate: a placeholder string would read as
        a firmware statement rather than as our own ignorance.
      type: str
total_records:
  description: >-
    C(AMT_MessageLog.CurrentNumberOfRecords) -- how many records firmware says the log
    holds. Compare against RV(records_read) to tell a truncated read from a short log.
    V(null) if firmware did not report it.
  type: int
  returned: always
records_read:
  description:
    - >-
      How many records were actually read from firmware, before RV(filtered_out) was
      applied. Always equal to the length of RV(records).
    - >-
      Zero-filled empty slots are B(not) counted here and are not present in
      RV(records) -- see RV(empty_slots). Before that exclusion existed this count
      could exceed RV(total_records), which made the RV(records_read) versus
      RV(total_records) comparison this module documents unusable on a log that had
      been cleared and was refilling.
  type: int
  returned: always
empty_slots:
  description:
    - >-
      How many all-zero 21-byte C(RecordArray) entries firmware returned that this
      read excluded from RV(records). V(0) on a log firmware did not pad.
    - >-
      Firmware pads its C(GetRecords) response with zero-filled entries for record
      slots a previous C(ClearLog) freed. They are empty slots, not records: no
      timestamp, no entity, no severity, no event data. One real AMT 16.1.30 endpoint
      returned 223 entries for an 18-record log, 205 of them identical all-zero
      padding.
    - >-
      Reported rather than merely dropped, so the padding is visible. A non-zero
      value is normal for a recently cleared log and is B(not) a fault. Notably it is
      also not evidence that deleted records are being served -- the padding entries
      are all zero and contain nothing that was in the log before the clear.
  type: int
  returned: always
  version_added: 0.8.0
filtered_out:
  description: How many read records the O(severity) filter removed. V(0) when O(severity) is unset.
  type: int
  returned: always
truncated:
  description: >-
    V(true) when O(max_records) stopped the read while more records remained. A caller
    must not treat a truncated result as the whole log.
  type: bool
  returned: always
complete:
  description: >-
    V(true) when the iteration ended the way firmware said it should. V(false) for a
    truncated read or an abnormal end -- see RV(stop_reason).
  type: bool
  returned: always
stop_reason:
  description: >-
    Why the iteration stopped. V(no_more_records) (firmware set C(NoMoreRecords)),
    V(no_record_exists)/V(no_record_exists_in_log) (empty log), V(max_records)
    (O(max_records) bound reached), V(invalid_record_pointed),
    V(no_iteration_identifier), or V(iteration_stalled).
  type: str
  returned: always
batches:
  description: How many C(GetRecords) calls were issued. V(0) when the log was empty.
  type: int
  returned: always
log:
  description: The C(AMT_MessageLog) container properties -- the log itself, not its records.
  type: dict
  returned: always
  contains:
    current_number_of_records:
      description: Same value as RV(total_records).
      type: int
    max_number_of_records:
      description: C(MaxNumberOfRecords) -- the log's capacity.
      type: int
    max_record_size:
      description: C(MaxRecordSize) in bytes. Expected to be V(21).
      type: int
    element_name:
      description: C(ElementName), e.g. V(Intel(r) AMT:MessageLog 1).
      type: str
    is_frozen:
      description: C(IsFrozen) -- whether firmware is currently refusing modifications to the log.
      type: bool
    log_state:
      description: Raw C(LogState) integer.
      type: int
    overwrite_policy:
      description: Raw C(OverwritePolicy) integer -- what firmware does when the log fills.
      type: int
    capabilities:
      description: >-
        Raw C(Capabilities) integers. V(6) is C(ClearLogSupported), i.e. firmware saying
        M(james_crowley.intel_amt.amt_log_clear) is implemented.
      type: list
      elements: int
operation:
  description: >-
    The C(intel-amt-operation/v1) receipt for this read, in the same nested shape every
    module in this collection returns it under.
  type: dict
  returned: always
  contains:
    schema:
      description: Always V(intel-amt-operation/v1).
      type: str
    action:
      description: Always V(amt_event_log.read).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Always V(false) -- this module never changes anything.
      type: bool
    previous:
      description: Always V(null). Nothing was changed, so there is no prior state to record.
      type: dict
    desired:
      description: Always V(null). Nothing was requested.
      type: dict
    observed:
      description: The C(AMT_MessageLog) container properties, same shape as RV(log).
      type: dict
    tls_peer_fingerprint:
      description: SHA-256 fingerprint of the TLS leaf certificate observed, or V(null) over plaintext.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

import dataclasses

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import message_log
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import HAS_REQUESTS, REQUESTS_IMPORT_ERROR, WsmanClient


def _connection_argument_spec() -> dict[str, dict]:
    return {
        "host": {"type": "str", "required": True},
        "port": {"type": "int"},
        "username": {"type": "str", "default": "admin"},
        "password": {"type": "str", "required": True, "no_log": True},
        "use_tls": {"type": "bool", "default": True},
        "allow_insecure_transport": {"type": "bool", "default": False},
        "validate_certs": {"type": "bool", "default": True},
        "ca_path": {"type": "path"},
        "tls_fingerprint": {"type": "str"},
        "timeout": {"type": "int", "default": 30},
        "connect_timeout": {"type": "int", "default": 10},
    }


def argument_spec() -> dict[str, dict]:
    spec = _connection_argument_spec()
    spec["max_records"] = {"type": "int", "default": message_log.DEFAULT_MAX_RECORDS}
    spec["severity"] = {"type": "list", "elements": "str", "choices": list(message_log.SEVERITY_CHOICES)}
    return spec


def build_wsman_client(params: dict) -> WsmanClient:
    """Construct a :class:`WsmanClient` from the module's connection parameters."""
    return WsmanClient.from_connection_options(
        host=params["host"],
        port=params["port"],
        username=params["username"],
        password=params["password"],
        use_tls=params["use_tls"],
        allow_insecure_transport=params["allow_insecure_transport"],
        validate_certs=params["validate_certs"],
        ca_path=params["ca_path"],
        tls_fingerprint=params["tls_fingerprint"],
        timeout=params["timeout"],
        connect_timeout=params["connect_timeout"],
    )


def build_result(read: message_log.MessageLogRead, severities: list[str] | None, endpoint: str, tls_fingerprint: str | None) -> dict:
    """Shape a :class:`message_log.MessageLogRead` into the module's return value.

    Kept separate from :func:`main` so the truncation/filter accounting is
    directly unit-testable without an ``AnsibleModule`` or a transport.
    """
    kept = message_log.filter_by_severity(read.records, severities)
    log_properties = dataclasses.asdict(read.properties)
    receipt = OperationReceipt(
        action="amt_event_log.read",
        endpoint=endpoint,
        changed=False,
        observed=log_properties,
        tls_peer_fingerprint=tls_fingerprint,
    )
    return {
        # Never anything but False. A read is not a change, and check mode runs
        # this identical path.
        "changed": False,
        "records": [dataclasses.asdict(record) for record in kept],
        "total_records": read.total_records,
        "records_read": len(read.records),
        "empty_slots": read.empty_slots,
        "filtered_out": len(read.records) - len(kept),
        "truncated": read.truncated,
        "complete": read.complete,
        "stop_reason": read.stop_reason,
        "batches": read.batches,
        "log": log_properties,
        "operation": receipt.to_dict(),
    }


def main() -> None:
    module = AnsibleModule(argument_spec=argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    max_records = module.params["max_records"]
    if max_records < 1:
        module.fail_json(msg=f"max_records must be at least 1, got {max_records}")

    try:
        wsman = build_wsman_client(module.params)
        read = message_log.read_records(wsman, max_records=max_records)
        peer_cert = wsman.last_peer_certificate
        fingerprint = peer_cert.sha256_fingerprint if peer_cert else None
        result = build_result(read, module.params["severity"], wsman.endpoint, fingerprint)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return

    module.exit_json(**result)


if __name__ == "__main__":
    main()

#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_alarm
short_description: Manage Intel AMT scheduled-wake alarms (the AMT alarm clock)
description:
  - >-
    Reads and converges Intel AMT alarm-clock occurrences -- wall-clock times at which the
    firmware powers the machine on by itself, with nothing installed on the target. An alarm
    is desired state, so a second run with the same arguments reports C(changed=false).
  - >-
    Alarms are held as C(IPS_AlarmClockOccurrence) instances and created through
    C(AMT_AlarmClockService.AddAlarm). O(name) becomes both the instance key
    (C(InstanceID)) and the friendly name (C(ElementName)); the key is caller-supplied, which
    is what makes convergence possible at all.
  - >-
    O(start_time) B(must carry a timezone). This module refuses to guess, because the two
    existing implementations of this firmware class disagree about what an unqualified
    wall-clock time means -- one converts to UTC, the other sends local time labelled as UTC
    -- and guessing wrong wakes the machine at the wrong hour. See
    C(docs/amt_alarm.md).
  - >-
    A past-dated O(start_time) is refused unless O(allow_past_start_time=true). B(That
    refusal is this module's, not firmware's):  no source available to this collection
    establishes whether firmware fires such an alarm immediately, rejects it, or holds it
    forever. The comparison is made against firmware's own real-time clock where firmware
    will report it, not against the controller's.
  - >-
    With O(state=query) (the default) the module is read-only and always reports
    C(changed=false).
version_added: 0.8.0
author:
  - Jim Crowley (@james-crowley)
options:
  state:
    description:
      - V(query) reads and reports every configured alarm, plus firmware's clock, and changes
        nothing.
      - V(present) converges the alarm named by O(name) to O(start_time), O(interval_minutes)
        and O(delete_on_completion), creating it if absent and replacing it if any of the
        three differs.
      - V(absent) removes the alarm named by O(name) if it exists.
    type: str
    choices: [query, present, absent]
    default: query
  name:
    description:
      - Identity of the alarm. Becomes both C(InstanceID) (the instance key) and
        C(ElementName) on the firmware instance, matching what Intel's own tooling does.
      - Required for O(state=present) and O(state=absent); ignored for O(state=query).
      - >-
        Two alarms cannot share a name. Setting an alarm whose name already exists with
        different settings replaces it -- the existing instance is deleted and a new one
        added, because the firmware class has no update operation.
    type: str
  start_time:
    description:
      - When the machine should wake, as an ISO-8601 timestamp B(including a timezone):
        V(2026-08-01T03:00:00Z) or V(2026-08-01T03:00:00-04:00).
      - >-
        A value with no timezone is B(rejected) with C(error_class=invalid_state). This is
        deliberate; see the module description.
      - >-
        Seconds are truncated to V(00). Prior art carries an explicit note that firmware
        requires whole minutes, and the value actually sent is reported in the receipt.
      - Required for O(state=present).
    type: str
  interval_minutes:
    description:
      - >-
        Recurrence interval in B(minutes). V(0) (the default) is a one-shot alarm. V(1440) is
        daily; V(10080) is weekly.
      - >-
        Named for its unit on purpose. The firmware property is an ISO-8601 duration
        (C(P1DT0H0M)) and both vendor implementations model it as an integer count of
        minutes, but a bare C(interval: 24) is ambiguous in a way a wake-up time cannot
        afford. The encoded duration is reported in the receipt.
    type: int
    default: 0
  delete_on_completion:
    description:
      - >-
        Whether firmware should delete the occurrence once it has fired. V(true) (the
        default) leaves no residue after a one-shot wake.
      - >-
        Compared during convergence, so changing only this value still replaces the alarm.
      - >-
        Setting this V(false) on a one-shot alarm (O(interval_minutes=0)) leaves an instance
        behind that counts against firmware's occurrence limit. Alarms are capped at five.
    type: bool
    default: true
  allow_past_start_time:
    description:
      - >-
        Send an alarm whose O(start_time) has already passed. Off by default: the module
        refuses such an alarm with C(error_class=invalid_state) rather than discovering
        experimentally what firmware does with it.
      - >-
        The refusal is a client-side judgement, not a firmware state report. Set this when you
        have a reason to believe your firmware handles a past-dated alarm the way you want it
        to, and expect to find out.
    type: bool
    default: false
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
attributes:
  check_mode:
    description: >-
      Supported. Reports exactly the operation a real run would perform -- the same planner
      decides both -- and sends no C(AddAlarm) and no C(Delete). All reads, including
      firmware's clock, still happen, so the past-date and occurrence-limit refusals fire in
      check mode too.
    support: full
  diff_mode:
    description: >-
      Returns the alarm as it was before the action and the alarm that was requested, in the
      operation receipt.
    support: full
"""

EXAMPLES = r"""
- name: Report every configured alarm and firmware's clock
  james_crowley.intel_amt.amt_alarm:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt_alarms

- name: Wake for patching at 03:00 UTC every day
  james_crowley.intel_amt.amt_alarm:
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

- name: One-shot wake at 22:00 US Eastern, deleted by firmware once it fires
  james_crowley.intel_amt.amt_alarm:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    state: present
    name: one-shot-maintenance
    start_time: "2026-08-02T22:00:00-04:00"
  delegate_to: localhost
  no_log: true

- name: Remove the nightly wake
  james_crowley.intel_amt.amt_alarm:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    state: absent
    name: nightly-patch-window
  delegate_to: localhost
  no_log: true

# A maintenance window driven entirely from the controller.
- name: Schedule the wake, then confirm the machine came up
  block:
    - name: Arm the wake
      james_crowley.intel_amt.amt_alarm:
        host: 10.0.0.5
        username: admin
        password: "{{ vaulted_amt_password }}"
        tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
        state: present
        name: window-open
        start_time: "{{ maintenance_start_utc }}"
      delegate_to: localhost
      no_log: true

    - name: Report the power state once the alarm should have fired
      james_crowley.intel_amt.amt_power:
        host: 10.0.0.5
        username: admin
        password: "{{ vaulted_amt_password }}"
        tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
        state: query
      delegate_to: localhost
      no_log: true
      register: post_wake_power
"""

RETURN = r"""
changed:
  description: >-
    V(true) only when O(state) was V(present) or V(absent), the requested state differed from
    what firmware held, and (outside check mode) C(AddAlarm) and/or C(Delete) was sent.
    Always V(false) for O(state=query).
  type: bool
  returned: always
alarms:
  description: >-
    Every configured alarm, as observed B(after) any action this run performed. Empty when
    firmware holds none.
  type: list
  elements: dict
  returned: always
  contains:
    instance_id:
      description: The instance key. This is what O(name) becomes, and the only field
        convergence matches on.
      type: str
    element_name:
      description: The friendly name. Set equal to C(instance_id) by this module; a
        differing value means the alarm was created by something else.
      type: str
    start_time:
      description: >-
        The wake time exactly as firmware reported it, not reparsed or reformatted. Normally
        V(YYYY-MM-DDTHH:MM:SSZ). V(null) if firmware reported nothing readable.
      type: str
    interval:
      description: The raw ISO-8601 recurrence duration firmware reported, e.g.
        V(P1DT0H0M). V(null) if absent.
      type: str
    interval_minutes:
      description: >-
        RV(alarms[].interval) decoded to whole minutes. V(0) means a one-shot alarm;
        V(null) means firmware reported a duration this collection could not parse, which is
        B(not) the same finding.
      type: int
    delete_on_completion:
      description: Whether firmware will delete the occurrence after it fires. V(null) if
        firmware did not report it.
      type: bool
alarm:
  description: >-
    The single alarm named by O(name), as observed after any action, or V(null) when it does
    not exist or O(name) was not given. Same shape as one RV(alarms) element.
  type: dict
  returned: always
firmware_clock:
  description: >-
    What firmware's own real-time clock reads, from
    C(AMT_TimeSynchronizationService.GetLowAccuracyTimeSynch), plus its time-source
    configuration. V(null) when firmware does not implement that service -- which degrades
    the past-date check to the controller's clock rather than failing the run.
  type: dict
  returned: always
  contains:
    epoch_seconds:
      description: The raw C(Ta0) value -- Unix epoch seconds.
      type: int
    utc:
      description: RV(firmware_clock.epoch_seconds) rendered as an ISO-8601 UTC string.
      type: str
    skew_seconds:
      description: >-
        Firmware's clock minus the controller's, in seconds. Positive means firmware is
        B(ahead). Reported, never corrected for -- an alarm silently adjusted for skew would
        be impossible to reason about.
      type: int
    time_source:
      description: >-
        Raw C(TimeSource): whether the RTC was set by configuration software. V(0) means
        firmware is reading the platform RTC, which on a machine whose BIOS keeps local time
        is B(not) UTC.
      type: int
    time_source_name:
      description: RV(firmware_clock.time_source) decoded -- V(bios_rtc), V(configured), or
        V(unknown(N)).
      type: str
    local_time_sync_enabled:
      description: Raw C(LocalTimeSyncEnabled) -- whether a local caller may move firmware's
        clock underneath a scheduled alarm.
      type: int
    local_time_sync_enabled_name:
      description: RV(firmware_clock.local_time_sync_enabled) decoded -- V(default_true),
        V(configured_true), V(false), or V(unknown(N)).
      type: str
service:
  description: >-
    Firmware's own summary from C(AMT_AlarmClockService), containing C(element_name),
    C(next_alarm_time) and C(alarm_interval). B(All three may be V(null)):  the vendor's
    captured response for this class omits C(NextAMTAlarmTime) and C(AMTAlarmClockInterval)
    entirely, so nothing here is depended on -- RV(alarms) is the authoritative reading.
  type: dict
  returned: always
operation:
  description: >-
    The C(intel-amt-operation/v1) receipt for this action, in the same nested shape every
    module in this collection returns it under.
  type: dict
  returned: always
  contains:
    schema:
      description: Always V(intel-amt-operation/v1).
      type: str
    action:
      description: Always V(amt_alarm).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Mirrors the top-level RV(changed).
      type: bool
    previous:
      description: The alarm of this name as it was before the action, or V(null).
      type: dict
    desired:
      description: >-
        The alarm that was requested, including C(start_time) and C(interval) exactly as
        they would go on the wire -- so a truncated seconds field or an encoded duration is
        visible. V(null) for O(state=query) and O(state=absent).
      type: dict
    observed:
      description: The alarm of this name as observed after the action, or V(null).
      type: dict
    alarm_operation:
      description: >-
        What convergence decided: V(none), V(add), V(replace) (delete then add, because the
        firmware class has no update operation), or V(delete).
      type: str
    tls_peer_fingerprint:
      description: >-
        SHA-256 fingerprint of the TLS leaf certificate observed during this operation, or
        V(null) over plaintext.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import alarm as alarm_util
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt, optional_str
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.tls import resolve_port
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    HAS_REQUESTS,
    REQUESTS_IMPORT_ERROR,
    WsmanClient,
)


def argument_spec() -> dict:
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
        "state": {"type": "str", "choices": ["query", "present", "absent"], "default": "query"},
        "name": {"type": "str"},
        "start_time": {"type": "str"},
        "interval_minutes": {"type": "int", "default": 0},
        "delete_on_completion": {"type": "bool", "default": True},
        "allow_past_start_time": {"type": "bool", "default": False},
    }


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


def _service_dict(instance: dict) -> dict:
    """Project ``AMT_AlarmClockService`` onto the three fields worth reporting.

    Every one may be ``None``: see this module's RETURN note and
    ``alarm.get_service``. The two alarm-summary properties are reported verbatim
    rather than decoded, because no captured response has ever shown either
    populated, so there is nothing to establish a format from.
    """
    return {
        "element_name": optional_str(instance.get("ElementName")),
        "next_alarm_time": optional_str(instance.get("NextAMTAlarmTime")),
        "alarm_interval": optional_str(instance.get("AMTAlarmClockInterval")),
    }


def main() -> None:
    module = AnsibleModule(
        argument_spec=argument_spec(),
        supports_check_mode=True,
        required_if=[
            ("state", "present", ("name", "start_time")),
            ("state", "absent", ("name",)),
        ],
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    params = module.params
    endpoint = f"{params['host']}:{resolve_port(port=params['port'], use_tls=params['use_tls'])}"
    state = params["state"]
    name = params["name"]

    client = build_wsman_client(params)
    try:
        # start_time is parsed before the first request, so a value with no
        # timezone -- the most likely mistake this module can be made -- is refused
        # without touching the endpoint at all.
        start_time = alarm_util.parse_start_time(params["start_time"]) if params["start_time"] else None

        service = alarm_util.get_service(client)
        alarms = alarm_util.list_alarms(client)
        firmware_clock = alarm_util.read_firmware_clock(client)
        previous = alarm_util.find_alarm(alarms, name) if name else None

        if state == "query":
            plan = alarm_util.AlarmPlan(operation=alarm_util.OPERATION_NONE, changed=False, existing=previous, desired=None)
        else:
            plan = alarm_util.plan(
                state=state,
                name=name,
                alarms=alarms,
                start_time=start_time,
                interval_minutes=params["interval_minutes"],
                delete_on_completion=params["delete_on_completion"],
                firmware_clock=firmware_clock,
                allow_past_start_time=params["allow_past_start_time"],
            )

        if plan.changed and not module.check_mode:
            # Delete first, then add. There is no Put on IPS_AlarmClockOccurrence in
            # any source, and re-adding an existing InstanceID has no documented
            # behaviour -- so a replace has to free the key before claiming it.
            if plan.sends_delete:
                alarm_util.delete_alarm(client, name)
            if plan.sends_add:
                alarm_util.add_alarm(
                    client,
                    name=name,
                    start_time=start_time,
                    interval_minutes=params["interval_minutes"],
                    delete_on_completion=params["delete_on_completion"],
                )
            # Re-read rather than assuming AddAlarm's ReturnValue tells the truth,
            # the same rule client.py applies to power transitions: a mutation is
            # requested, never confirmed, by ReturnValue == 0.
            alarms = alarm_util.list_alarms(client)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return
    finally:
        client.close()

    observed = alarm_util.find_alarm(alarms, name) if name else None
    receipt = OperationReceipt(
        action="amt_alarm",
        endpoint=endpoint,
        changed=plan.changed,
        previous=previous.to_dict() if previous else None,
        desired=plan.desired,
        observed=observed.to_dict() if observed else None,
        tls_peer_fingerprint=(client.last_peer_certificate.sha256_fingerprint if client.last_peer_certificate else None),
        extra={"alarm_operation": plan.operation},
    )
    module.exit_json(
        changed=plan.changed,
        alarms=[configured.to_dict() for configured in alarms],
        alarm=observed.to_dict() if observed else None,
        firmware_clock=firmware_clock.to_dict() if firmware_clock else None,
        service=_service_dict(service),
        operation=receipt.to_dict(),
    )


if __name__ == "__main__":
    main()

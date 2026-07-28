# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""One-time boot device selection: the five-step sequence from docs/protocol-notes.md s2.5.

This is deliberately its own module rather than folded into a shared client, because it is the
single most intricate and highest-consequence operation in this collection: a machine left in a
bad boot configuration needs physical or KVM recovery to fix. Everything here follows three rules
enforced structurally, not just by convention:

1. **Order is the contract.** The five WS-Man calls in :func:`arm_one_time_boot` run in exactly
   the sequence documented in protocol-notes s2.5 -- clear the boot order before mutating
   ``AMT_BootSettingData``, set the one-shot role, then set the boot order again. Reordering these
   (e.g. setting the boot source before clearing it) is a real firmware-compatibility regression,
   not a style choice.
2. **Never mutate on an assumption.** :func:`discover_and_validate` enumerates
   ``CIM_BootSourceSetting`` and ``AMT_BootCapabilities`` and fails closed with
   ``unsupported_capability`` *before* step 1 (the first ``Get``) if the requested target is
   unsupported or ambiguous. No Put or Invoke happens on a guess.
3. **One-shot, never auto re-armed.** :func:`arm_one_time_boot` requires a truthy ``action_token``
   on every call, including check-mode calls. There is no internal retry-with-rearm path: a caller
   that hits an indeterminate failure (see ``errors.TimeoutError_``) must decide to try again with a
   fresh token, not have this module decide for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    InvalidStateError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    EndpointReference,
    WsmanClient,
)

#: The single ``CIM_BootConfigSetting`` instance Intel AMT exposes. Named literally in
#: protocol-notes s2.5 steps 2, 4, and 5 -- there is exactly one, it is never enumerated for.
BOOT_CONFIG_INSTANCE_ID = "Intel(r) AMT: Boot Configuration 0"

#: CIM_BootConfigSetting.ChangeBootOrder / CIM_BootService.SetBootConfigRole role value for
#: "IsNextSingleUse" -- the one-shot role this module always requests. Protocol-notes s2.5 step 4.
BOOT_CONFIG_ROLE_NEXT_SINGLE_USE = 1

#: The six boot targets this module supports, in the order the amt_boot module documents them.
BOOT_TARGETS: tuple[str, ...] = ("pxe", "hdd", "cd", "bios", "ider_floppy", "ider_cdrom")

#: pxe/hdd/cd name a CIM_BootSourceSetting instance for step 5's ChangeBootOrder EPR.
#: bios/ider_floppy/ider_cdrom pass a null Source in step 5 instead -- see BootPlan.
_BOOT_SOURCE_INSTANCE_ID: dict[str, str] = {
    "pxe": "Intel(r) AMT: Force PXE Boot",
    "hdd": "Intel(r) AMT: Force Hard-drive Boot",
    "cd": "Intel(r) AMT: Force CD/DVD Boot",
}

#: AMT_BootCapabilities boolean field that must be true before mutating towards a given target.
#: All of these field names are verified: they appear in a recorded firmware response fixture,
#: pkg/wsman/wsmantesting/responses/amt/boot/capabilities/get.xml in
#: device-management-toolkit/go-wsman-messages. The full field table is in
#: docs/protocol-notes.md s2.5.
#:
#: A field absent from a given firmware's response must be read as "not supported", never
#: defaulted to true. That way a name that is wrong on some future generation fails closed --
#: the module refuses the boot -- rather than arming a boot the firmware cannot perform.
_CAPABILITY_FIELD_BY_TARGET: dict[str, str] = {
    "pxe": "ForcePXEBoot",
    "hdd": "ForceHardDriveBoot",
    "cd": "ForceCDorDVDBoot",
    "bios": "BIOSSetup",
    "ider_floppy": "IDER",
    "ider_cdrom": "IDER",
}

#: Fields that must be deleted from the read AMT_BootSettingData instance before Put -- newer
#: firmware rejects the Put if these are echoed back. protocol-notes s2.5 step 3.
DELETE_BEFORE_PUT_FIELDS: tuple[str, ...] = (
    "WinREBootEnabled",
    "UEFILocalPBABootEnabled",
    "UEFIHTTPSBootEnabled",
    "SecureBootControlEnabled",
    "BootguardStatus",
    "OptionsCleared",
    "BIOSLastStatus",
    "UefiBootParametersArray",
)

#: Fields zeroed (not deleted) when present, before Put. protocol-notes s2.5 step 3.
ZERO_IF_PRESENT_FIELDS: tuple[str, ...] = ("UefiBootNumberOfParams",)

#: Fields set to False only if the read instance already has them -- newer firmware may not
#: expose these properties at all, and adding them where absent could itself be rejected.
OPTIONAL_ERASE_FIELDS: tuple[str, ...] = ("SecureErase", "PlatformErase")


def _truthy(value: Any) -> bool:
    """Interpret a WS-Man response value (often the string ``"true"``/``"false"``) as a bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1")
    return bool(value)


@dataclass(frozen=True, slots=True)
class BootPlan:
    """The concrete WS-Man shape for one boot target, derived from :data:`BOOT_TARGETS`.

    ``boot_source_instance_id`` is the ``CIM_BootSourceSetting`` InstanceID passed as step 5's
    ChangeBootOrder EPR, or ``None`` when step 5 must pass a null Source instead (IDE-R and BIOS
    setup targets). ``use_ider``/``boot_source_instance_id`` are validated as mutually exclusive
    in :meth:`__post_init__` -- not because the six-value ``device`` choice can produce that
    combination through the module, but because this is the highest-consequence operation in the
    collection and the invariant deserves an unconditional runtime check, not just a closed enum.
    """

    target: str
    boot_source_instance_id: str | None
    use_ider: bool
    ider_boot_device: int
    bios_setup: bool

    def __post_init__(self) -> None:
        if self.use_ider and self.boot_source_instance_id is not None:
            raise InvalidStateError(
                "IDE-R boot and a native boot source are mutually exclusive: naming "
                f"{self.boot_source_instance_id!r} in step 5's ChangeBootOrder would override IDE-R "
                "redirection (protocol-notes.md s2.5). Select only one.",
                operation="build_boot_plan",
            )


#: One entry per BOOT_TARGETS value. Kept as a plain data table (allow-list), not branching code,
#: so the six-target -> WS-Man-shape mapping is auditable at a glance.
_TARGET_SPECS: dict[str, dict[str, Any]] = {
    "pxe": {"boot_source_instance_id": _BOOT_SOURCE_INSTANCE_ID["pxe"], "use_ider": False, "ider_boot_device": 0, "bios_setup": False},
    "hdd": {"boot_source_instance_id": _BOOT_SOURCE_INSTANCE_ID["hdd"], "use_ider": False, "ider_boot_device": 0, "bios_setup": False},
    "cd": {"boot_source_instance_id": _BOOT_SOURCE_INSTANCE_ID["cd"], "use_ider": False, "ider_boot_device": 0, "bios_setup": False},
    # BIOS setup entry is not a CIM_BootSourceSetting selection at all -- BIOSSetup=true in the
    # Put is what causes firmware to break into setup, so step 5 passes a null Source exactly as
    # it does for IDE-R. protocol-notes.md s2.5 does not spell this specific case out; treating it
    # the same as "no boot source selection" is this collection's own extension of the documented
    # rule and is called out in the PR description for review.
    "bios": {"boot_source_instance_id": None, "use_ider": False, "ider_boot_device": 0, "bios_setup": True},
    "ider_floppy": {"boot_source_instance_id": None, "use_ider": True, "ider_boot_device": 0, "bios_setup": False},
    "ider_cdrom": {"boot_source_instance_id": None, "use_ider": True, "ider_boot_device": 1, "bios_setup": False},
}


def build_boot_plan(target: str) -> BootPlan:
    """Build the :class:`BootPlan` for one of :data:`BOOT_TARGETS`.

    Raises :class:`ValueError` for an unknown target -- a pure programming error, not a firmware
    capability question, so it deliberately is not one of the AmtError classes.
    """
    if target not in _TARGET_SPECS:
        raise ValueError(f"unknown boot target {target!r}; expected one of {sorted(_TARGET_SPECS)}")
    return BootPlan(target=target, **_TARGET_SPECS[target])


def discover_and_validate(client: WsmanClient, target: str) -> None:
    """Enumerate CIM_BootSourceSetting and AMT_BootCapabilities and fail closed before any mutation.

    protocol-notes.md s2.5: "Enumerate CIM_BootSourceSetting and confirm exactly one instance
    matches the requested target before doing any of this. Fail with unsupported_capability if
    absent or ambiguous. Enumerate AMT_BootCapabilities to confirm ... support rather than
    assuming." Both enumerations run, and both must pass, before :func:`arm_one_time_boot` issues
    its first Get.
    """
    capabilities_instances = client.enumerate("AMT_BootCapabilities")
    if len(capabilities_instances) != 1:
        raise UnsupportedCapabilityError(
            f"expected exactly one AMT_BootCapabilities instance, found {len(capabilities_instances)}",
            operation="discover_boot_capabilities",
        )
    capabilities = capabilities_instances[0]
    capability_field = _CAPABILITY_FIELD_BY_TARGET[target]
    if not _truthy(capabilities.get(capability_field)):
        raise UnsupportedCapabilityError(
            f"firmware does not advertise {capability_field}=true in AMT_BootCapabilities for device={target!r}",
            operation="discover_boot_capabilities",
        )

    expected_instance_id = _BOOT_SOURCE_INSTANCE_ID.get(target)
    if expected_instance_id is None:
        # bios / ider_floppy / ider_cdrom never name a CIM_BootSourceSetting -- nothing further
        # to confirm here; the capability check above already covered them.
        return

    sources = client.enumerate("CIM_BootSourceSetting")
    matches = [source for source in sources if source.get("InstanceID") == expected_instance_id]
    if len(matches) != 1:
        raise UnsupportedCapabilityError(
            f"expected exactly one CIM_BootSourceSetting with InstanceID={expected_instance_id!r} for device={target!r}, found {len(matches)}",
            operation="discover_boot_source",
        )


def _build_put_properties(read_instance: dict[str, Any], plan: BootPlan) -> dict[str, Any]:
    """Build the mutated AMT_BootSettingData Put body from the read instance and a :class:`BootPlan`.

    Data-driven per protocol-notes.md s2.5 step 3: delete the deny-listed fields, zero the
    zero-if-present fields, then apply the fixed field values plus the plan-derived ones. This is
    a read-modify-write of the *entire* instance, not a partial patch -- the fields not mentioned
    in step 3 (InstanceID, ElementName, ...) are carried through unchanged from ``read_instance``.
    """
    mutated: dict[str, Any] = dict(read_instance)

    for field_name in DELETE_BEFORE_PUT_FIELDS:
        mutated.pop(field_name, None)

    for field_name in ZERO_IF_PRESENT_FIELDS:
        if field_name in mutated:
            mutated[field_name] = 0

    mutated["ConfigurationDataReset"] = False
    mutated["BIOSPause"] = False
    mutated["EnforceSecureBoot"] = False
    mutated["BIOSSetup"] = plan.bios_setup
    mutated["BootMediaIndex"] = 0
    mutated["FirmwareVerbosity"] = 0
    mutated["ForcedProgressEvents"] = False
    mutated["IDERBootDevice"] = plan.ider_boot_device
    mutated["LockKeyboard"] = False
    mutated["LockPowerButton"] = False
    mutated["LockResetButton"] = False
    mutated["LockSleepButton"] = False
    mutated["ReflashBIOS"] = False
    mutated["UseIDER"] = plan.use_ider
    mutated["UseSOL"] = plan.use_ider  # MeshCmd sets this equal to UseIDER; protocol-notes s2.5.
    mutated["UseSafeMode"] = False
    mutated["UserPasswordBypass"] = False

    for field_name in OPTIONAL_ERASE_FIELDS:
        if field_name in read_instance:
            mutated[field_name] = False

    return mutated


@dataclass(frozen=True, slots=True)
class BootArmResult:
    """Everything :func:`arm_one_time_boot` observed and applied, for the module's receipt."""

    plan: BootPlan
    previous: dict[str, Any]
    put_properties: dict[str, Any]
    observed: dict[str, Any]
    boot_config_selector: dict[str, str]
    boot_source_selector: dict[str, str] | None
    mutated: bool


def arm_one_time_boot(
    client: WsmanClient,
    target: str,
    *,
    action_token: str | None,
    check_mode: bool = False,
) -> BootArmResult:
    """Run the five-step sequence from protocol-notes.md s2.5 in exactly that order.

    1. Get AMT_BootSettingData
    2. CIM_BootConfigSetting.ChangeBootOrder(null)
    3. Put AMT_BootSettingData (mutated)
    4. CIM_BootService.SetBootConfigRole(Role=1)
    5. CIM_BootConfigSetting.ChangeBootOrder(<EPR or null>)

    ``action_token`` is required and checked for truthiness on every call, including check-mode
    calls -- it is the explicit, per-call acknowledgement gate for a one-shot, high-consequence
    operation, not something a dry run should be allowed to skip. There is deliberately no
    internal re-arm path: a caller must supply a fresh token for every attempt.

    Discovery (:func:`discover_and_validate`) and step 1 (Get) both happen before check_mode is
    consulted, since neither mutates anything; step 2 onward is skipped entirely in check mode.
    """
    if not action_token:
        raise InvalidStateError(
            "arming a one-time boot requires a truthy action_token; this is a one-shot, "
            "high-consequence operation and this module never arms it implicitly and never "
            "re-arms automatically after an uncertain reset or a later re-probe. Supply a fresh "
            "action_token for every attempt.",
            operation="arm_one_time_boot",
        )

    plan = build_boot_plan(target)

    # Discovery before mutation: fail unsupported_capability before the first WS-Man call that
    # could possibly mutate anything.
    discover_and_validate(client, target)

    # Step 1: Get AMT_BootSettingData. Safe in check mode -- it is a read.
    previous = client.get("AMT_BootSettingData")
    put_properties = _build_put_properties(previous, plan)

    boot_config_selector = {"InstanceID": BOOT_CONFIG_INSTANCE_ID}
    boot_source_selector = {"InstanceID": plan.boot_source_instance_id} if plan.boot_source_instance_id is not None else None

    if check_mode:
        return BootArmResult(
            plan=plan,
            previous=previous,
            put_properties=put_properties,
            observed=previous,
            boot_config_selector=boot_config_selector,
            boot_source_selector=boot_source_selector,
            mutated=False,
        )

    # Step 2: CIM_BootConfigSetting.ChangeBootOrder(null) -- clear first. client.invoke() already
    # raises RemoteOperationError on a non-zero ReturnValue, which aborts this function here.
    client.invoke(
        "CIM_BootConfigSetting",
        "ChangeBootOrder",
        {"Source": None},
        selectors=boot_config_selector,
    )

    # Step 3: Put AMT_BootSettingData with the mutated instance.
    client.put("AMT_BootSettingData", put_properties)

    # Step 4: CIM_BootService.SetBootConfigRole(Role=1 / IsNextSingleUse).
    client.invoke(
        "CIM_BootService",
        "SetBootConfigRole",
        {
            "BootConfigSetting": EndpointReference("CIM_BootConfigSetting", boot_config_selector),
            "Role": BOOT_CONFIG_ROLE_NEXT_SINGLE_USE,
        },
    )

    # Step 5: CIM_BootConfigSetting.ChangeBootOrder(<EPR or null>). IDE-R and BIOS-setup targets
    # pass a null Source -- naming a CIM_BootSourceSetting here would override IDE-R redirection
    # (protocol-notes.md s2.5), which is exactly what BootPlan's mutual-exclusion check guards.
    source_param = EndpointReference("CIM_BootSourceSetting", boot_source_selector) if boot_source_selector is not None else None
    client.invoke(
        "CIM_BootConfigSetting",
        "ChangeBootOrder",
        {"Source": source_param},
        selectors=boot_config_selector,
    )

    observed = client.get("AMT_BootSettingData")

    return BootArmResult(
        plan=plan,
        previous=previous,
        put_properties=put_properties,
        observed=observed,
        boot_config_selector=boot_config_selector,
        boot_source_selector=boot_source_selector,
        mutated=True,
    )

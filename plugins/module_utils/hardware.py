# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hardware/asset inventory facts read from the ``CIM_`` physical-asset classes.

Why this exists at all: Intel AMT runs beneath the host OS, so it can report a
machine's serial number, model, DIMMs and disks **while that machine is powered
off**. Where an agent is running you would use ``ansible.builtin.setup``; where
one is not, AMT is the only source of truth. MeshCentral makes exactly that
distinction -- ``amtmanager.js``'s ``attemptFetchHardwareInventory()`` fetches
this batch only when ``mesh.mtype == 1``, an *AMT-only* device group, i.e. one
with no agent to ask instead.

The one rule that governs this whole file
-----------------------------------------

**Every value table here is transcribed from ``go-wsman-messages`` or the DMTF
CIM schema. None is inferred from a hardware dump.** A dump proves a value was
*returned*; it can never establish what the value *means*. Conflating those two
is what shipped an inverted ``wake_on_lan_capable`` in 0.2.0 and 0.3.0 (see
``docs/capability-matrix.md``'s "Correction: the ``LinkPolicy`` row was
previously wrong"), and it is the second time a transcribed constants table from
that source has been wrong.

The corollaries, all of which this file follows:

* The **raw integer is always reported alongside** any decoded name, exactly as
  :class:`models.PowerState` and :class:`models.SystemState` do.
* An unrecognised value renders as ``unknown(<raw>)``, never a bare ``unknown``
  -- several of these tables define ``0`` as ``unknown``, and "the firmware said
  0" and "the firmware said something this table has never heard of" are
  different findings that must not print identically.
* **Where no table can be sourced, the raw integer ships undecoded** and the
  documentation says so. Two properties are in that position and are called out
  individually below: ``CIM_Processor.Family`` and
  ``CIM_PhysicalMemory.FormFactor``. Shipping a bare integer is honest; shipping
  a confident wrong label is what the last release cycle was spent undoing.

Provenance of each table is recorded immediately above it, naming the file in
``go-wsman-messages`` at tag ``v2.48.3`` it came from. The *mappings* were
extracted mechanically from that library's ``const``/``map`` pairs rather than
retyped. The *labels* are a mechanical snake_case of that library's own display
strings, so a few read awkwardly (``socketm_pga604``, ``io_t_gateway``); they
are deliberately not hand-tidied, because hand-editing a value table is the
precise activity this file exists to avoid. The raw integer is authoritative in
every case.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    ENABLED_STATE_TABLE,
    OPERATIONAL_STATUS_TABLE,
    optional_bool,
    optional_int,
    optional_str,
)

# --------------------------------------------------------------------------
# gather_subset vocabulary and resolution
# --------------------------------------------------------------------------

#: Everything ``amt_info`` read before 0.5.0. Named for the data rather than the
#: classes behind it, like every other subset here.
SUBSET_CONFIG = "config"
#: ``CIM_Chassis`` + ``CIM_Card`` -- the system's and the board's identity plates.
#: One subset rather than two because nobody wants a chassis serial without a
#: board serial: together they tell a board swap from a re-rack, and separately
#: neither does.
SUBSET_SYSTEM = "system"
#: ``CIM_Processor`` + ``CIM_Chip``. Also deliberately one subset:
#: ``CIM_Processor`` alone yields a ``Family`` integer this collection will not
#: decode, and ``CIM_Chip.Version`` is the human-readable processor name. Asking
#: for one without the other is always a mistake, so the option does not offer it.
SUBSET_PROCESSOR = "processor"
#: ``CIM_PhysicalMemory`` -- per-DIMM.
SUBSET_MEMORY = "memory"
#: ``CIM_MediaAccessDevice`` -- disks.
SUBSET_STORAGE = "storage"

#: Alias for every inventory subset. Not itself gatherable -- it expands.
SUBSET_HARDWARE = "hardware"

#: The subsets that may appear in a resolved result.
VALID_SUBSETS: frozenset[str] = frozenset({SUBSET_CONFIG, SUBSET_SYSTEM, SUBSET_PROCESSOR, SUBSET_MEMORY, SUBSET_STORAGE})

#: The un-excludable core, mirroring ``setup``'s ``minimal_gather_subset``.
#:
#: ``config`` being minimal is what makes this option **backward compatible by
#: construction**: no combination of values can remove the keys ``amt_info``
#: returned before 0.5.0, so no existing caller can be broken by a
#: ``gather_subset`` someone else added to a play. It also matches ``setup``,
#: where a plain ``!<subset>`` cannot drop the minimal facts either.
MINIMAL_SUBSET: frozenset[str] = frozenset({SUBSET_CONFIG})

#: Aliases expanded on both the positive and the negated side, so
#: ``!hardware`` removes exactly what ``hardware`` adds.
SUBSET_ALIASES: dict[str, frozenset[str]] = {
    SUBSET_HARDWARE: frozenset({SUBSET_SYSTEM, SUBSET_PROCESSOR, SUBSET_MEMORY, SUBSET_STORAGE}),
}

#: Which :class:`HardwareFacts` fields each subset populates.
#:
#: **The subset names and the fact-group names are deliberately different, and
#: conflating them is a real and demonstrated bug.** ``system`` populates
#: ``chassis`` and ``baseboard``; ``processor`` populates ``processors`` and
#: ``chips``. Only ``memory`` and ``storage`` happen to share a name with the
#: group they fill. ``tests/hardware/qualify_readonly.yml`` reported
#: ``amt.hardware.system`` and ``amt.hardware.processor`` -- keys
#: :meth:`HardwareFacts.to_dict` has never emitted -- and Jinja's
#: ``| default(none)`` turned each undefined lookup into a printed ``null``. The
#: first hardware run therefore reported the chassis, baseboard, processor and
#: chip groups as absent on both lab machines when firmware had in fact returned
#: all four fully populated. Nothing was wrong with the reader; the summary asked
#: the wrong questions and was structurally unable to say so.
FACT_GROUPS_BY_SUBSET: dict[str, tuple[str, ...]] = {
    SUBSET_SYSTEM: ("chassis", "baseboard"),
    SUBSET_PROCESSOR: ("processors", "chips"),
    SUBSET_MEMORY: ("memory",),
    SUBSET_STORAGE: ("storage",),
}

#: The WS-Man class behind each fact group, and the ordering
#: :meth:`HardwareFacts.reads_to_dict` reports them in.
#:
#: Keyed by class rather than by group because the read outcome is a fact about a
#: *class*: "``CIM_Chassis`` answered" is what happened on the wire, and
#: ``chassis`` is only where the result was filed. Carrying the group alongside
#: means the receipt states the class-to-key mapping explicitly, which is the
#: information whose absence made the first hardware run misreport itself.
FACT_GROUP_BY_CLASS: dict[str, str] = {
    "CIM_Chassis": "chassis",
    "CIM_Card": "baseboard",
    "CIM_Processor": "processors",
    "CIM_Chip": "chips",
    "CIM_PhysicalMemory": "memory",
    "CIM_MediaAccessDevice": "storage",
}

#: :attr:`ClassRead.outcome` -- firmware returned at least one instance.
READ_OUTCOME_READ = "read"
#: :attr:`ClassRead.outcome` -- firmware answered with **zero** instances. A real
#: reading (a diskless machine really has no ``CIM_MediaAccessDevice``), not a gap.
READ_OUTCOME_EMPTY = "empty"
#: :attr:`ClassRead.outcome` -- every verb tried was refused, so this firmware does
#: not expose the class. :attr:`ClassRead.error_class` names how it was refused.
READ_OUTCOME_ABSENT = "absent"

#: WS-Man **HTTP requests** each subset costs, for the module's documented
#: round-trip table. An ``Enumerate`` costs two (Enumerate + one ``Pull``), and
#: one more ``Pull`` per further 64 instances -- no realistic machine has 64
#: DIMMs or disks, but the arithmetic is stated rather than assumed.
#:
#: ``system``'s two are bare ``Get``s that fall back to ``Enumerate`` if they
#: fault, so that subset can cost up to 6 on firmware that refuses ``Get`` for
#: both classes -- the same shape as ``CIM_BIOSElement`` in the ``config`` set.
ROUND_TRIPS_BY_SUBSET: dict[str, int] = {
    SUBSET_CONFIG: 10,
    SUBSET_SYSTEM: 2,
    SUBSET_PROCESSOR: 4,
    SUBSET_MEMORY: 2,
    SUBSET_STORAGE: 2,
}

#: Every accepted ``gather_subset`` value, for the module's ``choices``.
#:
#: Enumerated as ``choices`` rather than validated in module code -- unlike
#: ``setup``, which raises from its own collector -- so ``AnsibleModule`` rejects
#: a typo **before any connection is attempted**, and ``ansible-doc`` lists the
#: whole vocabulary. This follows the collection's existing precedent: ``state``
#: on ``amt_power`` and ``amt_boot`` is validated the same way, and it means a bad
#: option value never has to be squeezed into one of ``errors.py``'s nine
#: operation-failure classes, none of which describes "you made a typo".
GATHER_SUBSET_CHOICES: tuple[str, ...] = tuple(
    sorted({"all", "min", SUBSET_HARDWARE, *VALID_SUBSETS} | {f"!{name}" for name in {"all", "min", SUBSET_HARDWARE, *VALID_SUBSETS}})
)


def _expand(name: str) -> frozenset[str]:
    """Resolve one subset name, expanding an alias, to concrete subset names."""
    return SUBSET_ALIASES.get(name, frozenset({name}))


def resolve_gather_subset(gather_subset: list[str]) -> frozenset[str]:
    """Resolve a ``gather_subset`` list the way ``ansible.builtin.setup`` does.

    Deliberately a faithful reimplementation of ansible-core's
    ``module_utils/facts/collector.py`` ``get_collector_names()``, because the
    whole justification for borrowing the option *name* is that a user who knows
    ``setup`` already knows the semantics. A familiar name over unfamiliar
    behaviour would be worse than an unfamiliar name. The rules, in the order
    they apply:

    1. ``all`` adds every valid subset.
    2. ``min`` adds :data:`MINIMAL_SUBSET`.
    3. ``!all`` excludes everything *except* :data:`MINIMAL_SUBSET`.
    4. ``!min`` excludes :data:`MINIMAL_SUBSET` -- which rule 7 then undoes, so
       it is effectively inert. That is upstream's behaviour, quirk included, and
       is reproduced rather than "fixed": ``config`` here is the pre-0.5.0 fact
       set, and letting ``!min`` strip it would be a breaking change smuggled in
       through an option value.
    5. ``!<name>`` excludes that subset (expanding ``!hardware``).
    6. **If no positive entry was given at all**, every valid subset is added --
       so ``['!memory']`` means "everything except memory", not "the default
       except memory". Note this can cost *more* round trips than the option's
       default of ``['config']``: the default is the option's default *value*,
       while this rule is what the algorithm does once a caller has written a
       spec of their own. Both are upstream-faithful and both are documented.
    7. Exclusions are applied last, so a contradiction such as
       ``['all', '!memory']`` resolves in favour of the exclusion --
       and :data:`MINIMAL_SUBSET` is subtracted back out of the exclusion set, so
       it survives regardless.

    Unknown names cannot reach here: ``choices`` on the argument spec rejects
    them first (see :data:`GATHER_SUBSET_CHOICES`). An unknown name is ignored
    rather than raising, so this stays a pure function that cannot fail a module.
    """
    additional: set[str] = set()
    excluded: set[str] = set()

    for entry in gather_subset:
        name = entry.strip()
        if name == "all":
            additional.update(VALID_SUBSETS)
            continue
        if name == "min":
            additional.update(MINIMAL_SUBSET)
            continue
        if name.startswith("!"):
            negated = name[1:]
            if negated == "all":
                excluded.update(VALID_SUBSETS - MINIMAL_SUBSET)
            elif negated == "min":
                excluded.update(MINIMAL_SUBSET)
            else:
                excluded.update(_expand(negated) & VALID_SUBSETS)
            continue
        additional.update(_expand(name) & VALID_SUBSETS)

    if not additional:
        additional.update(VALID_SUBSETS)

    # Exclusion wins over inclusion, but never over the minimal set.
    return frozenset(additional - (excluded - MINIMAL_SUBSET)) | MINIMAL_SUBSET


def requested_fact_groups(subsets: frozenset[str]) -> frozenset[str]:
    """The :class:`HardwareFacts` field names the resolved ``subsets`` ask for."""
    groups: set[str] = set()
    for subset in subsets:
        groups.update(FACT_GROUPS_BY_SUBSET.get(subset, ()))
    return frozenset(groups)


def round_trip_estimate(subsets: frozenset[str]) -> int:
    """Best-case WS-Man HTTP request count for the resolved ``subsets``.

    "Best case" is load-bearing: a ``CIM_BIOSElement`` or ``system`` ``Get`` that
    faults costs an extra ``Enumerate``/``Pull`` pair on top of this. Reported in
    the module's receipt so an operator can see what a subset choice cost them
    without reading the docs.
    """
    return sum(ROUND_TRIPS_BY_SUBSET.get(subset, 0) for subset in subsets)


# --------------------------------------------------------------------------
# Value tables
# --------------------------------------------------------------------------

#: ``CIM_Chassis.ChassisPackageType`` -- the physical form factor of the chassis.
#: From ``go-wsman-messages`` ``pkg/wsman/cim/chassis/decoder.go``
#: (``ChassisPackageType`` const block + ``chassisPackageTypeToString``), 37
#: values, 0-36 contiguous.
#:
#: ``smbios_reserved1`` .. ``smbios_reserved4`` are that library's disambiguation
#: of the four slots DMTF names identically ("SMBIOS Reserved"). The numbering is
#: theirs, kept rather than collapsed so this table is a faithful transcription
#: of the cited source; the raw value is what distinguishes them regardless.
CHASSIS_PACKAGE_TYPE_TABLE: dict[int, str] = {
    0: "unknown",
    1: "other",
    2: "smbios_reserved1",
    3: "desktop",
    4: "low_profile_desktop",
    5: "pizza_box",
    6: "mini_tower",
    7: "tower",
    8: "portable",
    9: "laptop",
    10: "notebook",
    11: "handheld",
    12: "docking_station",
    13: "all_in_one",
    14: "sub_notebook",
    15: "space_saving",
    16: "lunch_box",
    17: "main_system_chassis",
    18: "expansion_chassis",
    19: "sub_chassis",
    20: "bus_expansion_chassis",
    21: "peripheral_chassis",
    22: "storage_chassis",
    23: "smbios_reserved2",
    24: "sealed_case_pc",
    25: "smbios_reserved3",
    26: "compact_pci",
    27: "advanced_tca",
    28: "blade_enclosure",
    29: "smbios_reserved4",
    30: "tablet",
    31: "convertible",
    32: "detachable",
    33: "io_t_gateway",
    34: "embedded_pc",
    35: "mini_pc",
    36: "stick_pc",
}

#: ``PackageType`` on ``CIM_Chassis`` **and** ``CIM_Card`` -- what kind of
#: physical package the element is. From ``go-wsman-messages``
#: ``pkg/wsman/cim/chassis/decoder.go`` and ``pkg/wsman/cim/card/decoder.go``
#: (``PackageType`` const block + ``packageTypeMap``), 18 values, 0-17.
#:
#: Those two files carry **byte-identical** maps, which is why one table serves
#: both classes here. Do not split it into two: a single table cannot drift
#: against itself, and both classes inherit the property from the same DMTF
#: parent (``CIM_PhysicalPackage``).
#:
#: This is a *different* enumeration from :data:`CHASSIS_PACKAGE_TYPE_TABLE`,
#: despite the similar name, and ``CIM_Chassis`` carries both properties at once
#: -- the real firmware fixture ``responses/cim/chassis/get.xml`` reports
#: ``ChassisPackageType`` 0 and ``PackageType`` 3 on the same instance. Decoding
#: one with the other's table is an easy and completely silent error.
PACKAGE_TYPE_TABLE: dict[int, str] = {
    0: "unknown",
    1: "other",
    2: "rack",
    3: "chassis_frame",
    4: "cross_connect_backplane",
    5: "container_frame_slot",
    6: "power_supply",
    7: "fan",
    8: "sensor",
    9: "module_card",
    10: "port_connector",
    11: "battery",
    12: "processor",
    13: "memory",
    14: "power_source_generator",
    15: "storage_media_package",
    16: "blade",
    17: "blade_expansion",
}

#: ``CIM_PhysicalMemory.MemoryType``. From ``go-wsman-messages``
#: ``pkg/wsman/cim/physical/decoder.go`` (``MemoryType`` const block +
#: ``memoryTypeMap``), 37 values, 0-36 contiguous.
#:
#: Independently corroborated by the real firmware fixture
#: ``responses/cim/physical/memory/pull.xml``: it reports ``MemoryType`` 26 for a
#: part number (``CT16G4SFD824A``) that is a DDR4 SODIMM, and 26 is ``ddr4``
#: here. That is a genuine cross-check of the table against firmware rather than
#: only against itself.
MEMORY_TYPE_TABLE: dict[int, str] = {
    0: "unknown",
    1: "other",
    2: "dram",
    3: "synchronous_dram",
    4: "cache_dram",
    5: "edo",
    6: "edram",
    7: "vram",
    8: "sram",
    9: "ram",
    10: "rom",
    11: "flash",
    12: "eeprom",
    13: "feprom",
    14: "eprom",
    15: "cdram",
    16: "3_dram",
    17: "sdram",
    18: "sgram",
    19: "rdram",
    20: "ddr",
    21: "ddr2",
    22: "bram",
    23: "fbdimm",
    24: "ddr3",
    25: "fbd2",
    26: "ddr4",
    27: "lpddr",
    28: "lpddr2",
    29: "lpddr3",
    30: "lpddr4",
    31: "logical_non_volatile_device",
    32: "hbm",
    33: "hbm2",
    34: "ddr5",
    35: "lpddr5",
    36: "hbm3",
}

#: ``CIM_MediaAccessDevice.Capabilities`` -- a CIM **array**, so decoded
#: element-wise. From ``go-wsman-messages``
#: ``pkg/wsman/cim/mediaaccess/decoder.go`` (``Capabilities`` const block +
#: ``capabilitiesToString``), 13 values, 0-12 contiguous, and independently
#: corroborated by the DMTF ``ValueMap``/``Values`` annotation that same
#: library's ``mediaaccess/types.go`` carries inline on the property:
#: ``ValueMap={0..12}`` / ``Values={Unknown, Other, Sequential Access, Random
#: Access, Supports Writing, Encryption, Compression, Supports Removeable Media,
#: Manual Cleaning, Automatic Cleaning, SMART Notification, Supports Dual Sided
#: Media, Predismount Eject Not Required}``.
#:
#: Value 4 (``supports_writing``) is the one an operator is most likely to act
#: on. Its label follows ``decoder.go``'s spelling; note DMTF's own ``Values``
#: array misspells value 7 as "Removeable", and the library spells it
#: "Removable" -- the label here follows the library, and the raw integer settles
#: any doubt.
MEDIA_CAPABILITIES_TABLE: dict[int, str] = {
    0: "unknown",
    1: "other",
    2: "sequential_access",
    3: "random_access",
    4: "supports_writing",
    5: "encryption",
    6: "compression",
    7: "supports_removable_media",
    8: "manual_cleaning",
    9: "automatic_cleaning",
    10: "smart_notification",
    11: "supports_dual_sided_media",
    12: "pre_dismount_eject_not_required",
}

#: ``CIM_MediaAccessDevice.Security``. From ``go-wsman-messages``
#: ``pkg/wsman/cim/mediaaccess/decoder.go`` (``Security`` const block, declared
#: ``iota + 1`` so it starts at 1, plus ``securityToString``), corroborated by
#: the inline annotation in ``mediaaccess/types.go``: ``ValueMap={1, 2, 3, 4, 5,
#: 6, 7}`` / ``Values={Other, Unknown, None, Read Only, Locked Out, Boot Bypass,
#: Boot Bypass and Read Only}``.
#:
#: **There is no value 0**, and the order is not what an English reader expects:
#: ``1`` is ``other`` and ``2`` is ``unknown``, the reverse of every other table
#: in this file. The real firmware fixture ``responses/cim/mediaaccess/pull.xml``
#: reports ``Security`` 2 on both devices, i.e. ``unknown`` -- so a table that
#: had those two transposed would silently report every disk in the fixture as
#: "other" and look entirely plausible doing it.
#:
#: The label for 7 follows the DMTF ``Values`` text ("Boot Bypass and Read
#: Only"); ``decoder.go``'s own display string renders it "BootBypassandReadOnly"
#: with a lowercase "and", which mechanically snake-cases to the misleading
#: ``boot_bypassand_read_only``. Same mapping either way.
MEDIA_SECURITY_TABLE: dict[int, str] = {
    1: "other",
    2: "unknown",
    3: "none",
    4: "read_only",
    5: "locked_out",
    6: "boot_bypass",
    7: "boot_bypass_and_read_only",
}

#: ``CIM_MediaAccessDevice.EnabledDefault`` -- the administrator's configured
#: startup state, distinct from the live ``EnabledState``. From
#: ``go-wsman-messages`` ``pkg/wsman/cim/mediaaccess/decoder.go``
#: (``EnabledDefault`` const block + ``enabledDefaultToString``).
#:
#: **Deliberately sparse**: that const block assigns explicit values and defines
#: no 0, 1, 4 or 8. Filling those gaps to make the table look tidy would be
#: inventing four meanings, so a firmware reporting one of them decodes to
#: ``unknown(<raw>)``.
MEDIA_ENABLED_DEFAULT_TABLE: dict[int, str] = {
    2: "enabled",
    3: "disabled",
    5: "not_applicable",
    6: "enabled_but_offline",
    7: "no_default",
    9: "quiesce",
}

#: ``CIM_Processor.CPUStatus``. From ``go-wsman-messages``
#: ``pkg/wsman/cim/processor/decoder.go`` (``CPUStatus`` const block +
#: ``cpuStatusMap``), 6 values, 0-5 contiguous. The real firmware fixture
#: ``responses/cim/physical/processor/get.xml`` reports ``1``, ``cpu_enabled``.
CPU_STATUS_TABLE: dict[int, str] = {
    0: "unknown",
    1: "cpu_enabled",
    2: "cpu_disabled_by_user",
    3: "cpu_disabled_by_bios",
    4: "cpu_is_idle",
    5: "other",
}

#: ``CIM_Processor.HealthState``. From ``go-wsman-messages``
#: ``pkg/wsman/cim/processor/decoder.go`` (``HealthState`` const block +
#: ``healthStateMap``).
#:
#: **Sparse by design** -- DMTF spaces this enumeration in steps of five
#: precisely so implementations can add intermediate values later. Everything
#: between the defined values is genuinely undefined and decodes to
#: ``unknown(<raw>)``.
HEALTH_STATE_TABLE: dict[int, str] = {
    0: "unknown",
    5: "ok",
    10: "degraded_warning",
    15: "minor_failure",
    20: "major_failure",
    25: "critical_failure",
    30: "non_recoverable_error",
}

#: ``CIM_Processor.UpgradeMethod`` -- the CPU socket, which is what says whether
#: a processor is socketed or soldered down. From ``go-wsman-messages``
#: ``pkg/wsman/cim/processor/decoder.go`` (``UpgradeMethod`` const block +
#: ``upgradeMethodMap``), 85 values, 0-84 contiguous.
#:
#: Note ``0`` is ``other`` and ``1`` is ``unknown``, the same inversion
#: :data:`MEDIA_SECURITY_TABLE` has and the opposite of most tables here.
#:
#: The real firmware fixture ``responses/cim/physical/processor/get.xml`` reports
#: ``52`` -- ``socket_bga1515``, a soldered ball-grid array, which is consistent
#: with the NUC the rest of that fixture set describes.
UPGRADE_METHOD_TABLE: dict[int, str] = {
    0: "other",
    1: "unknown",
    2: "daughter_board",
    3: "zif_socket",
    4: "replacement_piggy_back",
    5: "none",
    6: "lif_socket",
    7: "slot1",
    8: "slot2",
    9: "370_pin_socket",
    10: "slot_a",
    11: "slot_m",
    12: "socket423",
    13: "socket_a_socket462",
    14: "socket478",
    15: "socket754",
    16: "socket940",
    17: "socket939",
    18: "socketm_pga604",
    19: "socket_lga771",
    20: "socket_lga775",
    21: "socket_s1",
    22: "socket_am2",
    23: "socket_f1207",
    24: "socket_lga1366",
    25: "socket_g34",
    26: "socket_am3",
    27: "socket_c32",
    28: "socket_lga1156",
    29: "socket_lga1567",
    30: "socket_pga988_a",
    31: "socket_bga1288",
    32: "r_pga988_b",
    33: "bga1023",
    34: "bga1224",
    35: "lga1155",
    36: "lga1356",
    37: "lga2011",
    38: "socket_fs1",
    39: "socket_fs2",
    40: "socket_fm1",
    41: "socket_fm2",
    42: "socket_lga20113",
    43: "socket_lga13563",
    44: "socket_lga1150",
    45: "socket_bga1168",
    46: "socket_bga1234",
    47: "socket_bga1364",
    48: "socket_am4",
    49: "socket_lga1151",
    50: "socket_bga1356",
    51: "socket_bga1440",
    52: "socket_bga1515",
    53: "socket_lga36471",
    54: "socket_sp3",
    55: "socket_sp3r2",
    56: "socket_lga2066",
    57: "socket_bga1392",
    58: "socket_bga1510",
    59: "socket_bga1528",
    60: "socket_lga4189",
    61: "socket_lga1200",
    62: "socket_lga4677",
    63: "socket_lga1700",
    64: "socket_bga1744",
    65: "socket_bga1781",
    66: "socket_bga1211",
    67: "socket_bga2422",
    68: "socket_lga5773",
    69: "socket_bga5773",
    70: "socket_am5",
    71: "socket_sp5",
    72: "socket_sp6",
    73: "socket_bga883",
    74: "socket_bga1190",
    75: "socket_bga4129",
    76: "socket_lga4710",
    77: "socket_lga7529",
    78: "socket_bga1964",
    79: "socket_bga1792",
    80: "socket_bga2049",
    81: "socket_bga2551",
    82: "socket_lga1851",
    83: "socket_bga2114",
    84: "socket_bga2833",
}

#: Properties this module reads but deliberately **does not decode**, with the
#: reason. Kept as data rather than only prose so the module documentation and
#: the unit tests can both assert against the same list -- a claim that something
#: is undecoded is only worth anything if something checks it stays undecoded.
#:
#: ``CIM_Processor.Family``
#:     ``go-wsman-messages`` types it as a plain ``int`` and defines **no** map
#:     for it (``pkg/wsman/cim/processor/types.go``: ``Family int``; there is no
#:     ``familyMap`` anywhere in that library). The DMTF ``Family`` ValueMap has
#:     several hundred entries and no offline copy of the CIM schema was
#:     available to transcribe it from, so there is nothing to source. The real
#:     firmware fixture reports ``198``; what 198 *means* is exactly the kind of
#:     claim this collection has twice got wrong by guessing, so it ships raw.
#:     ``CIM_Chip.Version`` carries the human-readable processor name anyway (see
#:     :class:`ChipInfo`), which is what an operator actually wanted from
#:     ``Family``.
#:
#: ``CIM_PhysicalMemory.FormFactor``
#:     Same situation and a sharper trap. ``go-wsman-messages`` types it
#:     ``FormFactor int`` with no enum type and no map. Two *different* published
#:     tables both plausibly apply and **they disagree on the value the real
#:     firmware fixture actually reports**: the fixture says ``13``, which is
#:     ``SODIMM`` under the SMBIOS type-17 form-factor enumeration but ``SRIMM``
#:     under the DMTF ``CIM_PhysicalMemory.FormFactor`` ValueMap. The part in
#:     that fixture is a SODIMM, so SMBIOS looks right -- but "looks right on one
#:     machine" is a hardware-dump inference, which is the one form of evidence
#:     this file may not use for a meaning. Ships raw.
#:
#: ``RequestedState`` (on ``CIM_Processor`` and ``CIM_MediaAccessDevice``)
#:     Consistent with how ``amt_info`` already reports
#:     ``CIM_ComputerSystem.RequestedState``: raw and undecoded. A table does
#:     exist in ``go-wsman-messages`` for both classes, but the processor one
#:     omits value 0 and this collection has already chosen, for the identical
#:     property on a sibling class, not to publish a decode it has not verified.
#:     Reporting the same property two different ways in one module's output
#:     would be worse than reporting it plainly in both.
UNDECODED_PROPERTIES: tuple[tuple[str, str], ...] = (
    ("CIM_Processor", "Family"),
    ("CIM_PhysicalMemory", "FormFactor"),
    ("CIM_Processor", "RequestedState"),
    ("CIM_MediaAccessDevice", "RequestedState"),
)


# --------------------------------------------------------------------------
# Shared parsing helpers
# --------------------------------------------------------------------------


def _decode_table(table: dict[int, str], value: int) -> str:
    """Name a DMTF enumeration value, keeping an unrecognised one visible.

    Same convention as ``models.py``'s ``_decode`` and ``message_log.py``'s
    ``_decode_table``: a value outside the table renders ``unknown(<raw>)``, not
    a bare ``unknown``, because several tables here define ``0`` as ``unknown``
    and the two findings must not print identically.
    """
    return table.get(value, f"unknown({value})")


def _int_list(value: Any) -> list[int] | None:
    """Flatten a CIM array property into a list of ints.

    WS-Man renders an array as a repeated element, which
    ``wsman.py``'s ``_element_to_value()`` turns into a list of strings when
    there are two or more and a bare string when there is exactly one. Both
    shapes mean "array", so both are accepted -- collapsing the single-element
    case to a scalar would silently drop every status after the first on a
    degraded machine, which is precisely the set that says *why* it is degraded.

    ``None`` when the property is absent (unknown); ``[]`` when it is present
    but empty (genuinely no values).
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return []
    candidates = value if isinstance(value, list) else [value]
    return [number for item in candidates if (number := optional_int(item)) is not None]


def _decode_list(table: dict[int, str], values: list[int] | None) -> list[str] | None:
    """Element-wise decode of a CIM array property, preserving order."""
    return [_decode_table(table, value) for value in values] if values is not None else None


def _operational_status(instance: dict[str, Any]) -> tuple[list[int] | None, list[str] | None]:
    """``CIM_ManagedSystemElement.OperationalStatus`` -- shared by every class here.

    Uses the same DMTF table ``amt_info`` already applies to
    ``CIM_ComputerSystem``, imported rather than redeclared: a value table that
    exists twice can drift against itself, and this one is already Tier 1 in
    ``docs/capability-matrix.md``. ``go-wsman-messages`` carries a per-package
    copy of this same enumeration in all six of the packages backing this file,
    and all six agree with the DMTF table -- so importing the existing one is
    also the better-corroborated choice.
    """
    statuses = _int_list(instance.get("OperationalStatus"))
    return statuses, _decode_list(OPERATIONAL_STATUS_TABLE, statuses)


def _enabled_state(instance: dict[str, Any]) -> tuple[int | None, str | None]:
    """``CIM_EnabledLogicalElement.EnabledState``, decoded per DMTF.

    Deliberately uses ``models.ENABLED_STATE_TABLE`` -- the full DMTF 0-10 table
    already Tier 1 here -- rather than ``go-wsman-messages``'
    ``pkg/wsman/cim/processor/decoder.go`` ``enabledStateMap``, which **omits
    values 0, 1 and 2**. That omission is not academic: its own real firmware
    fixture ``responses/cim/physical/processor/get.xml`` reports ``EnabledState``
    2, so that library's decoder answers "Value not found in map" for its own
    captured firmware response. Its ``mediaaccess`` copy of the same enumeration
    *is* complete and agrees with the DMTF table exactly, which is what makes
    the processor one identifiable as an omission rather than a disagreement.
    """
    state = optional_int(instance.get("EnabledState"))
    return state, _decode_table(ENABLED_STATE_TABLE, state) if state is not None else None


# --------------------------------------------------------------------------
# Fact groups
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChassisInfo:
    """``CIM_Chassis`` -- the enclosure, and where the **system serial number** lives.

    This is the single field that motivates the whole inventory capability: on a
    powered-off machine with no agent, ``serial_number`` here is the only way to
    read it.

    Field set is that of the real firmware response fixture
    ``go-wsman-messages`` ships at
    ``pkg/wsman/wsmantesting/responses/cim/chassis/get.xml``, cross-checked
    against the class definition in ``pkg/wsman/cim/chassis/types.go``.

    **There is no asset-tag property on this class.** ``go-wsman-messages``
    declares none, and the string ``AssetTag`` does not occur anywhere in that
    library. What exists is ``Tag``, surfaced here as :attr:`tag`, whose DMTF
    description says it "can contain information such as asset tag or serial
    number data" -- but the fixture shows real firmware populating it with the
    literal string ``CIM_Chassis``, i.e. the class name, carrying no asset
    information whatsoever. It is reported because it is what firmware sends; it
    is **not** named ``asset_tag``, because on the one machine anyone has a
    recorded response from, it is not one.
    """

    serial_number: str | None = None
    model: str | None = None
    manufacturer: str | None = None
    version: str | None = None
    #: ``Tag``, the DMTF key property. See the class docstring: not an asset tag.
    tag: str | None = None
    element_name: str | None = None
    chassis_package_type: int | None = None
    chassis_package_type_text: str | None = None
    package_type: int | None = None
    package_type_text: str | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> ChassisInfo:
        chassis_package_type = optional_int(instance.get("ChassisPackageType"))
        package_type = optional_int(instance.get("PackageType"))
        statuses, statuses_text = _operational_status(instance)
        return cls(
            serial_number=optional_str(instance.get("SerialNumber")),
            model=optional_str(instance.get("Model")),
            manufacturer=optional_str(instance.get("Manufacturer")),
            version=optional_str(instance.get("Version")),
            tag=optional_str(instance.get("Tag")),
            element_name=optional_str(instance.get("ElementName")),
            chassis_package_type=chassis_package_type,
            # Two different enumerations on one instance -- see the note on
            # PACKAGE_TYPE_TABLE. Swapping these two tables would decode both
            # properties to plausible-looking wrong names.
            chassis_package_type_text=(_decode_table(CHASSIS_PACKAGE_TYPE_TABLE, chassis_package_type) if chassis_package_type is not None else None),
            package_type=package_type,
            package_type_text=_decode_table(PACKAGE_TYPE_TABLE, package_type) if package_type is not None else None,
            operational_status=statuses,
            operational_status_text=statuses_text,
        )


@dataclass(frozen=True, slots=True)
class BaseboardInfo:
    """``CIM_Card`` -- the motherboard, and its own serial number.

    Distinct from :class:`ChassisInfo`'s serial: a chassis can be re-used with a
    different board and vice versa, so an inventory that records only one of them
    cannot tell a board swap from a re-rack. The real firmware fixtures report
    genuinely different values for the two (``chassis/get.xml`` and
    ``card/get.xml``).

    Field set from the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/cim/card/get.xml`` plus the class
    definition ``pkg/wsman/cim/card/types.go``. ``Tag`` is again the class name
    on that fixture rather than an asset tag -- see :class:`ChassisInfo`.
    """

    serial_number: str | None = None
    model: str | None = None
    manufacturer: str | None = None
    version: str | None = None
    tag: str | None = None
    element_name: str | None = None
    #: ``CanBeFRUed`` -- whether this is a field-replaceable unit.
    can_be_frued: bool | None = None
    package_type: int | None = None
    package_type_text: str | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> BaseboardInfo:
        package_type = optional_int(instance.get("PackageType"))
        statuses, statuses_text = _operational_status(instance)
        return cls(
            serial_number=optional_str(instance.get("SerialNumber")),
            model=optional_str(instance.get("Model")),
            manufacturer=optional_str(instance.get("Manufacturer")),
            version=optional_str(instance.get("Version")),
            tag=optional_str(instance.get("Tag")),
            element_name=optional_str(instance.get("ElementName")),
            can_be_frued=optional_bool(instance.get("CanBeFRUed")),
            package_type=package_type,
            package_type_text=_decode_table(PACKAGE_TYPE_TABLE, package_type) if package_type is not None else None,
            operational_status=statuses,
            operational_status_text=statuses_text,
        )


@dataclass(frozen=True, slots=True)
class ProcessorInfo:
    """One ``CIM_Processor`` instance: clocks, socket, stepping, status.

    Field set from the real firmware response fixtures
    ``pkg/wsman/wsmantesting/responses/cim/physical/processor/{get,pull}.xml``
    (identical property sets) and the class definition
    ``pkg/wsman/cim/processor/types.go``.

    **This class carries no core or thread count.** ``go-wsman-messages``
    declares neither, and neither appears on either fixture: the property set is
    ``DeviceID``, ``CreationClassName``, ``SystemName``,
    ``SystemCreationClassName``, ``ElementName``, ``OperationalStatus``,
    ``HealthState``, ``EnabledState``, ``RequestedState``, ``Role``, ``Family``,
    ``OtherFamilyDescription``, ``UpgradeMethod``, ``MaxClockSpeed``,
    ``CurrentClockSpeed``, ``Stepping``, ``CPUStatus`` and
    ``ExternalBusClockSpeed``, and that is all. DMTF's ``CIM_Processor`` does
    define ``NumberOfEnabledCores`` and friends in later schema versions; AMT's
    implementation of the class, as evidenced here, does not expose them. Nothing
    in this collection reports a core count, because there is nothing to report
    it from. **One instance per physical package**, so a multi-socket machine
    returns several -- not one per core.

    :attr:`family` is reported **raw and undecoded**; see
    :data:`UNDECODED_PROPERTIES` for why, and :class:`ChipInfo` for the field
    that actually names the processor.
    """

    device_id: str | None = None
    element_name: str | None = None
    role: str | None = None
    #: ``Family``, raw. Undecoded on purpose -- see :data:`UNDECODED_PROPERTIES`.
    family: int | None = None
    other_family_description: str | None = None
    max_clock_speed_mhz: int | None = None
    current_clock_speed_mhz: int | None = None
    external_bus_clock_speed_mhz: int | None = None
    stepping: str | None = None
    cpu_status: int | None = None
    cpu_status_text: str | None = None
    upgrade_method: int | None = None
    upgrade_method_text: str | None = None
    health_state: int | None = None
    health_state_text: str | None = None
    enabled_state: int | None = None
    enabled_state_text: str | None = None
    #: ``RequestedState``, raw and undecoded -- matching how ``amt_info`` already
    #: reports the same property on ``CIM_ComputerSystem``.
    requested_state: int | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> ProcessorInfo:
        cpu_status = optional_int(instance.get("CPUStatus"))
        upgrade_method = optional_int(instance.get("UpgradeMethod"))
        health_state = optional_int(instance.get("HealthState"))
        enabled_state, enabled_state_text = _enabled_state(instance)
        statuses, statuses_text = _operational_status(instance)
        return cls(
            device_id=optional_str(instance.get("DeviceID")),
            element_name=optional_str(instance.get("ElementName")),
            role=optional_str(instance.get("Role")),
            family=optional_int(instance.get("Family")),
            other_family_description=optional_str(instance.get("OtherFamilyDescription")),
            # Named _mhz because the class definition states the unit; the raw
            # property names do not, and an unlabelled clock speed invites
            # someone to read MaxClockSpeed as Hz.
            max_clock_speed_mhz=optional_int(instance.get("MaxClockSpeed")),
            current_clock_speed_mhz=optional_int(instance.get("CurrentClockSpeed")),
            external_bus_clock_speed_mhz=optional_int(instance.get("ExternalBusClockSpeed")),
            # Free-form string per the class definition, not an integer: firmware
            # is entitled to report "13" or "B0" and both are valid.
            stepping=optional_str(instance.get("Stepping")),
            cpu_status=cpu_status,
            cpu_status_text=_decode_table(CPU_STATUS_TABLE, cpu_status) if cpu_status is not None else None,
            upgrade_method=upgrade_method,
            upgrade_method_text=(_decode_table(UPGRADE_METHOD_TABLE, upgrade_method) if upgrade_method is not None else None),
            health_state=health_state,
            health_state_text=_decode_table(HEALTH_STATE_TABLE, health_state) if health_state is not None else None,
            enabled_state=enabled_state,
            enabled_state_text=enabled_state_text,
            requested_state=optional_int(instance.get("RequestedState")),
            operational_status=statuses,
            operational_status_text=statuses_text,
        )


@dataclass(frozen=True, slots=True)
class ChipInfo:
    """One ``CIM_Chip`` instance -- and the reason this class is read at all.

    ``version`` here is the **human-readable processor name**. The real firmware
    fixture ``pkg/wsman/wsmantesting/responses/cim/chip/get.xml`` reports
    ``Version`` = ``Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz``. That string is
    what an operator means by "what CPU is in this machine", and
    ``CIM_Processor`` cannot supply it: the nearest thing it has is ``Family``,
    an integer this collection will not decode (see
    :data:`UNDECODED_PROPERTIES`). So ``CIM_Chip`` is not the redundant
    packaging class it looks like -- it carries the one processor fact the
    dedicated processor class does not.

    ``CIM_PhysicalMemory`` is a **subclass** of ``CIM_Chip`` (stated in
    ``go-wsman-messages``' ``pkg/wsman/cim/physical/memory.go`` package comment,
    and its ``ElementName`` doc notes the value is "Managed System Memory Chip"
    on ``CIM_Chip`` instances), so an ``Enumerate`` of ``CIM_Chip`` is entitled
    to return memory chips alongside processor chips. Instances are therefore
    reported **unfiltered**, with :attr:`element_name` and :attr:`tag` preserved
    so a caller can tell them apart. Filtering to "just the CPUs" would mean
    asserting which ``ElementName`` values firmware uses, and the one fixture
    available returns only the processor chip -- which establishes nothing about
    what other firmware returns.
    """

    #: ``Version`` -- the human-readable processor name. See the class docstring.
    version: str | None = None
    tag: str | None = None
    element_name: str | None = None
    manufacturer: str | None = None
    can_be_frued: bool | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> ChipInfo:
        statuses, statuses_text = _operational_status(instance)
        return cls(
            version=optional_str(instance.get("Version")),
            tag=optional_str(instance.get("Tag")),
            element_name=optional_str(instance.get("ElementName")),
            manufacturer=optional_str(instance.get("Manufacturer")),
            can_be_frued=optional_bool(instance.get("CanBeFRUed")),
            operational_status=statuses,
            operational_status_text=statuses_text,
        )


@dataclass(frozen=True, slots=True)
class MemoryInfo:
    """One ``CIM_PhysicalMemory`` instance -- a single DIMM.

    Field set from the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/cim/physical/memory/pull.xml`` (two
    instances, ``BANK 0`` and ``BANK 2``) and the class definition
    ``pkg/wsman/cim/physical/types.go``.

    **Speed is reported as four separate raw fields and nothing is derived from
    them.** The class definition is explicit that ``IsSpeedInMhz`` selects which
    of two properties actually holds the speed: "A value of TRUE shall indicate
    that the speed is represented by the ``MaxMemorySpeed`` property. A value of
    FALSE shall indicate that the speed is represented by the ``Speed``
    property." Worse, the two are in **different units** -- ``Speed`` is in
    nanoseconds and ``MaxMemorySpeed`` in MHz -- and the fixture reports
    ``Speed`` 0 with ``IsSpeedInMhz`` true, so anything that read ``Speed``
    naively would report every DIMM on that machine as 0.

    A single derived ``speed`` field is deliberately **not** offered. It would
    have to invent an answer for the ``IsSpeedInMhz`` false case, where the
    honest conversion (1000/ns) yields a figure that is not the memory clock rate
    an operator is looking for. All four inputs are surfaced instead and the rule
    is documented; a caller who needs one number can apply the rule knowing which
    branch they are on.

    :attr:`form_factor` is reported **raw and undecoded**. See
    :data:`UNDECODED_PROPERTIES`: two published tables disagree about the value
    real firmware actually reports here, and no vendor map exists to settle it.
    """

    bank_label: str | None = None
    #: ``Capacity``, in **bytes** per the class definition. The fixture's
    #: 17179869184 is 16 GiB, which corroborates the unit.
    capacity_bytes: int | None = None
    memory_type: int | None = None
    memory_type_text: str | None = None
    #: ``FormFactor``, raw. Undecoded -- see :data:`UNDECODED_PROPERTIES`.
    form_factor: int | None = None
    #: ``Speed``, in **nanoseconds**. Only meaningful when
    #: :attr:`is_speed_in_mhz` is false. See the class docstring.
    speed_ns: int | None = None
    #: ``MaxMemorySpeed``, in **MHz**. The speed when :attr:`is_speed_in_mhz`.
    max_memory_speed_mhz: int | None = None
    #: ``ConfiguredMemoryClockSpeed``, in **MHz** -- what the DIMM is actually
    #: clocked at, which may be below :attr:`max_memory_speed_mhz`.
    configured_clock_speed_mhz: int | None = None
    is_speed_in_mhz: bool | None = None
    manufacturer: str | None = None
    part_number: str | None = None
    serial_number: str | None = None
    tag: str | None = None
    element_name: str | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> MemoryInfo:
        memory_type = optional_int(instance.get("MemoryType"))
        statuses, statuses_text = _operational_status(instance)
        return cls(
            bank_label=optional_str(instance.get("BankLabel")),
            capacity_bytes=optional_int(instance.get("Capacity")),
            memory_type=memory_type,
            memory_type_text=_decode_table(MEMORY_TYPE_TABLE, memory_type) if memory_type is not None else None,
            form_factor=optional_int(instance.get("FormFactor")),
            speed_ns=optional_int(instance.get("Speed")),
            max_memory_speed_mhz=optional_int(instance.get("MaxMemorySpeed")),
            configured_clock_speed_mhz=optional_int(instance.get("ConfiguredMemoryClockSpeed")),
            is_speed_in_mhz=optional_bool(instance.get("IsSpeedInMhz")),
            # Firmware reports this as a JEDEC manufacturer ID on the fixture
            # ("859B") rather than a name. Passed through verbatim -- no JEDEC
            # ID table is available to source, and guessing one would be the
            # same error as guessing an enum.
            manufacturer=optional_str(instance.get("Manufacturer")),
            part_number=optional_str(instance.get("PartNumber")),
            serial_number=optional_str(instance.get("SerialNumber")),
            tag=optional_str(instance.get("Tag")),
            element_name=optional_str(instance.get("ElementName")),
            operational_status=statuses,
            operational_status_text=statuses_text,
        )


@dataclass(frozen=True, slots=True)
class StorageInfo:
    """One ``CIM_MediaAccessDevice`` instance -- a disk, as AMT sees it.

    Field set from the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/cim/mediaaccess/pull.xml`` (two devices)
    and the class definition ``pkg/wsman/cim/mediaaccess/types.go``.

    **This class carries no model, vendor or serial number.**
    ``go-wsman-messages`` declares ``Capabilities``, ``CreationClassName``,
    ``DeviceID``, ``ElementName``, ``EnabledDefault``, ``EnabledState``,
    ``MaxMediaSize``, ``OperationalStatus``, ``RequestedState``, ``Security``,
    ``SystemCreationClassName`` and ``SystemName`` -- and that is the complete
    set, matching the fixture exactly. ``ElementName`` is the constant string
    "Managed System Media Access Device" on **both** fixture devices, so it does
    not identify anything either. What distinguishes one disk from another here
    is :attr:`device_id` ("MEDIA DEV 0", "MEDIA DEV 1") and
    :attr:`max_media_size_kb`. An operator wanting a disk model number cannot get
    it from AMT via this class, and this collection does not pretend otherwise.

    :attr:`max_media_size_kb` is left in the **KBytes** the class definition
    states, deliberately unconverted. The fixture's 960197124 and 500107862 read
    as a 960 GB and a 500 GB device under KB = 1000 bytes, which is suggestive --
    but nothing establishes whether firmware means 1000 or 1024, and a converted
    ``_bytes`` field would silently bake that guess in at a 2.4% error.
    """

    device_id: str | None = None
    element_name: str | None = None
    #: ``MaxMediaSize``, in **KBytes**, unconverted. See the class docstring.
    max_media_size_kb: int | None = None
    capabilities: list[int] | None = None
    capabilities_text: list[str] | None = None
    security: int | None = None
    security_text: str | None = None
    enabled_state: int | None = None
    enabled_state_text: str | None = None
    enabled_default: int | None = None
    enabled_default_text: str | None = None
    #: ``RequestedState``, raw and undecoded -- see :data:`UNDECODED_PROPERTIES`.
    requested_state: int | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> StorageInfo:
        capabilities = _int_list(instance.get("Capabilities"))
        security = optional_int(instance.get("Security"))
        enabled_default = optional_int(instance.get("EnabledDefault"))
        enabled_state, enabled_state_text = _enabled_state(instance)
        statuses, statuses_text = _operational_status(instance)
        return cls(
            device_id=optional_str(instance.get("DeviceID")),
            element_name=optional_str(instance.get("ElementName")),
            max_media_size_kb=optional_int(instance.get("MaxMediaSize")),
            capabilities=capabilities,
            capabilities_text=_decode_list(MEDIA_CAPABILITIES_TABLE, capabilities),
            security=security,
            # 1 is "other" and 2 is "unknown" here, the reverse of most tables --
            # see MEDIA_SECURITY_TABLE.
            security_text=_decode_table(MEDIA_SECURITY_TABLE, security) if security is not None else None,
            enabled_state=enabled_state,
            enabled_state_text=enabled_state_text,
            enabled_default=enabled_default,
            enabled_default_text=(_decode_table(MEDIA_ENABLED_DEFAULT_TABLE, enabled_default) if enabled_default is not None else None),
            requested_state=optional_int(instance.get("RequestedState")),
            operational_status=statuses,
            operational_status_text=statuses_text,
        )


@dataclass(frozen=True, slots=True)
class ClassRead:
    """What happened when one inventory class was read. Diagnostics, not a fact.

    This type exists because ``null`` is not a diagnosis. Every fact group in
    :class:`HardwareFacts` degrades to ``None`` when its class cannot be read, and
    that is the right behaviour -- but on its own it cannot distinguish

    * this firmware does not expose the class,
    * we asked for it with a verb or selector it refuses,
    * it answered and the reader did not recognise the shape,

    and the first hardware run needed exactly that distinction and did not have
    it. So each read records its own outcome alongside the fact, and the fact
    value is left untouched: this is reported *in addition to* ``null``, never
    instead of it.

    Carried on the **operation receipt** rather than under ``amt``, matching where
    ``gather_subset`` and ``wsman_requests_estimated`` already sit. ``amt`` is
    documented as firmware-observed evidence; which verb this collection chose to
    send is a fact about this collection, not about the endpoint.
    """

    #: The ``amt.hardware`` key this class's result was filed under. Stated
    #: explicitly because the subset name, the class name and the fact key are
    #: three different vocabularies -- see :data:`FACT_GROUPS_BY_SUBSET`.
    fact_group: str
    #: One of :data:`READ_OUTCOME_READ`, :data:`READ_OUTCOME_EMPTY`,
    #: :data:`READ_OUTCOME_ABSENT`.
    outcome: str
    #: The WS-Man verb whose result is being reported: ``"Get"`` or
    #: ``"Enumerate"``. For the two single-instance classes this is also how a
    #: reader sees whether the ``Enumerate`` fallback had to run -- a value of
    #: ``"Enumerate"`` there means the bare ``Get`` was refused, and that the
    #: subset cost more round trips than
    #: :func:`round_trip_estimate` predicted.
    verb: str | None = None
    #: How many instances firmware returned. ``0`` on
    #: :data:`READ_OUTCOME_EMPTY`; ``None`` on :data:`READ_OUTCOME_ABSENT`,
    #: because nothing was returned to count.
    instances: int | None = None
    #: The ``errors.py`` ``error_class`` the refusal carried, on
    #: :data:`READ_OUTCOME_ABSENT` only. AMT answers an unimplemented resource URI
    #: with HTTP 400, which this collection raises as ``ProtocolError`` and so
    #: reports here as ``protocol`` -- the same signal MeshCentral treats as
    #: "this class is not present" (``amtmanager.js``' CIRA batch deletes
    #: 400-answering classes and carries on).
    error_class: str | None = None


def render_class_reads(reads: dict[str, ClassRead]) -> dict[str, Any]:
    """Render per-class read outcomes for the operation receipt, in class order.

    Ordered by :data:`FACT_GROUP_BY_CLASS` rather than by insertion, so the
    receipt reads the same way every run regardless of which subsets were asked
    for. A class that was not read at all is simply absent -- exactly as
    :meth:`HardwareFacts.to_dict` omits a group that was not requested, so "I did
    not ask" and "I asked and got nothing back" stay distinguishable here too.

    A free function rather than only a method because two callers need it and a
    rendering rule that exists twice can drift against itself.
    """
    return {class_name: dataclasses.asdict(reads[class_name]) for class_name in FACT_GROUP_BY_CLASS if class_name in reads}


@dataclass(frozen=True, slots=True)
class HardwareFacts:
    """The inventory fact groups, one field per :mod:`amt_info` subset component.

    Every field distinguishes **three** outcomes, and the difference is the whole
    point of the type:

    * the attribute is absent from the rendered dict -- *this subset was not
      requested*, so nothing was asked of the endpoint;
    * ``None`` -- requested, but the class faulted or is not implemented on this
      firmware;
    * a value, including an empty list -- the class answered. ``[]`` means
      firmware returned **zero instances**, which is a real answer and not the
      same as a fault.

    Rendering is done by :meth:`to_dict` rather than ``dataclasses.asdict`` so
    the not-requested case can be represented by an absent key. A caller reading
    ``'memory' in amt.hardware`` is asking "did I request it", and
    ``amt.hardware.memory is none`` is asking "does this firmware have it".
    """

    chassis: ChassisInfo | None = None
    baseboard: BaseboardInfo | None = None
    processors: list[ProcessorInfo] | None = None
    chips: list[ChipInfo] | None = None
    memory: list[MemoryInfo] | None = None
    storage: list[StorageInfo] | None = None
    #: Names of the fields above that were actually requested. Only these appear
    #: in :meth:`to_dict`'s output.
    requested: frozenset[str] = frozenset()
    #: Per-class read outcomes, keyed by WS-Man class name. Deliberately **not**
    #: rendered by :meth:`to_dict`: ``amt.hardware``'s shape is a published
    #: interface and must not move, and these belong on the operation receipt
    #: anyway (see :class:`ClassRead`). Rendered by :meth:`reads_to_dict`.
    reads: dict[str, ClassRead] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Render only the requested groups, so an absent key means "not asked for".

        Note the field list here is explicit rather than derived from
        ``dataclasses.fields()``. That is what keeps :attr:`reads` and
        :attr:`requested` out of the published fact shape, and it is why adding a
        field to this class cannot silently change ``amt.hardware``.
        """
        document: dict[str, Any] = {}
        for name in ("chassis", "baseboard", "processors", "chips", "memory", "storage"):
            if name not in self.requested:
                continue
            value = getattr(self, name)
            if value is None:
                document[name] = None
            elif isinstance(value, list):
                document[name] = [dataclasses.asdict(item) for item in value]
            else:
                document[name] = dataclasses.asdict(value)
        return document

    def reads_to_dict(self) -> dict[str, Any]:
        """Render :attr:`reads` for the operation receipt. See :func:`render_class_reads`."""
        return render_class_reads(self.reads)

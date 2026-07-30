# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for the hardware/asset inventory facts.

The value-table tests here are the point of this file. ``docs/capability-matrix.md``
records that a transcribed enumeration table shipped inverted for two releases and
that neither the mock tier nor the hardware tier could catch it -- the mock was fed
from the same wrong understanding as the code, so both agreed while both were wrong.
The only thing that can catch that class of defect is an assertion, per value,
written against the *cited source* rather than against the implementation. So every
table is checked value by value, with the go-wsman-messages provenance named in the
test, plus an unrecognised value to prove it renders ``unknown(<raw>)`` and not a
bare ``unknown``.
"""

from __future__ import annotations

import dataclasses

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.hardware import (
    CHASSIS_PACKAGE_TYPE_TABLE,
    CPU_STATUS_TABLE,
    FACT_GROUPS_BY_SUBSET,
    GATHER_SUBSET_CHOICES,
    HEALTH_STATE_TABLE,
    MEDIA_CAPABILITIES_TABLE,
    MEDIA_ENABLED_DEFAULT_TABLE,
    MEDIA_SECURITY_TABLE,
    MEMORY_TYPE_TABLE,
    MINIMAL_SUBSET,
    PACKAGE_TYPE_TABLE,
    ROUND_TRIPS_BY_SUBSET,
    SUBSET_CONFIG,
    SUBSET_MEMORY,
    SUBSET_PROCESSOR,
    SUBSET_STORAGE,
    SUBSET_SYSTEM,
    UNDECODED_PROPERTIES,
    UPGRADE_METHOD_TABLE,
    VALID_SUBSETS,
    BaseboardInfo,
    ChassisInfo,
    ChipInfo,
    HardwareFacts,
    MemoryInfo,
    ProcessorInfo,
    StorageInfo,
    requested_fact_groups,
    resolve_gather_subset,
    round_trip_estimate,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    ENABLED_STATE_TABLE,
    OPERATIONAL_STATUS_TABLE,
)

# --------------------------------------------------------------------------
# Value tables -- every defined value, plus an undefined one
# --------------------------------------------------------------------------

#: Each table with the source that established it and a value it does **not**
#: define. Kept as data so a new table cannot be added without also being swept
#: by every generic test below -- the omission that let ``LinkPolicy`` through.
ALL_TABLES: tuple[tuple[str, dict[int, str], int, str], ...] = (
    ("ChassisPackageType", CHASSIS_PACKAGE_TYPE_TABLE, 37, "cim/chassis/decoder.go chassisPackageTypeToString"),
    ("PackageType", PACKAGE_TYPE_TABLE, 18, "cim/chassis|card/decoder.go packageTypeMap"),
    ("MemoryType", MEMORY_TYPE_TABLE, 37, "cim/physical/decoder.go memoryTypeMap"),
    ("MediaCapabilities", MEDIA_CAPABILITIES_TABLE, 13, "cim/mediaaccess/decoder.go capabilitiesToString"),
    ("MediaSecurity", MEDIA_SECURITY_TABLE, 7, "cim/mediaaccess/decoder.go securityToString"),
    ("MediaEnabledDefault", MEDIA_ENABLED_DEFAULT_TABLE, 6, "cim/mediaaccess/decoder.go enabledDefaultToString"),
    ("CPUStatus", CPU_STATUS_TABLE, 6, "cim/processor/decoder.go cpuStatusMap"),
    ("HealthState", HEALTH_STATE_TABLE, 7, "cim/processor/decoder.go healthStateMap"),
    ("UpgradeMethod", UPGRADE_METHOD_TABLE, 85, "cim/processor/decoder.go upgradeMethodMap"),
)


class TestValueTableShapes:
    """Structural invariants that hold for every table, whatever it decodes."""

    @pytest.mark.parametrize("name,table,size,source", ALL_TABLES, ids=[row[0] for row in ALL_TABLES])
    def test_table_has_exactly_the_number_of_values_its_source_defines(self, name, table, size, source):
        # A count is a cheap tripwire for the failure that actually happened: the
        # old LinkPolicy table had five entries where the vendor enum has four,
        # and nothing noticed because nothing counted.
        assert len(table) == size, f"{name} should have {size} values per {source}"

    @pytest.mark.parametrize("name,table,size,source", ALL_TABLES, ids=[row[0] for row in ALL_TABLES])
    def test_no_value_decodes_to_a_bare_unknown_placeholder_string(self, name, table, size, source):
        # "unknown" as a *defined* value is fine (0 means Unknown in most of these
        # enumerations). "unknown(...)" as a defined value would mean a table entry
        # had been written to look like the not-in-table rendering, which would make
        # the two indistinguishable -- the exact distinction this collection keeps.
        assert not any(value.startswith("unknown(") for value in table.values()), name

    @pytest.mark.parametrize("name,table,size,source", ALL_TABLES, ids=[row[0] for row in ALL_TABLES])
    def test_labels_are_lowercase_snake_case_like_the_rest_of_the_collection(self, name, table, size, source):
        for value in table.values():
            assert value == value.lower(), f"{name}: {value!r}"
            assert " " not in value and "-" not in value, f"{name}: {value!r}"


class TestChassisPackageTypeTable:
    """``CIM_Chassis.ChassisPackageType`` -- go-wsman-messages ``cim/chassis/decoder.go``."""

    # Every one of the 37 values the cited source defines, transcribed here
    # independently of the implementation's dict so the two must agree.
    EXPECTED = {
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

    @pytest.mark.parametrize("value,name", sorted(EXPECTED.items()))
    def test_every_defined_value_decodes_to_its_vendor_name(self, value, name):
        assert ChassisInfo.from_instance({"ChassisPackageType": str(value)}).chassis_package_type_text == name

    @pytest.mark.parametrize("value", [37, 99, 255, 65535])
    def test_undefined_value_renders_unknown_with_the_raw_kept(self, value):
        info = ChassisInfo.from_instance({"ChassisPackageType": str(value)})
        assert info.chassis_package_type_text == f"unknown({value})"
        assert info.chassis_package_type == value

    def test_defined_zero_and_an_undefined_value_do_not_render_identically(self):
        # 0 is a *defined* value meaning Unknown. A value outside the table is a
        # different finding. The codebase already makes this distinction for
        # EnabledState and it must hold here too.
        defined = ChassisInfo.from_instance({"ChassisPackageType": "0"}).chassis_package_type_text
        undefined = ChassisInfo.from_instance({"ChassisPackageType": "37"}).chassis_package_type_text
        assert defined == "unknown"
        assert undefined == "unknown(37)"
        assert defined != undefined


class TestPackageTypeTable:
    """``PackageType`` on ``CIM_Chassis`` and ``CIM_Card`` -- one shared table."""

    EXPECTED = {
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

    @pytest.mark.parametrize("value,name", sorted(EXPECTED.items()))
    def test_every_defined_value_decodes_on_chassis(self, value, name):
        assert ChassisInfo.from_instance({"PackageType": str(value)}).package_type_text == name

    @pytest.mark.parametrize("value,name", sorted(EXPECTED.items()))
    def test_every_defined_value_decodes_identically_on_a_card(self, value, name):
        # Both classes inherit the property from the same DMTF parent and
        # go-wsman-messages carries byte-identical maps for them. If these two ever
        # diverge, one of them was decoded with the wrong table.
        assert BaseboardInfo.from_instance({"PackageType": str(value)}).package_type_text == name

    @pytest.mark.parametrize("value", [18, 200])
    def test_undefined_value_renders_unknown_with_the_raw_kept(self, value):
        info = BaseboardInfo.from_instance({"PackageType": str(value)})
        assert info.package_type_text == f"unknown({value})"
        assert info.package_type == value

    def test_the_two_chassis_enumerations_are_not_confused_with_each_other(self):
        # CIM_Chassis carries ChassisPackageType and PackageType at once, with
        # different tables. The real firmware fixture reports 0 and 3, which decode
        # to different names -- so a client that applied one table to the other
        # property would be visible here.
        info = ChassisInfo.from_instance({"ChassisPackageType": "3", "PackageType": "3"})
        assert info.chassis_package_type_text == "desktop"
        assert info.package_type_text == "chassis_frame"


class TestMemoryTypeTable:
    """``CIM_PhysicalMemory.MemoryType`` -- go-wsman-messages ``cim/physical/decoder.go``."""

    EXPECTED = {
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

    @pytest.mark.parametrize("value,name", sorted(EXPECTED.items()))
    def test_every_defined_value_decodes_to_its_vendor_name(self, value, name):
        assert MemoryInfo.from_instance({"MemoryType": str(value)}).memory_type_text == name

    @pytest.mark.parametrize("value", [37, 100])
    def test_undefined_value_renders_unknown_with_the_raw_kept(self, value):
        info = MemoryInfo.from_instance({"MemoryType": str(value)})
        assert info.memory_type_text == f"unknown({value})"
        assert info.memory_type == value

    def test_the_real_firmware_fixture_value_decodes_to_ddr4(self):
        # responses/cim/physical/memory/pull.xml reports MemoryType 26 for a part
        # number that is a DDR4 SODIMM. This is the one value in this table with an
        # independent cross-check against firmware rather than only against the
        # vendor library, so it is asserted on its own.
        assert MemoryInfo.from_instance({"MemoryType": "26"}).memory_type_text == "ddr4"


class TestMediaAccessDeviceTables:
    """``CIM_MediaAccessDevice`` -- go-wsman-messages ``cim/mediaaccess/decoder.go``."""

    CAPABILITIES = {
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
    SECURITY = {
        1: "other",
        2: "unknown",
        3: "none",
        4: "read_only",
        5: "locked_out",
        6: "boot_bypass",
        7: "boot_bypass_and_read_only",
    }
    ENABLED_DEFAULT = {
        2: "enabled",
        3: "disabled",
        5: "not_applicable",
        6: "enabled_but_offline",
        7: "no_default",
        9: "quiesce",
    }

    @pytest.mark.parametrize("value,name", sorted(CAPABILITIES.items()))
    def test_every_defined_capability_decodes(self, value, name):
        assert StorageInfo.from_instance({"Capabilities": str(value)}).capabilities_text == [name]

    @pytest.mark.parametrize("value", [13, 64])
    def test_undefined_capability_renders_unknown_with_the_raw_kept(self, value):
        info = StorageInfo.from_instance({"Capabilities": str(value)})
        assert info.capabilities_text == [f"unknown({value})"]
        assert info.capabilities == [value]

    @pytest.mark.parametrize("value,name", sorted(SECURITY.items()))
    def test_every_defined_security_value_decodes(self, value, name):
        assert StorageInfo.from_instance({"Security": str(value)}).security_text == name

    def test_security_one_is_other_and_two_is_unknown_not_the_other_way_round(self):
        # This enumeration is inverted relative to almost every other CIM table,
        # and the real firmware fixture reports 2 on both of its devices. A
        # transposed table would report every disk as "other" and look plausible.
        assert StorageInfo.from_instance({"Security": "1"}).security_text == "other"
        assert StorageInfo.from_instance({"Security": "2"}).security_text == "unknown"

    def test_security_has_no_value_zero(self):
        # The const block is `iota + 1`. Zero is not a defined value, so it must
        # render as out-of-table rather than being quietly mapped to "other".
        info = StorageInfo.from_instance({"Security": "0"})
        assert info.security_text == "unknown(0)"
        assert info.security == 0

    @pytest.mark.parametrize("value,name", sorted(ENABLED_DEFAULT.items()))
    def test_every_defined_enabled_default_decodes(self, value, name):
        assert StorageInfo.from_instance({"EnabledDefault": str(value)}).enabled_default_text == name

    @pytest.mark.parametrize("value", [0, 1, 4, 8, 10])
    def test_the_gaps_in_enabled_default_are_not_invented(self, value):
        # The vendor const block defines no 0, 1, 4 or 8. Filling those in to make
        # the table look complete would be inventing four meanings.
        info = StorageInfo.from_instance({"EnabledDefault": str(value)})
        assert info.enabled_default_text == f"unknown({value})"

    def test_capabilities_is_parsed_as_an_array_even_with_several_values(self):
        info = StorageInfo.from_instance({"Capabilities": ["3", "4", "7"]})
        assert info.capabilities == [3, 4, 7]
        assert info.capabilities_text == ["random_access", "supports_writing", "supports_removable_media"]


class TestProcessorTables:
    """``CIM_Processor`` -- go-wsman-messages ``cim/processor/decoder.go``."""

    CPU_STATUS = {
        0: "unknown",
        1: "cpu_enabled",
        2: "cpu_disabled_by_user",
        3: "cpu_disabled_by_bios",
        4: "cpu_is_idle",
        5: "other",
    }
    HEALTH_STATE = {
        0: "unknown",
        5: "ok",
        10: "degraded_warning",
        15: "minor_failure",
        20: "major_failure",
        25: "critical_failure",
        30: "non_recoverable_error",
    }

    @pytest.mark.parametrize("value,name", sorted(CPU_STATUS.items()))
    def test_every_defined_cpu_status_decodes(self, value, name):
        assert ProcessorInfo.from_instance({"CPUStatus": str(value)}).cpu_status_text == name

    @pytest.mark.parametrize("value", [6, 99])
    def test_undefined_cpu_status_renders_unknown_with_the_raw_kept(self, value):
        info = ProcessorInfo.from_instance({"CPUStatus": str(value)})
        assert info.cpu_status_text == f"unknown({value})"
        assert info.cpu_status == value

    @pytest.mark.parametrize("value,name", sorted(HEALTH_STATE.items()))
    def test_every_defined_health_state_decodes(self, value, name):
        assert ProcessorInfo.from_instance({"HealthState": str(value)}).health_state_text == name

    @pytest.mark.parametrize("value", [1, 4, 6, 11, 26, 31])
    def test_health_state_gaps_are_undefined_not_rounded_to_a_neighbour(self, value):
        # DMTF spaces this enumeration in fives so implementations can add values
        # later. Rounding 11 to "degraded_warning" would be inventing a meaning.
        assert ProcessorInfo.from_instance({"HealthState": str(value)}).health_state_text == f"unknown({value})"

    @pytest.mark.parametrize("value,name", sorted(UPGRADE_METHOD_TABLE.items()))
    def test_every_defined_upgrade_method_decodes(self, value, name):
        assert ProcessorInfo.from_instance({"UpgradeMethod": str(value)}).upgrade_method_text == name

    @pytest.mark.parametrize("value", [85, 200])
    def test_undefined_upgrade_method_renders_unknown_with_the_raw_kept(self, value):
        info = ProcessorInfo.from_instance({"UpgradeMethod": str(value)})
        assert info.upgrade_method_text == f"unknown({value})"
        assert info.upgrade_method == value

    def test_upgrade_method_zero_is_other_and_one_is_unknown(self):
        # Inverted relative to most tables here, like MediaSecurity.
        assert ProcessorInfo.from_instance({"UpgradeMethod": "0"}).upgrade_method_text == "other"
        assert ProcessorInfo.from_instance({"UpgradeMethod": "1"}).upgrade_method_text == "unknown"

    def test_the_real_firmware_fixture_socket_decodes_to_a_soldered_bga(self):
        # responses/cim/physical/processor/get.xml reports UpgradeMethod 52.
        assert ProcessorInfo.from_instance({"UpgradeMethod": "52"}).upgrade_method_text == "socket_bga1515"


class TestSharedDmtfTables:
    """``EnabledState`` and ``OperationalStatus``, imported from ``models`` not redeclared."""

    @pytest.mark.parametrize("value,name", sorted(ENABLED_STATE_TABLE.items()))
    def test_processor_enabled_state_uses_the_full_dmtf_table(self, value, name):
        assert ProcessorInfo.from_instance({"EnabledState": str(value)}).enabled_state_text == name

    @pytest.mark.parametrize("value,name", sorted(ENABLED_STATE_TABLE.items()))
    def test_storage_enabled_state_uses_the_same_table(self, value, name):
        assert StorageInfo.from_instance({"EnabledState": str(value)}).enabled_state_text == name

    @pytest.mark.parametrize("value", [0, 1, 2])
    def test_the_three_values_the_vendor_processor_map_omits_still_decode(self, value):
        # go-wsman-messages' cim/processor/decoder.go enabledStateMap defines no 0,
        # 1 or 2, so its own decoder answers "Value not found in map" for its own
        # captured firmware response (which reports EnabledState 2). This collection
        # uses the full DMTF table instead, and this is the test that says so.
        text = ProcessorInfo.from_instance({"EnabledState": str(value)}).enabled_state_text
        assert text == ENABLED_STATE_TABLE[value]
        assert not text.startswith("unknown(")

    @pytest.mark.parametrize("value", [11, 32768])
    def test_undefined_enabled_state_renders_unknown_with_the_raw_kept(self, value):
        info = ProcessorInfo.from_instance({"EnabledState": str(value)})
        assert info.enabled_state_text == f"unknown({value})"
        assert info.enabled_state == value

    @pytest.mark.parametrize("value,name", sorted(OPERATIONAL_STATUS_TABLE.items()))
    @pytest.mark.parametrize(
        "factory",
        [ChassisInfo, BaseboardInfo, ProcessorInfo, ChipInfo, MemoryInfo, StorageInfo],
        ids=["chassis", "baseboard", "processor", "chip", "memory", "storage"],
    )
    def test_operational_status_decodes_identically_on_every_class(self, factory, value, name):
        # The property is defined on the DMTF parent CIM_ManagedSystemElement, so
        # every one of these classes carries it and every one must decode it the
        # same way. Six separate copies of a table is six chances to drift.
        info = factory.from_instance({"OperationalStatus": str(value)})
        assert info.operational_status == [value]
        assert info.operational_status_text == [name]

    @pytest.mark.parametrize("value", [20, 999])
    def test_undefined_operational_status_renders_unknown_with_the_raw_kept(self, value):
        info = ChipInfo.from_instance({"OperationalStatus": str(value)})
        assert info.operational_status_text == [f"unknown({value})"]
        assert info.operational_status == [value]


class TestUndecodedProperties:
    """The properties this collection deliberately refuses to name.

    These assertions exist to stop a well-meaning future change from adding a
    guessed table. The rule is that a mapping comes from ``go-wsman-messages`` or
    the DMTF schema or it does not ship; for these four properties there is
    nothing to source, so the raw integer is the whole answer.
    """

    def test_processor_family_is_reported_raw_with_no_decoded_companion(self):
        info = ProcessorInfo.from_instance({"Family": "198"})
        assert info.family == 198
        assert not any(field.name == "family_text" for field in dataclasses.fields(info))

    def test_memory_form_factor_is_reported_raw_with_no_decoded_companion(self):
        # 13 is SODIMM under SMBIOS type 17 and SRIMM under the DMTF
        # CIM_PhysicalMemory.FormFactor ValueMap. The two published tables
        # disagree about the exact value real firmware reports, and no vendor map
        # exists to settle it, so no name is claimed.
        info = MemoryInfo.from_instance({"FormFactor": "13"})
        assert info.form_factor == 13
        assert not any(field.name == "form_factor_text" for field in dataclasses.fields(info))

    @pytest.mark.parametrize(
        "factory",
        [ProcessorInfo, StorageInfo],
        ids=["processor", "storage"],
    )
    def test_requested_state_is_reported_raw_on_both_classes_that_carry_it(self, factory):
        # Matching how amt_info already reports CIM_ComputerSystem.RequestedState.
        info = factory.from_instance({"RequestedState": "12"})
        assert info.requested_state == 12
        assert not any(field.name == "requested_state_text" for field in dataclasses.fields(info))

    def test_the_documented_list_of_undecoded_properties_matches_what_is_implemented(self):
        assert set(UNDECODED_PROPERTIES) == {
            ("CIM_Processor", "Family"),
            ("CIM_PhysicalMemory", "FormFactor"),
            ("CIM_Processor", "RequestedState"),
            ("CIM_MediaAccessDevice", "RequestedState"),
        }


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


class TestChassisParsing:
    #: Field set of the real firmware response fixture
    #: go-wsman-messages pkg/wsman/wsmantesting/responses/cim/chassis/get.xml,
    #: with identifying values replaced -- that fixture's serial and model belong
    #: to a real machine and are not reproduced in this repository.
    INSTANCE = {
        "ChassisPackageType": "3",
        "CreationClassName": "CIM_Chassis",
        "ElementName": "Managed System Chassis",
        "Manufacturer": "Mock Systems (example.invalid)",
        "Model": "MOCK-CHASSIS-0000",
        "OperationalStatus": "2",
        "PackageType": "3",
        "SerialNumber": "MOCKCHASSIS0001",
        "Tag": "CIM_Chassis",
        "Version": "MOCK-000-000",
    }

    def test_reads_the_system_serial_number(self):
        # The single field that motivates the whole capability: on a powered-off
        # machine with no agent this is the only way to read it.
        assert ChassisInfo.from_instance(self.INSTANCE).serial_number == "MOCKCHASSIS0001"

    def test_reads_model_manufacturer_and_version(self):
        info = ChassisInfo.from_instance(self.INSTANCE)
        assert info.model == "MOCK-CHASSIS-0000"
        assert info.manufacturer == "Mock Systems (example.invalid)"
        assert info.version == "MOCK-000-000"

    def test_tag_is_surfaced_as_tag_and_never_as_an_asset_tag(self):
        info = ChassisInfo.from_instance(self.INSTANCE)
        # CIM_Chassis has no AssetTag property -- the string does not occur
        # anywhere in go-wsman-messages. What exists is Tag, and on the real
        # fixture firmware populates it with the class name, carrying no asset
        # information at all. Naming this field asset_tag would be a claim the
        # evidence contradicts.
        assert info.tag == "CIM_Chassis"
        assert not any(field.name == "asset_tag" for field in dataclasses.fields(info))

    def test_an_absent_property_is_none_not_a_fabricated_default(self):
        info = ChassisInfo.from_instance({})
        assert info.serial_number is None
        assert info.chassis_package_type is None
        assert info.chassis_package_type_text is None
        assert info.operational_status is None
        assert info.operational_status_text is None

    def test_an_empty_property_is_none_rather_than_an_empty_string(self):
        assert ChassisInfo.from_instance({"SerialNumber": "   "}).serial_number is None


class TestBaseboardParsing:
    #: responses/cim/card/get.xml's field set, identifying values replaced.
    INSTANCE = {
        "CanBeFRUed": "true",
        "CreationClassName": "CIM_Card",
        "ElementName": "Managed System Base Board",
        "Manufacturer": "Mock Systems (example.invalid)",
        "Model": "MOCK-BOARD-0000",
        "OperationalStatus": "2",
        "PackageType": "9",
        "SerialNumber": "MOCKBOARD0001",
        "Tag": "CIM_Card",
        "Version": "MOCK-000-001",
    }

    def test_reads_the_baseboard_serial_distinct_from_the_chassis_serial(self):
        board = BaseboardInfo.from_instance(self.INSTANCE)
        chassis = ChassisInfo.from_instance(TestChassisParsing.INSTANCE)
        assert board.serial_number == "MOCKBOARD0001"
        # Recording only one of the two cannot tell a board swap from a re-rack,
        # and the real fixtures report genuinely different values for them.
        assert board.serial_number != chassis.serial_number

    def test_can_be_frued_is_parsed_as_a_boolean_from_element_text(self):
        assert BaseboardInfo.from_instance(self.INSTANCE).can_be_frued is True
        assert BaseboardInfo.from_instance({"CanBeFRUed": "false"}).can_be_frued is False

    def test_an_absent_can_be_frued_is_none_not_false(self):
        # "This firmware did not say" and "this is not field-replaceable" are
        # different findings, per models.optional_bool's whole reason for existing.
        assert BaseboardInfo.from_instance({}).can_be_frued is None


class TestProcessorParsing:
    #: responses/cim/physical/processor/get.xml's field set and values. Nothing
    #: here is identity-shaped, so the fixture's values are used as-is -- DeviceID
    #: is a slot label, not a serial.
    INSTANCE = {
        "CPUStatus": "1",
        "CreationClassName": "CIM_Processor",
        "CurrentClockSpeed": "2400",
        "DeviceID": "CPU 0",
        "ElementName": "Managed System CPU",
        "EnabledState": "2",
        "ExternalBusClockSpeed": "100",
        "Family": "198",
        "HealthState": "0",
        "MaxClockSpeed": "8300",
        "OperationalStatus": "0",
        "OtherFamilyDescription": "",
        "RequestedState": "12",
        "Role": "Central",
        "Stepping": "13",
        "SystemCreationClassName": "CIM_ComputerSystem",
        "SystemName": "ManagedSystem",
        "UpgradeMethod": "52",
    }

    def test_reads_the_whole_fixture_instance(self):
        info = ProcessorInfo.from_instance(self.INSTANCE)
        assert info.device_id == "CPU 0"
        assert info.role == "Central"
        assert info.max_clock_speed_mhz == 8300
        assert info.current_clock_speed_mhz == 2400
        assert info.external_bus_clock_speed_mhz == 100
        assert info.cpu_status_text == "cpu_enabled"
        assert info.upgrade_method_text == "socket_bga1515"
        assert info.enabled_state_text == "enabled"

    def test_stepping_is_a_string_not_an_integer(self):
        # The class definition types Stepping as a free-form string. Firmware is
        # entitled to report "B0", and coercing to int would lose it.
        assert ProcessorInfo.from_instance(self.INSTANCE).stepping == "13"
        assert ProcessorInfo.from_instance({"Stepping": "B0"}).stepping == "B0"

    def test_empty_other_family_description_is_none(self):
        # Only populated when Family is 1 (Other); the fixture leaves it empty.
        assert ProcessorInfo.from_instance(self.INSTANCE).other_family_description is None

    def test_no_core_or_thread_count_field_exists(self):
        # AMT's CIM_Processor exposes neither, on the class definition or on either
        # fixture. Reporting a core count would mean inventing a property.
        names = {field.name for field in dataclasses.fields(ProcessorInfo)}
        assert not {name for name in names if "core" in name or "thread" in name}


class TestChipParsing:
    #: responses/cim/chip/get.xml's field set. Version is replaced: the fixture's
    #: is a real processor model from a real machine.
    INSTANCE = {
        "CanBeFRUed": "true",
        "CreationClassName": "CIM_Chip",
        "ElementName": "Managed System Processor Chip",
        "Manufacturer": "Mock Systems (example.invalid)",
        "OperationalStatus": "0",
        "Tag": "CPU 0",
        "Version": "Mock(R) Example(TM) CPU E0000 @ 2.40GHz",
    }

    def test_version_carries_the_human_readable_processor_name(self):
        # The reason this class is read at all. CIM_Processor cannot supply it: its
        # nearest field is Family, an integer this collection will not decode.
        assert ChipInfo.from_instance(self.INSTANCE).version == "Mock(R) Example(TM) CPU E0000 @ 2.40GHz"

    def test_element_name_is_preserved_so_memory_chips_can_be_told_apart(self):
        # CIM_PhysicalMemory is a subclass of CIM_Chip, so firmware may return
        # memory chips in the same enumeration. Instances are reported unfiltered
        # and ElementName is how a caller distinguishes them.
        processor_chip = ChipInfo.from_instance(self.INSTANCE)
        memory_chip = ChipInfo.from_instance({"ElementName": "Managed System Memory Chip", "Tag": "9000000000"})
        assert processor_chip.element_name == "Managed System Processor Chip"
        assert memory_chip.element_name == "Managed System Memory Chip"


class TestMemoryParsing:
    #: responses/cim/physical/memory/pull.xml's field set and its non-identifying
    #: values. PartNumber/SerialNumber/Manufacturer/Tag are replaced.
    INSTANCE = {
        "BankLabel": "BANK 0",
        "Capacity": "17179869184",
        "ConfiguredMemoryClockSpeed": "2400",
        "CreationClassName": "CIM_PhysicalMemory",
        "ElementName": "Managed System Memory Chip",
        "FormFactor": "13",
        "IsSpeedInMhz": "true",
        "Manufacturer": "0000",
        "MaxMemorySpeed": "2400",
        "MemoryType": "26",
        "OperationalStatus": "0",
        "PartNumber": "MOCKDIMM16G0000.M00XX",
        "SerialNumber": "A0000000",
        "Speed": "0",
        "Tag": "9000000000",
    }

    def test_capacity_is_read_in_bytes(self):
        # The class definition says bytes, and the fixture's value is exactly 16
        # GiB, which corroborates it.
        info = MemoryInfo.from_instance(self.INSTANCE)
        assert info.capacity_bytes == 17179869184
        assert info.capacity_bytes == 16 * 1024**3

    def test_all_four_speed_inputs_are_surfaced_separately(self):
        info = MemoryInfo.from_instance(self.INSTANCE)
        assert info.speed_ns == 0
        assert info.max_memory_speed_mhz == 2400
        assert info.configured_clock_speed_mhz == 2400
        assert info.is_speed_in_mhz is True

    def test_no_single_derived_speed_field_is_offered(self):
        # Deriving one would need an answer for the IsSpeedInMhz-false branch,
        # where Speed is in nanoseconds and the honest conversion is not a memory
        # clock rate. The four inputs are published and the rule is documented.
        names = {field.name for field in dataclasses.fields(MemoryInfo)}
        assert "speed" not in names
        assert "speed_mhz" not in names

    def test_the_fixture_reports_speed_zero_with_is_speed_in_mhz_true(self):
        # This exact combination is what real firmware returned, and it is why a
        # naive reader of Speed reports every DIMM on that machine as 0. Asserted
        # explicitly so the trap is documented by a test and not only by prose.
        info = MemoryInfo.from_instance(self.INSTANCE)
        assert info.is_speed_in_mhz is True
        assert info.speed_ns == 0
        assert info.max_memory_speed_mhz == 2400

    def test_bank_label_part_number_and_serial_are_read(self):
        info = MemoryInfo.from_instance(self.INSTANCE)
        assert info.bank_label == "BANK 0"
        assert info.part_number == "MOCKDIMM16G0000.M00XX"
        assert info.serial_number == "A0000000"


class TestStorageParsing:
    #: responses/cim/mediaaccess/pull.xml's field set and values -- none of which
    #: is identity-shaped, because the class carries no serial or model.
    INSTANCE = {
        "Capabilities": "4",
        "CreationClassName": "CIM_MediaAccessDevice",
        "DeviceID": "MEDIA DEV 0",
        "ElementName": "Managed System Media Access Device",
        "EnabledDefault": "2",
        "EnabledState": "0",
        "MaxMediaSize": "960197124",
        "OperationalStatus": "0",
        "RequestedState": "12",
        "Security": "2",
        "SystemCreationClassName": "CIM_ComputerSystem",
        "SystemName": "ManagedSystem",
    }

    def test_max_media_size_is_left_in_kbytes_unconverted(self):
        # The class definition says KBytes. Nothing establishes whether firmware
        # means 1000 or 1024, so a _bytes field would bake a guess in at 2.4%.
        info = StorageInfo.from_instance(self.INSTANCE)
        assert info.max_media_size_kb == 960197124
        names = {field.name for field in dataclasses.fields(StorageInfo)}
        assert "max_media_size_bytes" not in names
        assert "capacity_bytes" not in names

    def test_no_model_vendor_or_serial_field_exists(self):
        # The class has none -- not on the definition and not on the fixture. A
        # disk model is not obtainable from AMT here and this must not pretend.
        names = {field.name for field in dataclasses.fields(StorageInfo)}
        assert "model" not in names
        assert "manufacturer" not in names
        assert "serial_number" not in names

    def test_device_id_is_the_only_per_instance_identifier(self):
        # ElementName is the same constant string on every fixture instance, so a
        # caller telling disks apart by it would fail on firmware.
        first = StorageInfo.from_instance(self.INSTANCE)
        second = StorageInfo.from_instance({**self.INSTANCE, "DeviceID": "MEDIA DEV 1", "MaxMediaSize": "500107862"})
        assert first.element_name == second.element_name
        assert first.device_id != second.device_id


class TestCimArrayShapes:
    """WS-Man renders an array as a repeated element, which the parser sees two ways."""

    def test_a_single_element_array_is_still_a_list(self):
        # wsman.py's _element_to_value returns a bare string for one occurrence.
        # Collapsing that to a scalar would drop every status after the first on a
        # degraded machine -- exactly the set that says why it is degraded.
        assert ChipInfo.from_instance({"OperationalStatus": "2"}).operational_status == [2]

    def test_several_elements_preserve_firmware_order(self):
        info = ChipInfo.from_instance({"OperationalStatus": ["3", "2", "6"]})
        assert info.operational_status == [3, 2, 6]
        assert info.operational_status_text == ["degraded", "ok", "error"]

    def test_an_empty_array_is_an_empty_list_not_none(self):
        # Present but carrying no values is a different finding from absent.
        assert ChipInfo.from_instance({"OperationalStatus": ""}).operational_status == []

    def test_an_absent_array_is_none_not_an_empty_list(self):
        assert ChipInfo.from_instance({}).operational_status is None

    def test_non_numeric_array_members_are_dropped_rather_than_raising(self):
        # Facts degrade; they do not abort a read on one unexpected field.
        assert ChipInfo.from_instance({"OperationalStatus": ["2", "junk", "3"]}).operational_status == [2, 3]


# --------------------------------------------------------------------------
# gather_subset resolution
# --------------------------------------------------------------------------


class TestResolveGatherSubset:
    """The ``setup``-compatible semantics, case by case.

    The whole justification for borrowing ``gather_subset``'s *name* is that its
    behaviour is already familiar, so these are tests of fidelity to
    ansible-core's ``get_collector_names()``, not of a design of our own.
    """

    def test_the_default_is_exactly_the_pre_0_5_0_fact_set(self):
        assert resolve_gather_subset([SUBSET_CONFIG]) == frozenset({SUBSET_CONFIG})

    def test_all_gathers_every_valid_subset(self):
        assert resolve_gather_subset(["all"]) == VALID_SUBSETS

    def test_min_gathers_the_minimal_subset(self):
        assert resolve_gather_subset(["min"]) == MINIMAL_SUBSET

    def test_hardware_is_an_alias_for_the_four_inventory_subsets(self):
        assert resolve_gather_subset(["hardware"]) == VALID_SUBSETS
        assert resolve_gather_subset(["hardware"]) == frozenset({SUBSET_CONFIG, SUBSET_SYSTEM, SUBSET_PROCESSOR, SUBSET_MEMORY, SUBSET_STORAGE})

    def test_negating_the_alias_removes_exactly_what_it_adds(self):
        assert resolve_gather_subset(["all", "!hardware"]) == frozenset({SUBSET_CONFIG})

    def test_exclusion_is_applied_last_so_a_contradiction_resolves_against_inclusion(self):
        assert resolve_gather_subset(["all", "!memory"]) == VALID_SUBSETS - {SUBSET_MEMORY}
        assert resolve_gather_subset([SUBSET_MEMORY, "!memory"]) == frozenset({SUBSET_CONFIG})

    def test_a_spec_with_no_positive_entry_gathers_everything_then_excludes(self):
        # Upstream rule, reproduced: ['!memory'] means "everything except memory",
        # which costs MORE than the option's default of ['config']. Surprising, but
        # it is what a setup user's habits will expect, and it is documented.
        assert resolve_gather_subset(["!memory"]) == VALID_SUBSETS - {SUBSET_MEMORY}
        assert round_trip_estimate(resolve_gather_subset(["!memory"])) > round_trip_estimate(resolve_gather_subset([SUBSET_CONFIG]))

    def test_not_all_leaves_only_the_minimal_subset(self):
        assert resolve_gather_subset(["!all"]) == MINIMAL_SUBSET

    @pytest.mark.parametrize("entry", ["!min", "!config"])
    def test_the_minimal_subset_cannot_be_excluded(self, entry):
        # Matches upstream, where !min is likewise inert. Load-bearing here: config
        # is the pre-0.5.0 fact set, so letting an option value strip it would be a
        # breaking change smuggled in through gather_subset.
        assert SUBSET_CONFIG in resolve_gather_subset([entry])
        assert SUBSET_CONFIG in resolve_gather_subset(["all", entry])
        assert SUBSET_CONFIG in resolve_gather_subset([SUBSET_MEMORY, entry])

    def test_an_empty_list_gathers_everything_per_upstream(self):
        assert resolve_gather_subset([]) == VALID_SUBSETS

    def test_whitespace_around_a_name_is_tolerated(self):
        assert resolve_gather_subset([" memory "]) == frozenset({SUBSET_CONFIG, SUBSET_MEMORY})

    def test_an_unknown_name_is_ignored_rather_than_raising(self):
        # `choices` on the argument spec refuses these before this function is
        # reached; staying a pure total function means it can never be the thing
        # that fails a module.
        assert resolve_gather_subset([SUBSET_MEMORY, "nonsense"]) == frozenset({SUBSET_CONFIG, SUBSET_MEMORY})

    def test_duplicates_are_idempotent(self):
        assert resolve_gather_subset([SUBSET_MEMORY, SUBSET_MEMORY]) == frozenset({SUBSET_CONFIG, SUBSET_MEMORY})

    def test_order_of_entries_does_not_change_the_result(self):
        assert resolve_gather_subset(["all", "!memory"]) == resolve_gather_subset(["!memory", "all"])

    def test_every_choice_the_argument_spec_accepts_resolves_without_raising(self):
        for choice in GATHER_SUBSET_CHOICES:
            result = resolve_gather_subset([choice])
            assert result <= VALID_SUBSETS
            assert SUBSET_CONFIG in result

    def test_the_choices_list_covers_every_subset_and_alias_in_both_polarities(self):
        names = {"all", "min", "hardware", *VALID_SUBSETS}
        assert set(GATHER_SUBSET_CHOICES) == names | {f"!{name}" for name in names}


class TestSubsetMetadata:
    def test_config_costs_the_documented_ten_requests(self):
        # The pre-0.5.0 count, unchanged. If this moves, amt_info's documented
        # round-trip table is wrong and callers are being misinformed.
        assert ROUND_TRIPS_BY_SUBSET[SUBSET_CONFIG] == 10
        assert round_trip_estimate(resolve_gather_subset([SUBSET_CONFIG])) == 10

    def test_gathering_everything_costs_twenty_requests(self):
        assert round_trip_estimate(resolve_gather_subset(["all"])) == 20

    @pytest.mark.parametrize(
        "subset,cost",
        [(SUBSET_SYSTEM, 2), (SUBSET_PROCESSOR, 4), (SUBSET_MEMORY, 2), (SUBSET_STORAGE, 2)],
    )
    def test_each_hardware_subset_costs_what_the_docs_say(self, subset, cost):
        assert ROUND_TRIPS_BY_SUBSET[subset] == cost

    def test_every_valid_subset_has_a_documented_cost(self):
        assert set(ROUND_TRIPS_BY_SUBSET) == VALID_SUBSETS

    def test_config_maps_to_no_hardware_fact_group(self):
        assert requested_fact_groups(frozenset({SUBSET_CONFIG})) == frozenset()

    def test_every_hardware_subset_maps_to_at_least_one_fact_group(self):
        for subset in VALID_SUBSETS - MINIMAL_SUBSET:
            assert FACT_GROUPS_BY_SUBSET[subset]

    def test_all_maps_to_every_fact_group_on_hardware_facts(self):
        groups = requested_fact_groups(resolve_gather_subset(["all"]))
        assert groups == {"chassis", "baseboard", "processors", "chips", "memory", "storage"}
        # Every group must be a real field, or to_dict() would silently drop it.
        assert groups <= {field.name for field in dataclasses.fields(HardwareFacts)}

    def test_system_and_processor_each_cover_two_classes(self):
        # Neither is offered split: a chassis serial without a board serial cannot
        # tell a board swap from a re-rack, and CIM_Processor without CIM_Chip
        # yields a Family integer with no name attached.
        assert FACT_GROUPS_BY_SUBSET[SUBSET_SYSTEM] == ("chassis", "baseboard")
        assert FACT_GROUPS_BY_SUBSET[SUBSET_PROCESSOR] == ("processors", "chips")


class TestHardwareFactsRendering:
    """The three-state contract: not requested / absent / present."""

    def test_a_group_that_was_not_requested_is_absent_from_the_dict(self):
        facts = HardwareFacts(memory=[], requested=frozenset({"memory"}))
        rendered = facts.to_dict()
        assert "memory" in rendered
        # Asking "did I request this" must be answerable, which needs the key gone
        # rather than null.
        assert "storage" not in rendered
        assert "chassis" not in rendered

    def test_a_requested_group_the_firmware_lacks_renders_as_null(self):
        rendered = HardwareFacts(storage=None, requested=frozenset({"storage"})).to_dict()
        assert rendered["storage"] is None

    def test_a_requested_group_with_zero_instances_renders_as_an_empty_list(self):
        # A diskless machine is a real reading, not a firmware gap.
        rendered = HardwareFacts(storage=[], requested=frozenset({"storage"})).to_dict()
        assert rendered["storage"] == []
        assert rendered["storage"] is not None

    def test_absent_null_and_empty_are_three_distinguishable_answers(self):
        not_requested = HardwareFacts(requested=frozenset()).to_dict()
        absent = HardwareFacts(memory=None, requested=frozenset({"memory"})).to_dict()
        empty = HardwareFacts(memory=[], requested=frozenset({"memory"})).to_dict()
        assert "memory" not in not_requested
        assert absent["memory"] is None
        assert empty["memory"] == []

    def test_single_instance_groups_render_as_plain_dicts(self):
        facts = HardwareFacts(chassis=ChassisInfo(serial_number="MOCKCHASSIS0001"), requested=frozenset({"chassis"}))
        rendered = facts.to_dict()
        assert isinstance(rendered["chassis"], dict)
        assert rendered["chassis"]["serial_number"] == "MOCKCHASSIS0001"

    def test_list_groups_render_as_lists_of_plain_dicts(self):
        facts = HardwareFacts(
            memory=[MemoryInfo(bank_label="BANK 0"), MemoryInfo(bank_label="BANK 2")],
            requested=frozenset({"memory"}),
        )
        rendered = facts.to_dict()
        assert [item["bank_label"] for item in rendered["memory"]] == ["BANK 0", "BANK 2"]
        assert all(isinstance(item, dict) for item in rendered["memory"])

    def test_rendered_output_is_json_safe(self):
        import json

        facts = HardwareFacts(
            chassis=ChassisInfo.from_instance(TestChassisParsing.INSTANCE),
            memory=[MemoryInfo.from_instance(TestMemoryParsing.INSTANCE)],
            storage=[StorageInfo.from_instance(TestStorageParsing.INSTANCE)],
            requested=frozenset({"chassis", "memory", "storage"}),
        )
        # Ansible serializes module results to JSON; a frozenset or dataclass
        # leaking through would fail at exit_json, not here.
        assert json.loads(json.dumps(facts.to_dict()))["chassis"]["serial_number"] == "MOCKCHASSIS0001"

    def test_the_requested_marker_itself_never_reaches_the_output(self):
        rendered = HardwareFacts(requested=frozenset({"chassis"})).to_dict()
        assert "requested" not in rendered
